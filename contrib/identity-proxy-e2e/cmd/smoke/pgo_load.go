// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync/atomic"
	"time"

	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/croessner/nauthilus/v4/server/model/authdto"
	"golang.org/x/sync/errgroup"
)

const (
	modePGOLoad = "pgo-load"

	// pgoLoadAccounts is the size of the synthetic account pool the workload rotates through. The authority test
	// backend provisions an account on its first login, so the edge sees positive-cache misses as well as hits.
	pgoLoadAccounts      = 256
	pgoLoadAccountFormat = "pgo-load-%03d@example.test"

	edgeAuthPath     = "/api/v1/auth/json"
	edgeTokenPath    = "/oidc/token"
	edgeLoadTimeout  = 10 * time.Second
	edgeLoadIdleConn = 64
)

// pgoLoadOperation sends one authentication request of the PGO workload for an account.
type pgoLoadOperation func(ctx context.Context, account string) error

// pgoLoad drives the sustained authentication workload the PGO capture samples. It mixes edge HTTP JSON
// authentication (edge handler, pipeline, positive cache, remote backend) with direct authority gRPC authentication
// and identity lookup (authority caller authentication and pipeline). Every request must succeed, so a profile never
// records an error path by accident.
type pgoLoad struct {
	runner         *runner
	edge           *http.Client
	edgeToken      string
	authorityToken string
	requests       atomic.Int64
}

// runPGOLoad runs the workload for the configured duration and reports how many requests completed.
func (r *runner) runPGOLoad(parent context.Context) error {
	load, err := r.newPGOLoad(parent)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(parent, r.opts.loadDuration)
	defer cancel()

	if err = load.run(ctx, load.operations()); err != nil {
		return err
	}

	if load.requests.Load() == 0 {
		return errors.New("pgo-load completed no request")
	}

	ok(fmt.Sprintf("%s requests=%d workers=%d duration=%s", modePGOLoad, load.requests.Load(), r.opts.loadWorkers, r.opts.loadDuration))

	return nil
}

// newPGOLoad validates the workload settings and acquires the edge and authority caller tokens it presents.
func (r *runner) newPGOLoad(parent context.Context) (*pgoLoad, error) {
	if r.opts.loadWorkers < 1 || r.opts.loadDuration <= 0 {
		return nil, errors.New("pgo-load needs a positive -load-workers and -load-duration")
	}

	if r.opts.edgeClientID == "" || r.opts.edgeClientSecret == "" {
		return nil, errors.New("pgo-load needs -edge-client-id and -edge-client-secret")
	}

	edge, err := r.edgeHTTPClient()
	if err != nil {
		return nil, err
	}

	edgeToken, err := r.acquireEdgeToken(parent, edge)
	if err != nil {
		return nil, err
	}

	authorityToken, err := r.acquireToken(parent, []string{definitions.ScopeAuthenticate, definitions.ScopeLookupIdentity})
	if err != nil {
		return nil, err
	}

	return &pgoLoad{runner: r, edge: edge, edgeToken: edgeToken, authorityToken: authorityToken}, nil
}

// edgeHTTPClient returns a keep-alive HTTP/1.1 client that verifies the edge certificate against the E2E CA, like a
// reverse proxy holding persistent connections to Nauthilus.
func (r *runner) edgeHTTPClient() (*http.Client, error) {
	roots, err := loadE2ERoots(r.opts.workDir)
	if err != nil {
		return nil, err
	}

	transport := &http.Transport{
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots},
		MaxIdleConns:        edgeLoadIdleConn,
		MaxIdleConnsPerHost: edgeLoadIdleConn,
	}

	return &http.Client{Transport: transport, Timeout: edgeLoadTimeout}, nil
}

// acquireEdgeToken obtains an edge backchannel token for the JSON authentication endpoint with client_secret_basic.
func (r *runner) acquireEdgeToken(parent context.Context, client *http.Client) (string, error) {
	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("scope", definitions.ScopeAuthenticate)

	return tokenRequest{client: client, url: r.opts.edgeURL + edgeTokenPath, form: form, name: "edge backchannel",
		prepare: func(request *http.Request) {
			request.SetBasicAuth(r.opts.edgeClientID, r.opts.edgeClientSecret)
		}}.exchange(parent)
}

// operations returns the request mix of the workload: edge HTTP authentication, authority gRPC authentication, and
// authority gRPC identity lookup.
func (l *pgoLoad) operations() []pgoLoadOperation {
	return []pgoLoadOperation{l.edgeAuthenticate, l.authorityAuthenticate, l.authorityLookup}
}

// run starts the workers and returns the first request failure; reaching the deadline ends the workload cleanly.
func (l *pgoLoad) run(ctx context.Context, operations []pgoLoadOperation) error {
	group, groupCtx := errgroup.WithContext(ctx)

	for worker := range l.runner.opts.loadWorkers {
		group.Go(func() error {
			return l.work(groupCtx, worker, operations)
		})
	}

	return group.Wait()
}

// work rotates one worker through the operations and the account pool until its context ends. A request cut short by
// the deadline or by another worker's failure is not a failure of its own.
func (l *pgoLoad) work(ctx context.Context, worker int, operations []pgoLoadOperation) error {
	for request := worker; ; request++ {
		account := fmt.Sprintf(pgoLoadAccountFormat, request%pgoLoadAccounts)
		err := operations[request%len(operations)](ctx, account)

		if ctx.Err() != nil || workloadDeadlinePassed(ctx) {
			return nil
		}

		if err != nil {
			return err
		}

		l.requests.Add(1)
	}
}

// workloadDeadlinePassed reports whether the workload deadline lies behind the wall clock. A context sets Err only when
// its timer fires; on a loaded host a server status for a request sent in the last milliseconds, such as gRPC
// DeadlineExceeded, can arrive before that, and must still count as the end of the workload.
func workloadDeadlinePassed(ctx context.Context) bool {
	deadline, ok := ctx.Deadline()

	return ok && !time.Now().Before(deadline)
}

// edgeAuthenticate sends one JSON authentication request through edge-a and requires an ok=true answer.
func (l *pgoLoad) edgeAuthenticate(ctx context.Context, account string) error {
	body, err := json.Marshal(authdto.Request{
		Username:       account,
		Password:       l.runner.opts.password,
		ClientIP:       smokeClientIP,
		ClientPort:     smokeClientPort,
		ClientHostname: smokeClientHostname,
		ClientID:       smokeClientID,
		UserAgent:      smokeUserAgent,
		LocalIP:        smokeLocalIP,
		LocalPort:      smokeLocalPort,
		Protocol:       smokeProtocol,
		Method:         smokeMethod,
	})
	if err != nil {
		return err
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodPost, l.runner.opts.edgeURL+edgeAuthPath, bytes.NewReader(body))
	if err != nil {
		return err
	}

	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+l.edgeToken)

	response, err := l.edge.Do(request)
	if err != nil {
		return fmt.Errorf("edge JSON authentication: %w", err)
	}

	defer func() {
		_, _ = io.Copy(io.Discard, response.Body)
		_ = response.Body.Close()
	}()

	var result struct {
		OK bool `json:"ok"`
	}

	decodeErr := json.NewDecoder(response.Body).Decode(&result)
	if response.StatusCode != http.StatusOK || decodeErr != nil || !result.OK {
		return fmt.Errorf("edge JSON authentication of %s: status=%d ok=%v decode=%v", account, response.StatusCode, result.OK, decodeErr)
	}

	return nil
}

// authorityAuthenticate sends one direct gRPC password authentication to the authority.
func (l *pgoLoad) authorityAuthenticate(ctx context.Context, account string) error {
	_, err := l.runner.authenticate(ctx, l.authorityToken, account, l.runner.opts.password)

	return err
}

// authorityLookup sends one direct gRPC identity lookup to the authority.
func (l *pgoLoad) authorityLookup(ctx context.Context, account string) error {
	_, err := l.runner.lookupIdentity(ctx, l.authorityToken, account)

	return err
}
