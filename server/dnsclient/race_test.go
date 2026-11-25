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

package dnsclient

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

// errShutdown is a custom cancellation cause.
var errShutdown = errors.New("resolver pool shutting down")

// errBudgetSpent is a custom deadline cause.
var errBudgetSpent = errors.New("RBL budget spent")

// uncomparableError is an error whose dynamic type cannot be compared with ==.
type uncomparableError []string

// Error joins the parts of the error.
func (e uncomparableError) Error() string {
	return strings.Join(e, " ")
}

// contextErrorCase describes one way the lookup context ends.
type contextErrorCase struct {
	context     func() (context.Context, context.CancelFunc)
	is          []error
	contains    []string
	notContains []string
	name        string
	timeout     bool
}

// contextErrorCases covers deadline, cancellation, and custom causes of both.
func contextErrorCases() []contextErrorCase {
	return []contextErrorCase{
		{name: "deadline", timeout: true, is: []error{context.DeadlineExceeded},
			contains:    []string{"DNS lookup context ended: context deadline exceeded"},
			notContains: []string{"cause:", errTextTimeoutLegacy},
			context: func() (context.Context, context.CancelFunc) {
				return context.WithTimeout(context.Background(), time.Millisecond)
			}},
		{name: "cancellation", is: []error{context.Canceled},
			contains: []string{"DNS lookup context ended: context canceled"}, notContains: []string{"cause:"},
			context: func() (context.Context, context.CancelFunc) {
				ctx, cancel := context.WithCancel(context.Background())
				cancel()

				return ctx, cancel
			}},
		{name: "cancellation with cause", is: []error{context.Canceled, errShutdown},
			contains: []string{"DNS lookup context ended: context canceled; cause: " + errShutdown.Error()},
			context: func() (context.Context, context.CancelFunc) {
				ctx, cancel := context.WithCancelCause(context.Background())
				cancel(errShutdown)

				return ctx, func() {}
			}},
		{name: "deadline with cause", timeout: true, is: []error{context.DeadlineExceeded, errBudgetSpent},
			contains: []string{"DNS lookup context ended: context deadline exceeded; cause: " + errBudgetSpent.Error()},
			context: func() (context.Context, context.CancelFunc) {
				return context.WithTimeoutCause(context.Background(), time.Millisecond, errBudgetSpent)
			}},
		{name: "cause wrapping the context error", is: []error{context.Canceled},
			contains: []string{"; cause: drain: context canceled"},
			context: func() (context.Context, context.CancelFunc) {
				ctx, cancel := context.WithCancelCause(context.Background())
				cancel(wrapDrain(context.Canceled))

				return ctx, func() {}
			}},
		{name: "deadline cause on a cancellation is no timeout", is: []error{context.Canceled, context.DeadlineExceeded},
			contains: []string{"context canceled; cause: context deadline exceeded"},
			context: func() (context.Context, context.CancelFunc) {
				ctx, cancel := context.WithCancelCause(context.Background())
				cancel(context.DeadlineExceeded)

				return ctx, func() {}
			}},
		{name: "uncomparable cause", is: []error{context.Canceled}, contains: []string{"; cause: odd cause"},
			context: func() (context.Context, context.CancelFunc) {
				ctx, cancel := context.WithCancelCause(context.Background())
				cancel(uncomparableError{"odd", "cause"})

				return ctx, func() {}
			}},
	}
}

// errTextTimeoutLegacy is the resolver text the context error used to borrow for an expired budget.
const errTextTimeoutLegacy = "i/o timeout"

// wrapDrain wraps err like a caller that adds its own context to a cancellation.
func wrapDrain(err error) error {
	return &drainError{err: err}
}

// drainError is a custom cause that wraps another error.
type drainError struct {
	err error
}

// Error describes the drain.
func (e *drainError) Error() string {
	return "drain: " + e.err.Error()
}

// Unwrap returns the wrapped error.
func (e *drainError) Unwrap() error {
	return e.err
}

// TestLookupRaceContextErrorKeepsCause pins that an ended lookup context names the context end and its cause in the
// DNS error text, keeps the standard context error and the cause reachable through errors.Is, and marks only an
// expired deadline as a timeout.
func TestLookupRaceContextErrorKeepsCause(t *testing.T) {
	for _, test := range contextErrorCases() {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := test.context()
			defer cancel()

			err := endedRaceError(ctx, t)

			var dnsErr *net.DNSError
			if !errors.As(err, &dnsErr) || dnsErr.Name != testLookupName || dnsErr.IsTimeout != test.timeout {
				t.Fatalf("error %#v, want a DNS error for %s with timeout %v", err, testLookupName, test.timeout)
			}

			for _, target := range test.is {
				if !errors.Is(err, target) {
					t.Errorf("errors.Is(%v, %v) = false", err, target)
				}
			}

			for _, text := range test.contains {
				if !strings.Contains(err.Error(), text) {
					t.Errorf("error text %q lacks %q", err.Error(), text)
				}
			}

			for _, text := range test.notContains {
				if strings.Contains(err.Error(), text) {
					t.Errorf("error text %q must not contain %q", err.Error(), text)
				}
			}
		})
	}
}

// TestLookupRaceContextErrorFindsUncomparableCause pins that a cause of an uncomparable type stays reachable through
// errors.As.
func TestLookupRaceContextErrorFindsUncomparableCause(t *testing.T) {
	ctx, cancel := context.WithCancelCause(context.Background())
	cancel(uncomparableError{"odd", "cause"})

	var cause uncomparableError
	if err := endedRaceError(ctx, t); !errors.As(err, &cause) || cause.Error() != "odd cause" {
		t.Fatalf("errors.As(%v) found %v", err, cause)
	}
}

// endedRaceError runs a race whose attempt never answers until ctx has ended and returns the race error.
func endedRaceError(ctx context.Context, t *testing.T) error {
	t.Helper()

	release := make(chan struct{})

	t.Cleanup(func() { close(release) })

	race := newLookupRace(ctx, testLookupName, []*net.Resolver{{}}, func(context.Context, *net.Resolver) (struct{}, error) {
		<-release

		return struct{}{}, nil
	})

	<-ctx.Done()

	_, err := race.run(time.Hour)

	return err
}
