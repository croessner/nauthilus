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

package ldappool

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v3/server/config"
	ber "github.com/go-asn1-ber/asn1-ber"
)

const healthProbeTestTimeout = 2 * time.Second

type healthProbePKI struct {
	caCert     *x509.Certificate
	caKey      *ecdsa.PrivateKey
	caFile     string
	clientCert string
	clientKey  string
}

func TestHealthProbeUsesConfiguredPrivateCAForLDAPS(t *testing.T) {
	pki := newHealthProbePKI(t)
	serverTLS := pki.serverTLSConfig(t, []string{"localhost"}, false)

	target, closeServer, _ := startHealthProbeLDAPSServer(t, serverTLS)
	defer closeServer()

	conf := newHealthProbeConf(target, pki.caFile)
	runInitialHealthProbe(t, "private-ca", conf, false, true)
}

func TestHealthProbeRejectsUntrustedLDAPS(t *testing.T) {
	serverPKI := newHealthProbePKI(t)
	untrustedPKI := newHealthProbePKI(t)
	serverTLS := serverPKI.serverTLSConfig(t, []string{"localhost"}, false)

	target, closeServer, _ := startHealthProbeLDAPSServer(t, serverTLS)
	defer closeServer()

	conf := newHealthProbeConf(target, untrustedPKI.caFile)
	runInitialHealthProbe(t, "wrong-ca", conf, true, false)
}

func TestHealthProbeRejectsLDAPSNameMismatch(t *testing.T) {
	pki := newHealthProbePKI(t)
	serverTLS := pki.serverTLSConfig(t, []string{"not-localhost.invalid"}, false)

	target, closeServer, _ := startHealthProbeLDAPSServer(t, serverTLS)
	defer closeServer()

	conf := newHealthProbeConf(target, pki.caFile)
	runInitialHealthProbe(t, "name-mismatch", conf, true, false)
}

func TestHealthProbePerformsStartTLS(t *testing.T) {
	pki := newHealthProbePKI(t)
	serverTLS := pki.serverTLSConfig(t, []string{"localhost"}, false)

	target, closeServer, upgraded := startHealthProbeStartTLSServer(t, serverTLS, true)
	defer closeServer()

	conf := newHealthProbeConf(target, pki.caFile)
	conf.StartTLS = true
	runInitialHealthProbe(t, "starttls", conf, false, true)

	select {
	case ok := <-upgraded:
		if !ok {
			t.Fatal("health probe did not complete the StartTLS handshake")
		}
	case <-time.After(healthProbeTestTimeout):
		t.Fatal("timed out waiting for the StartTLS handshake")
	}
}

func TestHealthProbeRejectsFailedStartTLS(t *testing.T) {
	pki := newHealthProbePKI(t)
	serverTLS := pki.serverTLSConfig(t, []string{"localhost"}, false)

	target, closeServer, _ := startHealthProbeStartTLSServer(t, serverTLS, false)
	defer closeServer()

	conf := newHealthProbeConf(target, pki.caFile)
	conf.StartTLS = true
	runInitialHealthProbe(t, "starttls-failure", conf, true, false)
}

func TestHealthProbePresentsConfiguredClientCertificate(t *testing.T) {
	pki := newHealthProbePKI(t)
	serverTLS := pki.serverTLSConfig(t, []string{"localhost"}, true)

	target, closeServer, _ := startHealthProbeLDAPSServer(t, serverTLS)
	defer closeServer()

	conf := newHealthProbeConf(target, pki.caFile)
	conf.TLSClientCert = pki.clientCert
	conf.TLSClientKey = pki.clientKey
	runInitialHealthProbe(t, "mutual-tls", conf, false, true)
}

func TestHealthProbeRemainsTransportOnly(t *testing.T) {
	pki := newHealthProbePKI(t)
	serverTLS := pki.serverTLSConfig(t, []string{"localhost"}, false)

	target, closeServer, applicationData := startHealthProbeLDAPSServer(t, serverTLS)
	defer closeServer()

	conf := newHealthProbeConf(target, pki.caFile)
	conf.BindDN = "cn=must-not-bind,dc=example,dc=test"
	runInitialHealthProbe(t, "transport-only", conf, false, true)

	select {
	case hasApplicationData := <-applicationData:
		if hasApplicationData {
			t.Fatal("transport health probe sent an LDAP application request")
		}
	case <-time.After(healthProbeTestTimeout):
		t.Fatal("timed out waiting for transport-only probe evidence")
	}
}

// newHealthProbeConf creates a single-target configuration with bounded probes.
func newHealthProbeConf(target, caFile string) *config.LDAPConf {
	return &config.LDAPConf{
		ServerURIs:          []string{target},
		TLSCAFile:           caFile,
		HealthCheckInterval: time.Hour,
		HealthCheckTimeout:  500 * time.Millisecond,
	}
}

// runInitialHealthProbe starts the loop and waits for its synchronous first probe.
func runInitialHealthProbe(t *testing.T, pool string, conf *config.LDAPConf, initial, want bool) {
	t.Helper()
	setHealth(pool, conf.ServerURIs[0], initial)

	go startHealthLoop(pool, conf)

	deadline := time.Now().Add(healthProbeTestTimeout)
	for time.Now().Before(deadline) {
		if got := targetHealth(pool, conf.ServerURIs[0]); got == want {
			return
		}

		time.Sleep(10 * time.Millisecond)
	}

	t.Fatalf("target health = %t, want %t", targetHealth(pool, conf.ServerURIs[0]), want)
}

// targetHealth returns the synchronized health value used by target selection.
func targetHealth(pool, target string) bool {
	state := ensureTargetState(pool, target)

	healthMu.Lock()
	defer healthMu.Unlock()

	return state.healthy
}

// newHealthProbePKI creates an isolated CA and client identity.
func newHealthProbePKI(t *testing.T) *healthProbePKI {
	t.Helper()

	caKey := newHealthProbeKey(t)
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: "LDAP health test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	caDER := createHealthProbeCertificate(t, caTemplate, caTemplate, &caKey.PublicKey, caKey)

	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse CA certificate: %v", err)
	}

	testDir := t.TempDir()
	caFile := filepath.Join(testDir, "ca.pem")
	writeHealthProbePEM(t, caFile, "CERTIFICATE", caDER)

	clientCert, clientKey := issueHealthProbeIdentity(
		t,
		testDir,
		"client",
		caCert,
		caKey,
		nil,
		[]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	)

	return &healthProbePKI{
		caCert:     caCert,
		caKey:      caKey,
		caFile:     caFile,
		clientCert: clientCert,
		clientKey:  clientKey,
	}
}

// serverTLSConfig creates a server identity and optional client-certificate policy.
func (pki *healthProbePKI) serverTLSConfig(t *testing.T, dnsNames []string, requireClient bool) *tls.Config {
	t.Helper()

	serverCertFile, serverKeyFile := issueHealthProbeIdentity(
		t,
		t.TempDir(),
		"server",
		pki.caCert,
		pki.caKey,
		dnsNames,
		[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	)

	serverCert, err := tls.LoadX509KeyPair(serverCertFile, serverKeyFile)
	if err != nil {
		t.Fatalf("load server key pair: %v", err)
	}

	serverConfig := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		MinVersion:   tls.VersionTLS12,
	}

	if requireClient {
		clientRoots := x509.NewCertPool()
		clientRoots.AddCert(pki.caCert)

		serverConfig.ClientAuth = tls.RequireAndVerifyClientCert
		serverConfig.ClientCAs = clientRoots
	}

	return serverConfig
}

// issueHealthProbeIdentity writes one CA-signed certificate and private key.
func issueHealthProbeIdentity(
	t *testing.T,
	dir string,
	name string,
	caCert *x509.Certificate,
	caKey *ecdsa.PrivateKey,
	dnsNames []string,
	usage []x509.ExtKeyUsage,
) (string, string) {
	t.Helper()

	key := newHealthProbeKey(t)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: name},
		DNSNames:     dnsNames,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  usage,
	}
	certDER := createHealthProbeCertificate(t, template, caCert, &key.PublicKey, caKey)

	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal %s private key: %v", name, err)
	}

	certFile := filepath.Join(dir, name+".pem")
	keyFile := filepath.Join(dir, name+"-key.pem")

	writeHealthProbePEM(t, certFile, "CERTIFICATE", certDER)
	writeHealthProbePEM(t, keyFile, "PRIVATE KEY", keyDER)

	return certFile, keyFile
}

// newHealthProbeKey creates an ephemeral ECDSA key.
func newHealthProbeKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ECDSA key: %v", err)
	}

	return key
}

// createHealthProbeCertificate signs one ephemeral test certificate.
func createHealthProbeCertificate(
	t *testing.T,
	template *x509.Certificate,
	parent *x509.Certificate,
	publicKey *ecdsa.PublicKey,
	signer *ecdsa.PrivateKey,
) []byte {
	t.Helper()

	certificate, err := x509.CreateCertificate(rand.Reader, template, parent, publicKey, signer)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	return certificate
}

// writeHealthProbePEM writes certificate material inside a test-only temporary directory.
func writeHealthProbePEM(t *testing.T, path, blockType string, data []byte) {
	t.Helper()

	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		t.Fatalf("open PEM file: %v", err)
	}

	if err = pem.Encode(file, &pem.Block{Type: blockType, Bytes: data}); err != nil {
		_ = file.Close()

		t.Fatalf("encode PEM file: %v", err)
	}

	if err = file.Close(); err != nil {
		t.Fatalf("close PEM file: %v", err)
	}
}

// startHealthProbeLDAPSServer accepts TLS probes and reports LDAP application data.
func startHealthProbeLDAPSServer(t *testing.T, tlsConfig *tls.Config) (string, func(), <-chan bool) {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for LDAPS: %v", err)
	}

	applicationData := make(chan bool, 1)

	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer func() {
			_ = connection.Close()
		}()

		tlsConnection := tls.Server(connection, tlsConfig)
		if handshakeErr := tlsConnection.Handshake(); handshakeErr != nil {
			applicationData <- false

			return
		}

		_ = tlsConnection.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
		buffer := make([]byte, 1)

		size, _ := tlsConnection.Read(buffer)
		applicationData <- size > 0
	}()

	target := "ldaps://localhost:" + strconv.Itoa(listener.Addr().(*net.TCPAddr).Port)

	return target, func() { _ = listener.Close() }, applicationData
}

// startHealthProbeStartTLSServer accepts one LDAP StartTLS request and optionally upgrades it.
func startHealthProbeStartTLSServer(
	t *testing.T,
	tlsConfig *tls.Config,
	allowUpgrade bool,
) (string, func(), <-chan bool) {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for StartTLS: %v", err)
	}

	upgraded := make(chan bool, 1)

	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer func() {
			_ = connection.Close()
		}()

		_ = connection.SetDeadline(time.Now().Add(healthProbeTestTimeout))

		request, readErr := ber.ReadPacket(connection)
		if readErr != nil || !allowUpgrade {
			upgraded <- false

			return
		}

		if _, writeErr := connection.Write(newStartTLSResponse(request).Bytes()); writeErr != nil {
			upgraded <- false

			return
		}

		tlsConnection := tls.Server(connection, tlsConfig)
		upgraded <- tlsConnection.Handshake() == nil
	}()

	target := "ldap://localhost:" + strconv.Itoa(listener.Addr().(*net.TCPAddr).Port)

	return target, func() { _ = listener.Close() }, upgraded
}

// newStartTLSResponse creates a successful LDAP ExtendedResponse for StartTLS.
func newStartTLSResponse(request *ber.Packet) *ber.Packet {
	messageID := request.Children[0].Value
	response := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Response")
	response.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, messageID, "MessageID"))

	extendedResponse := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ber.Tag(24), nil, "Extended Response")
	extendedResponse.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, 0, "Result Code"))
	extendedResponse.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "Matched DN"))
	extendedResponse.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "Diagnostic Message"))
	response.AppendChild(extendedResponse)

	return response
}
