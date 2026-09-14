package main

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

const journalProducer = "producer"
const journalConsumer = "consumer"

type journalConfig struct {
	Brokers         []string `mapstructure:"brokers"`
	Role            string   `mapstructure:"role"`
	Topic           string   `mapstructure:"topic"`
	QuarantineTopic string   `mapstructure:"quarantine_topic"`
	GroupID         string   `mapstructure:"group_id"`
	CAFile          string   `mapstructure:"ca_file"`
	CertificateFile string   `mapstructure:"certificate_file"`
	KeyFile         string   `mapstructure:"key_file"`
	DeliveryTimeout string   `mapstructure:"delivery_timeout"`
}

// validateJournal requires explicit TLS, bounded buffers and an unambiguous process responsibility.
func (c *configuration) validateJournal() error {
	j := c.raw.Journal
	if j == nil {
		return nil
	}

	if !j.validIdentity() || !j.validPaths() {
		return errConfiguration
	}

	if !j.validBrokers() {
		return errConfiguration
	}

	timeout, err := time.ParseDuration(j.DeliveryTimeout)
	if err != nil || timeout < 100*time.Millisecond || timeout > 10*time.Second {
		return errConfiguration
	}

	return nil
}

// tlsConfig requires a verified server certificate and reloads the mounted client certificate on each handshake.
func (j *journalConfig) tlsConfig() (*tls.Config, error) {
	pem, err := os.ReadFile(j.CAFile)
	if err != nil {
		return nil, errConfiguration
	}

	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		return nil, errConfiguration
	}

	if _, err := tls.LoadX509KeyPair(j.CertificateFile, j.KeyFile); err != nil {
		return nil, errConfiguration
	}

	return &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots,
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			certificate, err := tls.LoadX509KeyPair(j.CertificateFile, j.KeyFile)
			if err != nil {
				return nil, errStateUnavailable
			}

			return &certificate, nil
		}}, nil
}

// validIdentity separates the process role and bounded broker/topic catalog from filesystem configuration.
func (j *journalConfig) validIdentity() bool {
	return (j.Role == journalProducer || j.Role == journalConsumer) && len(j.Brokers) > 0 && len(j.Brokers) <= 16 &&
		identifierPattern.MatchString(j.Topic) && identifierPattern.MatchString(j.QuarantineTopic) && j.Topic != j.QuarantineTopic &&
		identifierPattern.MatchString(j.GroupID)
}

// validPaths requires deployment-owned absolute paths for mutual TLS material.
func (j *journalConfig) validPaths() bool {
	return filepath.IsAbs(j.CAFile) && filepath.IsAbs(j.CertificateFile) && filepath.IsAbs(j.KeyFile)
}

// validBrokers requires explicit numeric TCP ports for every deployment-owned bootstrap endpoint.
func (j *journalConfig) validBrokers() bool {
	for _, broker := range j.Brokers {
		host, port, err := net.SplitHostPort(broker)
		if err != nil || host == "" {
			return false
		}

		number, err := strconv.Atoi(port)
		if err != nil || number < 1 || number > 65535 {
			return false
		}
	}

	return true
}
