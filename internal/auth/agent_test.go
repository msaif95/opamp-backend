package auth

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http/httptest"
	"testing"
)

// With client certificates switched off, a valid certificate alone must not
// authenticate an agent, and certificates of connected agents count as invalid.
func TestClientCertificatesIgnoredWhenSwitchedOff(t *testing.T) {
	a := &AgentAuthenticator{MTLSEnabled: func() bool { return false }}
	r := httptest.NewRequest("GET", "/v1/opamp", nil)
	r.TLS = &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{{Raw: []byte("leaf")}}}}
	if _, err := a.Authenticate(context.Background(), r); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("err = %v, want ErrUnauthenticated", err)
	}
}
