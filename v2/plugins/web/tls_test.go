package web

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// generateTestCert writes a real, self-signed ECDSA cert/key pair (stdlib
// only — no shelling out to openssl) to a temp dir and returns their paths.
func generateTestCert(t *testing.T) (certFile, keyFile string) {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}

	dir := t.TempDir()
	certFile = filepath.Join(dir, "cert.pem")
	keyFile = filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	return certFile, keyFile
}

// TestTLS_EncryptedRequestSucceedsPlaintextRejected proves TLS is real and
// enforced, not merely accepted-and-ignored: a request over a genuine TLS
// connection succeeds, and a plaintext HTTP request to the SAME port fails
// (because the listener now speaks TLS only).
func TestTLS_EncryptedRequestSucceedsPlaintextRejected(t *testing.T) {
	certFile, keyFile := generateTestCert(t)

	// http.Server.ListenAndServeTLS resolves the address itself, so we
	// need a fixed, known port to connect back to after Start — bind one
	// up front, close it, and hand that address to the plugin via config
	// (a brief race with anything else grabbing the same port between
	// close and re-bind is an accepted, standard test tradeoff here).
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("pre-bind: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()

	reg := newFakeRegistry()
	reg.Provide("kv", newFakeKV())
	reg.Provide("object", newFakeObjectStore())
	cfg := &fakeConfig{data: map[string]any{
		"addr":          addr,
		"tls_cert_file": certFile,
		"tls_key_file":  keyFile,
	}}
	k := &fakeKernel{reg: reg, cfg: cfg, log: noopLogger{t: t}}

	p := NewPlugin("", "", "")
	if err := p.Init(context.Background(), k); err != nil {
		t.Fatalf("Init: %v", err)
	}

	if err := p.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer p.Stop(context.Background())

	// Encrypted request must succeed.
	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // test-only: self-signed cert, no CA to verify against
	}}
	resp, err := client.Get("https://" + addr + "/metrics")
	if err != nil {
		t.Fatalf("HTTPS request failed, expected success: %v", err)
	}
	resp.Body.Close()

	// A plaintext request to the same port must never reach the real
	// /metrics handler. Go's http.Server (also used for the TLS listener)
	// detects a plaintext HTTP request arriving on a TLS socket and
	// replies with its own built-in plaintext 400 explaining the mismatch
	// — so `err` here is often nil (a response DOES come back), but that
	// response must be the server's rejection page, never real API data.
	// This is still real enforcement: no application data is ever served
	// over the plaintext connection.
	plainClient := &http.Client{Timeout: 2 * time.Second}
	plainResp, err := plainClient.Get("http://" + addr + "/metrics")
	if err != nil {
		t.Logf("plaintext request correctly failed outright: %v", err)
		return
	}
	defer plainResp.Body.Close()
	body, _ := io.ReadAll(plainResp.Body)
	if plainResp.StatusCode == http.StatusOK && strings.Contains(string(body), "http_request_duration_seconds") {
		t.Fatalf("plaintext request unexpectedly reached the real /metrics handler: status=%d body=%q", plainResp.StatusCode, body)
	}
	t.Logf("plaintext request correctly rejected (not the real handler): status=%d body=%q", plainResp.StatusCode, body)
}

// TestTLS_MismatchedConfigRejected confirms setting only one of
// tls_cert_file/tls_key_file is a hard Init error, not silently ignored.
func TestTLS_MismatchedConfigRejected(t *testing.T) {
	reg := newFakeRegistry()
	reg.Provide("kv", newFakeKV())
	reg.Provide("object", newFakeObjectStore())
	k := &fakeKernel{reg: reg, cfg: &fakeConfig{data: map[string]any{
		"tls_cert_file": "/some/cert.pem",
	}}, log: noopLogger{t: t}}

	p := NewPlugin("", "", "")
	if err := p.Init(context.Background(), k); err == nil {
		t.Fatalf("expected Init to reject a cert-without-key config, got nil error")
	}
}
