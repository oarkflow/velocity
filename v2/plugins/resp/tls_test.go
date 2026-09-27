package resp

import (
	"context"
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
	"testing"
	"time"

	"github.com/oarkflow/velocity/v2/api"
	"github.com/oarkflow/velocity/v2/kernel"
)

func generateRespTestCert(t *testing.T) (certFile, keyFile string) {
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

// TestTLS_RESPEncryptedCommandSucceedsPlaintextRejected proves TLS is real
// and enforced for the RESP server: a command sent over a genuine TLS
// connection round-trips correctly, and a plaintext connection to the same
// port never receives a valid RESP reply (the listener only speaks TLS).
func TestTLS_RESPEncryptedCommandSucceedsPlaintextRejected(t *testing.T) {
	certFile, keyFile := generateRespTestCert(t)

	k := kernel.New(kernel.Manifest{Plugins: []kernel.PluginSpec{
		{Name: "kv", Enabled: true},
		{Name: "resp", Enabled: true, Config: map[string]any{
			"addr":          "127.0.0.1:0",
			"tls_cert_file": certFile,
			"tls_key_file":  keyFile,
		}},
	}})

	kv := newMemKV()
	fakeKVPlugin := &fakeServicePlugin{name: "kv", svc: kv}
	respPlugin := NewPlugin("kv")

	if err := k.Boot(context.Background(), []api.Plugin{fakeKVPlugin, respPlugin}, map[string]bool{"kv": true, "resp": true}); err != nil {
		t.Fatalf("boot: %v", err)
	}
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = k.Shutdown(shutdownCtx)
	}()

	addr := respPlugin.Addr()

	// Encrypted command must succeed.
	conn, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true}) // test-only: self-signed cert
	if err != nil {
		t.Fatalf("TLS dial failed, expected success: %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("*1\r\n$4\r\nPING\r\n")); err != nil {
		t.Fatalf("write over TLS: %v", err)
	}
	buf := make([]byte, 64)
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read over TLS: %v", err)
	}
	if got := string(buf[:n]); got != "+PONG\r\n" {
		t.Fatalf("PING over TLS: got %q, want %q", got, "+PONG\r\n")
	}

	// Plaintext connection to the same port must never yield a valid RESP
	// reply — either the raw TLS handshake bytes we send are rejected, or
	// the connection is closed before any usable response arrives.
	plain, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("plaintext dial: %v", err)
	}
	defer plain.Close()
	plain.Write([]byte("*1\r\n$4\r\nPING\r\n"))
	plain.SetReadDeadline(time.Now().Add(1 * time.Second))
	pbuf := make([]byte, 64)
	pn, perr := plain.Read(pbuf)
	if perr == nil && string(pbuf[:pn]) == "+PONG\r\n" {
		t.Fatalf("plaintext PING unexpectedly got a valid PONG reply from a TLS-only listener")
	}
	t.Logf("plaintext request correctly did not get a valid reply (n=%d, err=%v)", pn, perr)
}

// TestTLS_RESPMismatchedConfigRejected confirms setting only one of
// tls_cert_file/tls_key_file is a hard error, not silently ignored.
func TestTLS_RESPMismatchedConfigRejected(t *testing.T) {
	k := kernel.New(kernel.Manifest{Plugins: []kernel.PluginSpec{
		{Name: "kv", Enabled: true},
		{Name: "resp", Enabled: true, Config: map[string]any{
			"tls_cert_file": "/some/cert.pem",
		}},
	}})
	kv := newMemKV()
	fakeKVPlugin := &fakeServicePlugin{name: "kv", svc: kv}
	respPlugin := NewPlugin("kv")

	err := k.Boot(context.Background(), []api.Plugin{fakeKVPlugin, respPlugin}, map[string]bool{"kv": true, "resp": true})
	if err == nil {
		t.Fatalf("expected Boot to fail on a cert-without-key config, got nil error")
	}
}
