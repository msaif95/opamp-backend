package auth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func testCA(t *testing.T, name string) (*x509.Certificate, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func trusts(pool *x509.CertPool, cert *x509.Certificate) bool {
	_, err := cert.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
	return err == nil
}

func TestCABundleReloadsWhenFileChanges(t *testing.T) {
	oldCA, oldPEM := testCA(t, "old-ca")
	newCA, newPEM := testCA(t, "new-ca")
	path := filepath.Join(t.TempDir(), "ca.crt")
	if err := os.WriteFile(path, oldPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	b := &caBundle{path: path}
	pool, err := b.pool()
	if err != nil || !trusts(pool, oldCA) || trusts(pool, newCA) {
		t.Fatalf("initial bundle wrong: err %v", err)
	}
	if again, _ := b.pool(); again != pool {
		t.Fatal("unchanged file was re-parsed")
	}

	// Rotation: the bundle now holds only the new CA.
	if err := os.WriteFile(path, newPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	_ = os.Chtimes(path, time.Now(), time.Now().Add(2*time.Second))
	pool, err = b.pool()
	if err != nil || !trusts(pool, newCA) || trusts(pool, oldCA) {
		t.Fatalf("bundle not reloaded after rotation: err %v", err)
	}

	// A corrupt write must not take trust away: the last good bundle stays.
	if err := os.WriteFile(path, []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	_ = os.Chtimes(path, time.Now(), time.Now().Add(4*time.Second))
	pool, err = b.pool()
	if err == nil || pool == nil || !trusts(pool, newCA) {
		t.Fatalf("corrupt bundle: err %v, kept last good %v", err, pool != nil)
	}
}
