package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sassoftware/relic/v8/lib/pkcs7"
	"github.com/stretchr/testify/require"
)

func TestVerifyDetached(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "report signer"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	require.NoError(t, err)
	cert, _ := x509.ParseCertificate(der)

	dir := t.TempDir()
	content := []byte(`{"review":"ok"}`)
	contentPath := filepath.Join(dir, "review-report.json")
	require.NoError(t, os.WriteFile(contentPath, content, 0o600))
	digest := sha256.Sum256(content)
	b := pkcs7.NewBuilder(priv, []*x509.Certificate{cert}, crypto.SHA256)
	require.NoError(t, b.SetDetachedContent(pkcs7.OidData, digest[:]))
	require.NoError(t, b.AddAuthenticatedAttribute(pkcs7.OidAttributeSigningTime, time.Now().UTC()))
	psd, err := b.Sign()
	require.NoError(t, err)
	sig, err := psd.Marshal()
	require.NoError(t, err)
	sigPath := filepath.Join(dir, "review-report.json.p7s")
	require.NoError(t, os.WriteFile(sigPath, sig, 0o600))

	info, err := verifyDetached(sigPath, contentPath)
	require.NoError(t, err)
	require.Equal(t, "report signer", info.Cert.Subject.CommonName)
	require.False(t, info.SignedAt.IsZero())

	require.NoError(t, os.WriteFile(contentPath, append(content, ' '), 0o600))
	_, err = verifyDetached(sigPath, contentPath)
	require.Error(t, err, "modified content must fail")

	require.NoError(t, os.WriteFile(sigPath, nil, 0o600))
	_, err = verifyDetached(sigPath, contentPath)
	require.ErrorContains(t, err, "unsigned")
}
