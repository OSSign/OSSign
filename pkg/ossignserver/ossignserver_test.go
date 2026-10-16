package ossignserver

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type fakeServer struct {
	t      *testing.T
	priv   crypto.Signer
	cert   *x509.Certificate
	tokens int
	signs  int
}

func newFakeServer(t *testing.T, priv crypto.Signer) *httptest.Server {
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, priv.Public(), priv)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	fs := &fakeServer{t: t, priv: priv, cert: cert}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/token", func(w http.ResponseWriter, r *http.Request) {
		var req TokenRequest
		require.NoError(t, json.NewDecoder(r.Body).Decode(&req))
		if req.OIDCToken != "oidc-token" || req.Key != "mykey" {
			w.WriteHeader(403)
			json.NewEncoder(w).Encode(ErrorResponse{Error: "policy_denied", Message: "nope"})
			return
		}
		fs.tokens++
		json.NewEncoder(w).Encode(TokenResponse{AccessToken: "access", TokenType: "Bearer", ExpiresAt: time.Now().Add(time.Hour), Key: KeyInfo{Name: "mykey"}})
	})
	auth := func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Authorization") != "Bearer access" {
				w.WriteHeader(401)
				json.NewEncoder(w).Encode(ErrorResponse{Error: "invalid_token", Message: "missing"})
				return
			}
			h(w, r)
		}
	}
	mux.HandleFunc("GET /api/v1/keys/mykey/certificate", auth(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(CertificateResponse{Certificates: []string{base64.StdEncoding.EncodeToString(der)}})
	}))
	mux.HandleFunc("POST /api/v1/keys/mykey/sign", auth(func(w http.ResponseWriter, r *http.Request) {
		var req SignRequest
		require.NoError(t, json.NewDecoder(r.Body).Decode(&req))
		require.Equal(t, "SHA256", req.HashAlgorithm)
		digest, err := base64.StdEncoding.DecodeString(req.Digest)
		require.NoError(t, err)
		var opts crypto.SignerOpts = crypto.SHA256
		switch req.SignatureAlgorithm {
		case SigAlgRSAPSS:
			opts = &rsa.PSSOptions{SaltLength: req.PSSSaltLength, Hash: crypto.SHA256}
		case SigAlgRSAPKCS1, SigAlgECDSA:
		default:
			t.Fatalf("unexpected algorithm %s", req.SignatureAlgorithm)
		}
		sig, err := priv.Sign(rand.Reader, digest, opts)
		require.NoError(t, err)
		fs.signs++
		json.NewEncoder(w).Encode(SignResponse{Signature: base64.StdEncoding.EncodeToString(sig), OperationID: "op-1"})
	}))
	return httptest.NewServer(mux)
}

func TestRSASignRoundTrip(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	srv := newFakeServer(t, priv)
	defer srv.Close()

	cert, err := NewKey(context.Background(), Options{
		URL: strings.Replace(srv.URL, "127.0.0.1", "localhost", 1), Key: "mykey", Provider: "static", IDToken: "oidc-token",
		HTTPClient: srv.Client(),
	}, nil)
	require.NoError(t, err)
	require.Equal(t, "test", cert.Leaf.Subject.CommonName)

	digest := sha256.Sum256([]byte("hello"))
	sig, err := cert.Signer().Sign(rand.Reader, digest[:], crypto.SHA256)
	require.NoError(t, err)
	require.NoError(t, rsa.VerifyPKCS1v15(&priv.PublicKey, crypto.SHA256, digest[:], sig))

	sig, err = cert.Signer().Sign(rand.Reader, digest[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256})
	require.NoError(t, err)
	require.NoError(t, rsa.VerifyPSS(&priv.PublicKey, crypto.SHA256, digest[:], sig, nil))
}

func TestECDSASignRoundTrip(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	srv := newFakeServer(t, priv)
	defer srv.Close()

	cert, err := NewKey(context.Background(), Options{
		URL: srv.URL, Key: "mykey", Provider: "static", IDToken: "oidc-token", HTTPClient: srv.Client(),
	}, nil)
	require.NoError(t, err)

	digest := sha256.Sum256([]byte("hello"))
	sig, err := cert.Signer().Sign(rand.Reader, digest[:], crypto.SHA256)
	require.NoError(t, err)
	require.True(t, ecdsa.VerifyASN1(&priv.PublicKey, digest[:], sig))
}

func TestPolicyDenied(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	srv := newFakeServer(t, priv)
	defer srv.Close()

	_, err = NewKey(context.Background(), Options{
		URL: srv.URL, Key: "mykey", Provider: "static", IDToken: "wrong", HTTPClient: srv.Client(),
	}, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "policy_denied")
}

func TestGitHubProvider(t *testing.T) {
	gh := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "Bearer runner-token", r.Header.Get("Authorization"))
		require.Equal(t, "https://sign.example.com", r.URL.Query().Get("audience"))
		json.NewEncoder(w).Encode(map[string]string{"value": "gh-oidc"})
	}))
	defer gh.Close()
	t.Setenv(envGitHubRequestURL, gh.URL+"/?api-version=2.0")
	t.Setenv(envGitHubRequestToken, "runner-token")

	tok, err := GetIDToken(context.Background(), Options{URL: "https://sign.example.com", Provider: "auto"})
	require.NoError(t, err)
	require.Equal(t, "gh-oidc", tok)
}

func TestRequiresHTTPS(t *testing.T) {
	_, err := NewKey(context.Background(), Options{URL: "http://sign.example.com", Key: "k"}, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "https")
}
