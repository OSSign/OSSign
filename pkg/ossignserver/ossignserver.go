// Package ossignserver implements a signer that delegates signing operations to
// an OSSign Server.
//
// The OSSign Server uses the same permission model as "trusted publishing":
// the CI job presents an OIDC identity token issued by the CI provider
// (e.g. GitHub Actions) and the server decides, based on the claims in that
// token (repository, ref, environment, workflow, ...), whether the job may use
// a given signing key. No long-lived secrets are required on the client side.
//
// The API used by this client is defined in docs/ossign-server-api.yaml.
package ossignserver

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/sassoftware/relic/v8/config"
	"github.com/sassoftware/relic/v8/lib/certloader"
	"github.com/sassoftware/relic/v8/lib/pkcs9"
)

const (
	// APIVersion is the version prefix of the OSSign Server API this client speaks.
	APIVersion = "v1"

	defaultTimeout = 60 * time.Second
	userAgent      = "ossign-cli"
)

// Signature algorithms as defined in the OSSign Server API.
const (
	SigAlgRSAPKCS1 = "RSA_PKCS1"
	SigAlgRSAPSS   = "RSA_PSS"
	SigAlgECDSA    = "ECDSA"
)

// --- API wire types (see docs/ossign-server-api.yaml) --------------------

// TokenRequest is the body of POST /api/v1/token.
type TokenRequest struct {
	// OIDCToken is the identity token issued by the CI provider.
	OIDCToken string `json:"oidcToken"`
	// Key is the name of the signing key the caller intends to use.
	Key string `json:"key"`
}

// TokenResponse is the response of POST /api/v1/token.
type TokenResponse struct {
	AccessToken string    `json:"accessToken"`
	TokenType   string    `json:"tokenType"`
	ExpiresAt   time.Time `json:"expiresAt"`
	Key         KeyInfo   `json:"key"`
}

// KeyInfo describes a signing key as returned by the server.
type KeyInfo struct {
	Name                string   `json:"name"`
	Description         string   `json:"description,omitempty"`
	KeyType             string   `json:"keyType"`
	SignatureAlgorithms []string `json:"signatureAlgorithms"`
	HashAlgorithms      []string `json:"hashAlgorithms"`
	SubjectName         string   `json:"subjectName,omitempty"`
	SerialNumber        string   `json:"serialNumber,omitempty"`
	NotAfter            string   `json:"notAfter,omitempty"`
}

// CertificateResponse is the response of GET /api/v1/keys/{key}/certificate.
type CertificateResponse struct {
	// Certificates is the chain, leaf first, as base64 encoded DER.
	Certificates []string `json:"certificates"`
	// PEM is the same chain as a single PEM encoded string. Optional.
	PEM string `json:"pem,omitempty"`
}

// SignRequest is the body of POST /api/v1/keys/{key}/sign.
type SignRequest struct {
	// Digest is the base64 encoded hash to sign.
	Digest string `json:"digest"`
	// HashAlgorithm is the algorithm that produced the digest (SHA256, SHA384, SHA512).
	HashAlgorithm string `json:"hashAlgorithm"`
	// SignatureAlgorithm selects the signature scheme (RSA_PKCS1, RSA_PSS, ECDSA).
	SignatureAlgorithm string `json:"signatureAlgorithm"`
	// PSSSaltLength is only used for RSA_PSS. -1 means "same as hash length".
	PSSSaltLength int `json:"pssSaltLength,omitempty"`
	// Metadata is free-form information that the server may log for auditing.
	Metadata map[string]string `json:"metadata,omitempty"`
}

// SignResponse is the response of POST /api/v1/keys/{key}/sign.
type SignResponse struct {
	// Signature is the base64 encoded signature. For ECDSA keys the signature
	// is ASN.1 DER encoded (SEQUENCE { r INTEGER, s INTEGER }).
	Signature string `json:"signature"`
	// OperationID is the server side audit identifier for this signature.
	OperationID string `json:"operationId,omitempty"`
}

// ErrorResponse is returned by the server for all non-2xx responses.
type ErrorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message"`
	Details any    `json:"details,omitempty"`
}

// --- Client -----------------------------------------------------------------

// Options configures the OSSign Server signer.
type Options struct {
	// URL is the base URL of the OSSign Server, e.g. https://sign.example.com
	URL string
	// Key is the name of the signing key on the server.
	Key string
	// Audience is the audience requested for the OIDC token. Defaults to URL.
	Audience string
	// Provider selects how the OIDC token is obtained. One of
	// "auto" (default), "github", "gitlab", "env" or "static".
	Provider string
	// IDToken is a pre-obtained OIDC token (Provider = "static").
	IDToken string
	// IDTokenEnv is the name of an environment variable holding the OIDC token (Provider = "env").
	IDTokenEnv string
	// Metadata is attached to every sign request for auditing purposes.
	Metadata map[string]string
	// HTTPClient can be used to override the HTTP client. Optional.
	HTTPClient *http.Client
}

// Key is a crypto.Signer backed by an OSSign Server.
type Key struct {
	opts  Options
	base  *url.URL
	http  *http.Client
	token *TokenResponse
	pub   crypto.PublicKey

	Certs []*x509.Certificate
}

func (k *Key) Config() *config.KeyConfig {
	return &config.KeyConfig{ID: "ossignServer", Token: "ossignServer"}
}

func (k *Key) Certificate() []byte {
	if len(k.Certs) == 0 {
		return nil
	}
	return k.Certs[0].Raw
}

func (k *Key) GetID() []byte {
	if len(k.Certs) == 0 {
		return []byte(k.opts.Key)
	}
	return []byte(k.Certs[0].SerialNumber.String())
}

func (k *Key) ImportCertificate(cert *x509.Certificate) error {
	return fmt.Errorf("importing certificate not supported for OSSign Server keys")
}

func (k *Key) Public() crypto.PublicKey {
	return k.pub
}

func (k *Key) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return k.SignContext(context.Background(), digest, opts)
}

func (k *Key) SignContext(ctx context.Context, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	hashAlg, err := hashName(opts.HashFunc())
	if err != nil {
		return nil, err
	}

	req := SignRequest{
		Digest:        base64.StdEncoding.EncodeToString(digest),
		HashAlgorithm: hashAlg,
		Metadata:      k.opts.Metadata,
	}

	switch k.pub.(type) {
	case *rsa.PublicKey:
		if pss, ok := opts.(*rsa.PSSOptions); ok {
			req.SignatureAlgorithm = SigAlgRSAPSS
			req.PSSSaltLength = pss.SaltLength
		} else {
			req.SignatureAlgorithm = SigAlgRSAPKCS1
		}
	case *ecdsa.PublicKey:
		req.SignatureAlgorithm = SigAlgECDSA
	default:
		return nil, fmt.Errorf("unsupported public key type %T", k.pub)
	}

	if err := k.ensureToken(ctx); err != nil {
		return nil, err
	}

	var resp SignResponse
	if err := k.do(ctx, http.MethodPost, "keys/"+url.PathEscape(k.opts.Key)+"/sign", req, &resp); err != nil {
		return nil, fmt.Errorf("signing with OSSign Server: %w", err)
	}

	sig, err := base64.StdEncoding.DecodeString(resp.Signature)
	if err != nil {
		return nil, fmt.Errorf("decoding signature from OSSign Server: %w", err)
	}
	return sig, nil
}

// ensureToken exchanges the OIDC token for an access token if there is no
// valid access token yet.
func (k *Key) ensureToken(ctx context.Context) error {
	if k.token != nil && time.Until(k.token.ExpiresAt) > 30*time.Second {
		return nil
	}

	idToken, err := GetIDToken(ctx, k.opts)
	if err != nil {
		return err
	}

	var resp TokenResponse
	k.token = nil
	if err := k.do(ctx, http.MethodPost, "token", TokenRequest{OIDCToken: idToken, Key: k.opts.Key}, &resp); err != nil {
		return fmt.Errorf("exchanging OIDC token with OSSign Server: %w", err)
	}
	if resp.AccessToken == "" {
		return fmt.Errorf("OSSign Server returned an empty access token")
	}
	k.token = &resp
	return nil
}

func (k *Key) fetchCertificates(ctx context.Context) error {
	if err := k.ensureToken(ctx); err != nil {
		return err
	}

	var resp CertificateResponse
	if err := k.do(ctx, http.MethodGet, "keys/"+url.PathEscape(k.opts.Key)+"/certificate", nil, &resp); err != nil {
		return fmt.Errorf("fetching certificate from OSSign Server: %w", err)
	}

	certs, err := parseCertificates(resp)
	if err != nil {
		return err
	}
	if len(certs) == 0 {
		return fmt.Errorf("OSSign Server returned no certificates for key %q", k.opts.Key)
	}

	k.Certs = certs
	k.pub = certs[0].PublicKey
	return nil
}

func (k *Key) do(ctx context.Context, method, path string, body any, out any) error {
	var reader io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(buf)
	}

	u := k.base.JoinPath("api", APIVersion, path)
	req, err := http.NewRequestWithContext(ctx, method, u.String(), reader)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", userAgent)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if k.token != nil {
		req.Header.Set("Authorization", "Bearer "+k.token.AccessToken)
	}

	resp, err := k.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return err
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var apiErr ErrorResponse
		if json.Unmarshal(data, &apiErr) == nil && apiErr.Error != "" {
			return fmt.Errorf("%s %s: %d %s: %s", method, u.Path, resp.StatusCode, apiErr.Error, apiErr.Message)
		}
		return fmt.Errorf("%s %s: unexpected status %d: %s", method, u.Path, resp.StatusCode, strings.TrimSpace(string(data)))
	}

	if out == nil {
		return nil
	}
	return json.Unmarshal(data, out)
}

func parseCertificates(resp CertificateResponse) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	for i, c := range resp.Certificates {
		der, err := base64.StdEncoding.DecodeString(c)
		if err != nil {
			return nil, fmt.Errorf("decoding certificate %d: %w", i, err)
		}
		parsed, err := x509.ParseCertificates(der)
		if err != nil {
			return nil, fmt.Errorf("parsing certificate %d: %w", i, err)
		}
		certs = append(certs, parsed...)
	}
	if len(certs) > 0 {
		return certs, nil
	}

	rest := []byte(resp.PEM)
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		parsed, err := x509.ParseCertificates(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parsing PEM certificate: %w", err)
		}
		certs = append(certs, parsed...)
	}
	return certs, nil
}

func hashName(h crypto.Hash) (string, error) {
	switch h {
	case crypto.SHA256:
		return "SHA256", nil
	case crypto.SHA384:
		return "SHA384", nil
	case crypto.SHA512:
		return "SHA512", nil
	default:
		return "", fmt.Errorf("unsupported digest algorithm %s", h)
	}
}

// NewKey authenticates against the OSSign Server using the CI provider's OIDC
// token, fetches the certificate chain for the configured key and returns a
// certloader.Certificate ready for signing.
func NewKey(ctx context.Context, opts Options, timestamper pkcs9.Timestamper) (*certloader.Certificate, error) {
	if opts.URL == "" {
		return nil, fmt.Errorf("ossignServer.url is required")
	}
	if opts.Key == "" {
		return nil, fmt.Errorf("ossignServer.key is required")
	}

	base, err := url.Parse(opts.URL)
	if err != nil {
		return nil, fmt.Errorf("invalid ossignServer.url: %w", err)
	}
	if base.Scheme != "https" && base.Hostname() != "localhost" && base.Hostname() != "127.0.0.1" {
		return nil, fmt.Errorf("ossignServer.url must use https")
	}

	httpClient := opts.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: defaultTimeout}
	}

	k := &Key{opts: opts, base: base, http: httpClient}
	if err := k.fetchCertificates(ctx); err != nil {
		return nil, err
	}

	return &certloader.Certificate{
		Leaf:         k.Certs[0],
		Certificates: k.Certs,
		PrivateKey:   k,
		KeyName:      opts.Key,
		Timestamper:  timestamper,
	}, nil
}
