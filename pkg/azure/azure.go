package azure

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/keyvault/azkeys"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azcertificates"
	"github.com/go-jose/go-jose/v4"
	"github.com/sassoftware/relic/v8/config"
	"github.com/sassoftware/relic/v8/lib/certloader"
	"github.com/sassoftware/relic/v8/lib/pkcs7"
	"github.com/sassoftware/relic/v8/lib/x509tools"
)

var pkcs7SignedData = []byte{0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02}

type AzureKey struct {
	kconf    *config.KeyConfig
	cli      *azkeys.Client
	pub      crypto.PublicKey
	kname    string
	kversion string
	id       []byte
	cert     []byte

	Fcert []*x509.Certificate
}

func (k *AzureKey) Config() *config.KeyConfig { return k.kconf }
func (k *AzureKey) Certificate() []byte       { return k.cert }
func (k *AzureKey) GetID() []byte             { return k.id }
func (k *AzureKey) ImportCertificate(cert *x509.Certificate) error {
	return fmt.Errorf("importing certificate not supported for AzureKey")
}

func (k *AzureKey) SignContext(ctx context.Context, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	alg, err := k.sigAlgorithm(opts)
	if err != nil {
		return nil, err
	}

	resp, err := k.cli.Sign(ctx, k.kname, k.kversion, azkeys.SignParameters{
		Algorithm: &alg,
		Value:     digest,
	}, nil)
	if err != nil {
		return nil, err
	}
	sig := resp.Result
	if _, ok := k.pub.(*ecdsa.PublicKey); ok {
		// repack as ASN.1
		unpacked, err := x509tools.UnpackEcdsaSignature(sig)
		if err != nil {
			return nil, err
		}
		sig = unpacked.Marshal()
	}
	return sig, nil
}

// select a JOSE signature algorithm based on the public key algorithm and requested hash func
func (k *AzureKey) sigAlgorithm(opts crypto.SignerOpts) (azkeys.JSONWebKeySignatureAlgorithm, error) {
	var alg azkeys.JSONWebKeySignatureAlgorithm
	switch opts.HashFunc() {
	case crypto.SHA256:
		alg = "256"
	case crypto.SHA384:
		alg = "384"
	case crypto.SHA512:
		alg = "512"
	default:
		return "", fmt.Errorf("unsupported digest algorithm %s", opts.HashFunc())
	}
	switch k.pub.(type) {
	case *rsa.PublicKey:
		if _, ok := opts.(*rsa.PSSOptions); ok {
			return "PS" + alg, nil
		} else {
			return "RS" + alg, nil
		}
	case *ecdsa.PublicKey:
		return "ES" + alg, nil
	default:
		return "", fmt.Errorf("unsupported public key type %T", k.pub)
	}
}

func (k *AzureKey) Public() crypto.PublicKey {
	return k.pub
}

func (k *AzureKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	return k.SignContext(context.Background(), digest, opts)
}

func NewAzureKey(vaultUrl, tenant, client, secret, certName, certVersion string, ctx context.Context) (*AzureKey, error) {
	azcr, err := azidentity.NewClientSecretCredential(tenant, client, secret, nil)
	if err != nil {
		panic(err)
	}

	certCli, err := azcertificates.NewClient(vaultUrl, azcr, nil)
	if err != nil {
		panic(err)
	}

	cert, err := certCli.GetCertificate(ctx, certName, certVersion, nil)
	if err != nil {
		panic(err)
	}

	pemin := cert.CER
	var certs []*x509.Certificate
	for {
		var block *pem.Block
		block, pemin = pem.Decode(pemin)
		if block == nil && len(certs) > 0 {
			break
		} else if block != nil && block.Type == "CERTIFICATE" || block != nil && block.Type == "PKCS7" {
			newcerts, err := parseCertificatesDer(block.Bytes)
			if err != nil {
				return nil, err
			}
			certs = append(certs, newcerts.Certificates...)
		} else {
			newcerts, err := parseCertificatesDer(pemin)
			if err != nil {
				return nil, err
			}
			certs = append(certs, newcerts.Certificates...)
			break
		}
	}

	keyClient, err := azkeys.NewClient(vaultUrl, azcr, nil)
	if err != nil {
		panic(fmt.Errorf("creating key client: %w", err))
	}

	key, err := keyClient.GetKey(ctx, certName, certVersion, nil)
	if err != nil {
		panic(fmt.Errorf("getting key: %w", err))
	}

	// strip off -HSM suffix to get a key type jose will accept
	kty := azkeys.JSONWebKeyType(strings.TrimSuffix(string(*key.Key.Kty), "-HSM"))
	key.Key.Kty = &kty

	keyBlob, err := json.Marshal(key.Key)
	if err != nil {
		return nil, fmt.Errorf("marshaling public key: %w", err)
	}

	var jwk jose.JSONWebKey
	if err := json.Unmarshal(keyBlob, &jwk); err != nil {
		return nil, fmt.Errorf("unmarshaling public key: %w", err)
	}

	return &AzureKey{
		kconf:    NewKeyConfig("azure", "azure"),
		cli:      keyClient,
		pub:      jwk.Key,
		kname:    certName,
		kversion: certVersion,
		cert:     cert.CER,
		Fcert:    certs,
		id:       []byte(cert.KID.Name() + "/" + cert.KID.Version()),
	}, nil

}

func parseCertificatesDer(der []byte) (*certloader.Certificate, error) {
	var certifs []*x509.Certificate
	if bytes.Contains(der[:32], pkcs7SignedData) {
		psd, err := pkcs7.Unmarshal(der)
		if err != nil {
			return nil, err
		}
		certifs, err = psd.Content.Certificates.Parse()
		if err != nil {
			return nil, err
		}
	} else {
		var err error
		certifs, err = x509.ParseCertificates(der)
		if err != nil {
			return nil, err
		}
	}
	if len(certifs) == 0 {
		return nil, fmt.Errorf("no certificates found in DER data")
	}

	return &certloader.Certificate{
		Leaf: certifs[0], Certificates: certifs,
	}, nil
}

func NewKeyConfig(name string, token string) *config.KeyConfig {
	return &config.KeyConfig{
		ID:    name,
		Token: token,
	}
}
