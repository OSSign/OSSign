package azure

import (
	"context"
	"crypto"
	"crypto/x509"
	"fmt"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/sassoftware/relic/v8/config"
	"github.com/sassoftware/relic/v8/lib/certloader"
	"github.com/sassoftware/relic/v8/lib/pkcs9"

	goats "github.com/ossign/go-azure-trusted-signing"
)

type AzureTrustedKey struct {
	*goats.AzureTrustedSigning

	crtCache []*x509.Certificate
}

func (k *AzureTrustedKey) Config() *config.KeyConfig {
	return NewKeyConfig("azureTrusted", "azureTrusted")
}

func (k *AzureTrustedKey) Certificate() []byte {
	if k.crtCache != nil {
		return k.crtCache[0].Raw
	}
	crts, err := k.GetCertificateChain(context.Background())
	if err != nil {
		return nil
	}

	k.crtCache = crts

	return crts[0].Raw
}

func (k *AzureTrustedKey) GetID() []byte {
	if k.crtCache != nil && len(k.crtCache) > 0 {
		return []byte(k.crtCache[0].SerialNumber.String())
	}

	crt, err := k.GetCertificateChain(context.Background())
	if err != nil || len(crt) == 0 {
		return nil
	}

	k.crtCache = crt

	return []byte(crt[0].SerialNumber.String())
}

func (k *AzureTrustedKey) ImportCertificate(cert *x509.Certificate) error {
	return fmt.Errorf("importing certificate not supported for AzureTrustedKey")
}

func (k *AzureTrustedKey) SignContext(ctx context.Context, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	hfunc := strings.ReplaceAll(opts.HashFunc().String(), "-", "")
	if goats.FromHashFunc[hfunc] == "" {
		return nil, fmt.Errorf("unsupported digest algorithm %s", hfunc)
	}

	resp, err := k.SignAndWait(ctx, goats.SignRequest{
		Digest:             digest,
		SignatureAlgorithm: goats.FromHashFunc[hfunc],
	})
	if err != nil {
		return nil, err
	}

	return resp.Signature, nil
}

func NewAzureTrustedKey(region, tenant, client, secret, account, profile string, ctx context.Context, timestamper pkcs9.Timestamper) (*certloader.Certificate, error) {
	azcr, err := azidentity.NewClientSecretCredential(tenant, client, secret, nil)
	if err != nil {
		panic(err)
	}

	crtclient := goats.NewClient(goats.AzureTrustedSigningRegion(region), azcr, account, profile)

	certs, err := crtclient.GetCertificateChain(ctx)
	if err != nil {
		return nil, err
	}

	return &certloader.Certificate{
		Certificates: certs,
		Leaf:         certs[0],
		PrivateKey:   crtclient,
		KeyName:      profile,
		Timestamper:  timestamper,
	}, nil
}
