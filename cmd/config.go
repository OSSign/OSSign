package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/ossign/ossign/pkg/azure"
	"github.com/ossign/ossign/pkg/ossignserver"
	"github.com/sassoftware/relic/v8/lib/certloader"
	"github.com/sassoftware/relic/v8/lib/pkcs9"
)

type TokenType string
type SignatureType string

const (
	TokenTypeAzure        TokenType = "azure"
	TokenTypeAzureTrusted TokenType = "azureTrusted"
	TokenTypeCertificate  TokenType = "certificate"
	TokenTypeOSSignServer TokenType = "ossignServer"

	AutoSignature         SignatureType = "auto"
	PowershellSignature   SignatureType = "powershell"
	PecoffSignature       SignatureType = "pecoff"
	AuthenticodeSignature SignatureType = "authenticode"
)

// func (st SignatureType) GetTransformer(file vfs.File) (signers.Transformer, error) {
// 	return transformers.NewNoFileTransformer(file), nil

// 	// switch st {
// 	// case AutoSignature:
// 	// case PowershellSignature:
// 	// 	return transformers.NewNoFileTransformer(file).GetReader()
// 	// case PecoffSignature:
// 	// 	return transformers.NewPEFileTransformer(file).GetReader()
// 	// case AuthenticodeSignature:
// 	// 	return transformers.NewAuthenticodeFileTransformer(file).GetReader()
// 	// default:
// 	// 	return nil, fmt.Errorf("unknown signature type: %s", st)
// 	// }
// }

type SigningConfig struct {
	TokenType     TokenType     `json:"tokenType" yaml:"tokenType" mapstructure:"tokenType"`
	SignatureType SignatureType `json:"signatureType" yaml:"signatureType" mapstructure:"signatureType"`

	AzureConfig        AzureConfig        `json:"azure,omitempty" yaml:"azure,omitempty" mapstructure:"azure"`
	AzureTrustedConfig AzureTrustedConfig `json:"azureTrusted,omitempty" yaml:"azureTrusted,omitempty" mapstructure:"azureTrusted"`

	CertConfig CertConfig `json:"certificate,omitempty" yaml:"certificate,omitempty" mapstructure:"certificate"`

	OSSignServerConfig OSSignServerConfig `json:"ossignServer,omitempty" yaml:"ossignServer,omitempty" mapstructure:"ossignServer"`

	TimestampUrl   string `json:"timestampUrl,omitempty" yaml:"timestampUrl,omitempty" mapstructure:"timestampUrl"`
	MsTimestampUrl string `json:"msTimestampUrl,omitempty" yaml:"msTimestampUrl,omitempty" mapstructure:"msTimestampUrl"`

	InputFile  string `json:"inputFile" yaml:"inputFile" mapstructure:"inputFile"`
	OutputFile string `json:"outputFile" yaml:"outputFile" mapstructure:"outputFile"`

	Params map[string]string `json:"params,omitempty" yaml:"params,omitempty" mapstructure:"params"`
}

func (c *SigningConfig) GetParamDefault(key, def string) string {
	if val, ok := c.Params[key]; ok {
		return val
	}
	return def
}

func UnmarshalConfig(path string) (*SigningConfig, error) {
	fileContent, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("error reading config file: %w", err)
	}

	var config SigningConfig
	err = json.Unmarshal(fileContent, &config)
	if err != nil {
		return nil, fmt.Errorf("error parsing config file: %w", err)
	}

	return &config, config.Validate()
}

func (c *SigningConfig) Validate() error {
	if c.InputFile == "" || c.TokenType == "" {
		return fmt.Errorf("missing required configuration")
	}

	switch c.TokenType {
	case TokenTypeOSSignServer:
		if c.OSSignServerConfig.Url == "" || c.OSSignServerConfig.Key == "" {
			return fmt.Errorf("ossignServer.url and ossignServer.key are required")
		}
	default:
		if c.AzureConfig.ClientSecret == "" && c.AzureTrustedConfig.ClientSecret == "" && c.CertConfig.PrivateKey == "" {
			return fmt.Errorf("missing required configuration")
		}
	}

	if c.SignatureType == "" {
		c.SignatureType = AutoSignature
	}

	if c.TimestampUrl == "" {
		c.TimestampUrl = "http://timestamp.globalsign.com/tsa/advanced"
	}

	if c.MsTimestampUrl == "" {
		c.MsTimestampUrl = "http://timestamp.microsoft.com/tsa"
	}

	return nil
}

func (c *SigningConfig) GetSigner(timestamper pkcs9.Timestamper, ctx context.Context) (signerCert *certloader.Certificate, err error) {
	if c.TokenType == TokenTypeAzure {
		azconfig, err := azure.NewAzureKey(c.AzureConfig.VaultUrl, c.AzureConfig.TenantId, c.AzureConfig.ClientId, c.AzureConfig.ClientSecret, c.AzureConfig.CertificateName, c.AzureConfig.CertificateVersion, ctx)
		if err != nil {
			fatal("Error creating Azure key", "error", err)
		}

		signerCert = &certloader.Certificate{
			Leaf:         azconfig.Fcert[0],
			Certificates: azconfig.Fcert,
			PrivateKey:   azconfig,
			Timestamper:  timestamper,
		}

		return signerCert, nil
	}

	if c.TokenType == TokenTypeOSSignServer {
		return ossignserver.NewKey(ctx, ossignserver.Options{
			URL:        c.OSSignServerConfig.Url,
			Key:        c.OSSignServerConfig.Key,
			Audience:   c.OSSignServerConfig.Audience,
			Provider:   c.OSSignServerConfig.Provider,
			IDToken:    c.OSSignServerConfig.IdToken,
			IDTokenEnv: c.OSSignServerConfig.IdTokenEnv,
			Metadata:   c.OSSignServerConfig.Metadata,
		}, timestamper)
	}

	if c.TokenType == TokenTypeAzureTrusted {
		return azure.NewAzureTrustedKey(c.AzureTrustedConfig.Region, c.AzureTrustedConfig.TenantId, c.AzureTrustedConfig.ClientId, c.AzureTrustedConfig.ClientSecret, c.AzureTrustedConfig.Account, c.AzureTrustedConfig.Profile, ctx, timestamper)
	}

	cert, err := certloader.ParseX509Certificates([]byte(c.CertConfig.Certificate))
	if err != nil {
		fatal("Error parsing certificate", "error", err)
	}
	if len(cert) == 0 {
		fatal("No certificates found")
	}

	key, err := certloader.ParseAnyPrivateKey([]byte(c.CertConfig.PrivateKey), c.CertConfig)
	if err != nil {
		fatal("Error parsing private key", "error", err)
	}

	signerCert = &certloader.Certificate{
		Leaf:         cert[0],
		Certificates: cert,
		PrivateKey:   key,
		Timestamper:  timestamper,
	}

	return signerCert, nil
}

type AzureConfig struct {
	VaultUrl           string `json:"vaultUrl" yaml:"vaultUrl" mapstructure:"vaultUrl"`
	TenantId           string `json:"tenantId" yaml:"tenantId" mapstructure:"tenantId"`
	ClientId           string `json:"clientId" yaml:"clientId" mapstructure:"clientId"`
	ClientSecret       string `json:"clientSecret" yaml:"clientSecret" mapstructure:"clientSecret"`
	CertificateName    string `json:"certificateName" yaml:"certificateName" mapstructure:"certificateName"`
	CertificateVersion string `json:"certificateVersion,omitempty" yaml:"certificateVersion,omitempty" mapstructure:"certificateVersion"`
}

type AzureTrustedConfig struct {
	Region       string `json:"region" yaml:"region" mapstructure:"region"`
	TenantId     string `json:"tenantId" yaml:"tenantId" mapstructure:"tenantId"`
	ClientId     string `json:"clientId" yaml:"clientId" mapstructure:"clientId"`
	ClientSecret string `json:"clientSecret" yaml:"clientSecret" mapstructure:"clientSecret"`
	Account      string `json:"account" yaml:"account" mapstructure:"account"`
	Profile      string `json:"profile" yaml:"profile" mapstructure:"profile"`
}

// OSSignServerConfig configures signing through an OSSign Server.
//
// No secrets are needed: the CLI obtains an OIDC token from the CI provider
// (e.g. GitHub Actions) and the server decides, based on the token's claims,
// whether this repository/branch/environment may use the requested key.
type OSSignServerConfig struct {
	// Base URL of the OSSign Server, e.g. https://sign.example.com
	Url string `json:"url" yaml:"url" mapstructure:"url"`
	// Name of the signing key (as configured on the server)
	Key string `json:"key" yaml:"key" mapstructure:"key"`
	// Audience to request in the OIDC token. Defaults to the server URL.
	Audience string `json:"audience,omitempty" yaml:"audience,omitempty" mapstructure:"audience"`
	// How to obtain the OIDC token: auto (default), github, gitlab, env or static
	Provider string `json:"provider,omitempty" yaml:"provider,omitempty" mapstructure:"provider"`
	// A pre-obtained OIDC token (provider: static)
	IdToken string `json:"idToken,omitempty" yaml:"idToken,omitempty" mapstructure:"idToken"`
	// Name of an environment variable holding the OIDC token (provider: env / gitlab)
	IdTokenEnv string `json:"idTokenEnv,omitempty" yaml:"idTokenEnv,omitempty" mapstructure:"idTokenEnv"`
	// Free-form metadata sent with each signing request for server side auditing
	Metadata map[string]string `json:"metadata,omitempty" yaml:"metadata,omitempty" mapstructure:"metadata"`
}

type CertConfig struct {
	Certificate string `json:"certificate" yaml:"certificate" mapstructure:"certificate"`
	PrivateKey  string `json:"privateKey" yaml:"privateKey" mapstructure:"privateKey"`
	Passphrase  string `json:"passphrase,omitempty" yaml:"passphrase,omitempty" mapstructure:"passphrase"`
}

func (c CertConfig) GetPasswd(prompt string) (string, error) {
	return c.Passphrase, nil
}
