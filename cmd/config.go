package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/ossign/ossign/pkg/azure"
	"github.com/sassoftware/relic/v8/lib/certloader"
	"github.com/sassoftware/relic/v8/lib/pkcs9"
)

type TokenType string
type SignatureType string

const (
	TokenTypeAzure       TokenType = "azure"
	TokenTypeCertificate TokenType = "certificate"

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

	AzureConfig AzureConfig `json:"azure,omitempty" yaml:"azure,omitempty" mapstructure:"azure"`
	CertConfig  CertConfig  `json:"certificate,omitempty" yaml:"certificate,omitempty" mapstructure:"certificate"`

	TimestampUrl   string `json:"timestampUrl,omitempty" yaml:"timestampUrl,omitempty" mapstructure:"timestampUrl"`
	MsTimestampUrl string `json:"msTimestampUrl,omitempty" yaml:"msTimestampUrl,omitempty" mapstructure:"msTimestampUrl"`

	InputFile  string `json:"inputFile" yaml:"inputFile" mapstructure:"inputFile"`
	OutputFile string `json:"outputFile" yaml:"outputFile" mapstructure:"outputFile"`
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
	if c.InputFile == "" || c.TokenType == "" || (c.AzureConfig.ClientSecret == "" && c.CertConfig.PrivateKey == "") {
		return fmt.Errorf("missing required configuration")
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
			log.Fatalf("Error creating Azure key: %v", err)
		}

		signerCert = &certloader.Certificate{
			Leaf:         azconfig.Fcert[0],
			Certificates: azconfig.Fcert,
			PrivateKey:   azconfig,
			Timestamper:  timestamper,
		}

		return signerCert, nil
	}

	cert, err := certloader.ParseX509Certificates([]byte(c.CertConfig.Certificate))
	if err != nil {
		log.Fatalf("Error parsing certificate: %v", err)
	}
	if len(cert) == 0 {
		log.Fatalf("No certificates found")
	}

	key, err := certloader.ParseAnyPrivateKey([]byte(c.CertConfig.PrivateKey), c.CertConfig)
	if err != nil {
		log.Fatalf("Error parsing private key: %v", err)
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

type CertConfig struct {
	Certificate string `json:"certificate" yaml:"certificate" mapstructure:"certificate"`
	PrivateKey  string `json:"privateKey" yaml:"privateKey" mapstructure:"privateKey"`
	Passphrase  string `json:"passphrase,omitempty" yaml:"passphrase,omitempty" mapstructure:"passphrase"`
}

func (c CertConfig) GetPasswd(prompt string) (string, error) {
	return c.Passphrase, nil
}
