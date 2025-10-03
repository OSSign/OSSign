package main

import (
	"bytes"
	"context"
	"log"
	"os"

	"github.com/ossign/ossigner/pkg/signers"
	"github.com/ossign/ossigner/pkg/transformers"
	"github.com/ossign/ossigner/pkg/vfs"
	"github.com/sassoftware/relic/v8/config"
	"github.com/sassoftware/relic/v8/lib/pkcs9/tsclient"
	rvfs "github.com/sassoftware/relic/v8/lib/vfs"
)

func main() {
	if len(os.Args) < 2 {
		log.Fatal("Usage: ossigner <config.json>")
	}

	cfg, err := UnmarshalConfig(os.Args[1])
	if err != nil {
		log.Fatalf("Error loading config: %v", err)
	}

	ctx := context.Background()

	timestampConfig := config.TimestampConfig{
		URLs:   []string{cfg.TimestampUrl},
		MsURLs: []string{cfg.MsTimestampUrl},
	}

	timestamper, err := tsclient.New(&timestampConfig)
	if err != nil {
		log.Fatalf("Error creating timestamper: %v", err)
	}

	signerCert, err := cfg.GetSigner(timestamper, ctx)
	if err != nil {
		log.Fatalf("Error getting signer: %v", err)
	}

	file, err := vfs.ReadFromFile(cfg.InputFile)
	if err != nil {
		log.Fatalf("Error reading input file: %v", err)
	}

	outfileFdesc := rvfs.New([]byte{}, cfg.OutputFile)

	switch cfg.SignatureType {
	case "powershell":
		transformer := transformers.NewNoFileTransformer(file)
		transformReader, err := transformer.GetReader()
		if err != nil {
			log.Fatalf("Error getting transformer reader: %v", err)
		}

		signed, err := signers.SignPowershell(transformReader, signerCert, cfg.InputFile, ctx)
		if err != nil {
			log.Fatalf("Error signing file: %v", err)
		}

		if err := transformer.Apply(outfileFdesc, "application/x-binary-patch", bytes.NewReader(signed)); err != nil {
			log.Fatalf("Error applying signed data: %v", err)
		}

		if err := vfs.WriteToFile(outfileFdesc); err != nil {
			log.Fatalf("Error writing output file: %v", err)
		}

		log.Printf("Successfully signed %s to %s", cfg.InputFile, cfg.OutputFile)

	case "pecoff":
		transformer := transformers.NewDefaultTransformer(file)
		transformReader, err := transformer.GetReader()
		if err != nil {
			log.Fatalf("Error getting transformer reader: %v", err)
		}

		signed, err := signers.SignPecoff(transformReader, signerCert, cfg.InputFile, ctx)
		if err != nil {
			log.Fatalf("Error signing file: %v", err)
		}

		if err := transformer.Apply(outfileFdesc, "application/x-binary-patch", bytes.NewReader(signed)); err != nil {
			log.Fatalf("Error applying signed data: %v", err)
		}

		if err := vfs.WriteToFile(outfileFdesc); err != nil {
			log.Fatalf("Error writing output file: %v", err)
		}

		log.Printf("Successfully signed %s to %s", cfg.InputFile, cfg.OutputFile)

	case "msi":
		transformer, err := transformers.NewMsiTransformer(file)
		if err != nil {
			log.Fatalf("Error creating MSI transformer: %v", err)
		}

		transformReader, err := transformer.GetReader()
		if err != nil {
			log.Fatalf("Error getting transformer reader: %v", err)
		}

		signed, err := signers.SignMsi(transformReader, signerCert, cfg.InputFile, ctx)
		if err != nil {
			log.Fatalf("Error signing file: %v", err)
		}

		if err := transformer.Apply(outfileFdesc, "application/x-binary-patch", bytes.NewReader(signed)); err != nil {
			log.Fatalf("Error applying signed data: %v", err)
		}

		if err := vfs.WriteToFile(outfileFdesc); err != nil {
			log.Fatalf("Error writing output file: %v", err)
		}

		log.Printf("Successfully signed %s to %s", cfg.InputFile, cfg.OutputFile)

	default:
		log.Fatalf("Unsupported signature type: %s", cfg.SignatureType)
	}

}
