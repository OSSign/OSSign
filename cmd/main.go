package main

import (
	"context"
	"fmt"
	"log"
	"path/filepath"
	"strings"

	"github.com/ossign/ossign/pkg/vfs"
	"github.com/sassoftware/relic/v8/config"
	"github.com/sassoftware/relic/v8/lib/certloader"
	"github.com/sassoftware/relic/v8/lib/pkcs9/tsclient"
	rvfs "github.com/sassoftware/relic/v8/lib/vfs"
	"github.com/spf13/cobra"
)

func main() {
	if err := rootCmd.Execute(); err != nil {
		log.Fatalf("Error executing command: %v", err)
	}
}

var MapTypeToFunc = map[SignatureType]func(*rvfs.File, *certloader.Certificate, string, *rvfs.File, context.Context) error{
	"powershell":  SignPowershell,
	"pecoff":      SignPecoff,
	"msi":         SignMsi,
	"appx":        SignAppx,
	"appmanifest": SignAppmanifest,
	"dmg":         SignDmg,
	"machos":      SignMachos,
}

func Run(cmd *cobra.Command, args []string) {
	if len(args) == 1 {
		GlobalConfig.InputFile = args[0]
	}

	if signType, err := cmd.Flags().GetString("sign-type"); err == nil && signType != "" {
		GlobalConfig.SignatureType = SignatureType(signType)
	}

	if outFile, err := cmd.Flags().GetString("output"); err == nil && outFile != "" {
		GlobalConfig.OutputFile = outFile
	}

	if GlobalConfig.InputFile == "" {
		log.Fatal("No input file specified")
	}

	if GlobalConfig.OutputFile == "" {
		fileExt := filepath.Ext(GlobalConfig.InputFile)
		GlobalConfig.OutputFile = fmt.Sprintf("%s-signed.%s", strings.TrimSuffix(filepath.Base(GlobalConfig.InputFile), fileExt), fileExt)
	}

	ctx := context.Background()

	timestampConfig := config.TimestampConfig{
		URLs:   []string{GlobalConfig.TimestampUrl},
		MsURLs: []string{GlobalConfig.MsTimestampUrl},
	}

	timestamper, err := tsclient.New(&timestampConfig)
	if err != nil {
		log.Fatalf("Error creating timestamper: %v", err)
	}

	signerCert, err := GlobalConfig.GetSigner(timestamper, ctx)
	if err != nil {
		log.Fatalf("Error getting signer: %v", err)
	}

	file, err := vfs.ReadFromFile(GlobalConfig.InputFile)
	if err != nil {
		log.Fatalf("Error reading input file: %v", err)
	}

	outfileFdesc := rvfs.New([]byte{}, GlobalConfig.OutputFile)

	if GlobalConfig.SignatureType != "" && MapTypeToFunc[GlobalConfig.SignatureType] != nil {
		err = MapTypeToFunc[GlobalConfig.SignatureType](file, signerCert, GlobalConfig.InputFile, outfileFdesc, ctx)
	} else {
		log.Fatalf("No sign type specified or unsupported sign type: %s (auto not implemented yet)", GlobalConfig.SignatureType)
		// err = SignAuto(file, signerCert, GlobalConfig.InputFile, outfileFdesc, ctx)
	}
	if err != nil {
		log.Fatalf("Error signing file: %v", err)
	}

	if err := vfs.WriteToFile(outfileFdesc); err != nil {
		log.Fatalf("Error writing output file: %v", err)
	}

	log.Printf("Successfully signed %s to %s", GlobalConfig.InputFile, GlobalConfig.OutputFile)

	log.Println("Finished signing!")
}
