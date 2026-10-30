package main

import (
	"context"
	"log/slog"
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
		fatal("Error executing command", "error", err)
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

// Map all file endings to their corresponding signing functions
var MapFileEnding = map[string]func(*rvfs.File, *certloader.Certificate, string, *rvfs.File, context.Context) error{
	"ps1":  SignPowershell,
	"psm1": SignPowershell,
	"msi":  SignMsi,
	"msp":  SignMsi,
	"mst":  SignMsi,
	"appx": SignAppx,
	"msix": SignAppx,
	"dmg":  SignDmg,
	"pkg":  SignDmg,
	"exe":  SignPecoff,
	"dll":  SignPecoff,
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
		fatal("No input file specified")
	}

	// Default is signing in place, which is what the ossign action, the npm
	// package and build-tool hooks expect. Use -o to write a copy instead.
	if GlobalConfig.OutputFile == "" {
		GlobalConfig.OutputFile = GlobalConfig.InputFile
	}

	slog.Debug("Signing configuration", "input", GlobalConfig.InputFile, "output", GlobalConfig.OutputFile,
		"signType", GlobalConfig.SignatureType, "tokenType", GlobalConfig.TokenType,
		"timestampUrl", GlobalConfig.TimestampUrl, "msTimestampUrl", GlobalConfig.MsTimestampUrl)

	ctx := context.Background()

	timestampConfig := config.TimestampConfig{
		URLs:   []string{GlobalConfig.TimestampUrl},
		MsURLs: []string{GlobalConfig.MsTimestampUrl},
	}

	timestamper, err := tsclient.New(&timestampConfig)
	if err != nil {
		fatal("Error creating timestamper", "error", err)
	}

	signerCert, err := GlobalConfig.GetSigner(timestamper, ctx)
	if err != nil {
		fatal("Error getting signer", "error", err)
	}

	file, err := vfs.ReadFromFile(GlobalConfig.InputFile)
	if err != nil {
		fatal("Error reading input file", "path", GlobalConfig.InputFile, "error", err)
	}
	slog.Debug("Read input file", "path", GlobalConfig.InputFile, "size", file.Size())

	outfileFdesc := rvfs.New([]byte{}, GlobalConfig.OutputFile)

	if GlobalConfig.SignatureType != "" && MapTypeToFunc[GlobalConfig.SignatureType] != nil {
		err = MapTypeToFunc[GlobalConfig.SignatureType](file, signerCert, GlobalConfig.InputFile, outfileFdesc, ctx)
	} else {
		// Fetch the file ending and try to determine the filetype
		ext := strings.ToLower(filepath.Ext(GlobalConfig.InputFile))
		if MapFileEnding[ext] == nil {
			// Default to pecoff
			ext = "exe"
		}

		err = MapFileEnding[ext](file, signerCert, GlobalConfig.InputFile, outfileFdesc, ctx)
	}
	if err != nil {
		fatal("Error signing file", "error", err)
	}

	if err := vfs.WriteToFile(outfileFdesc); err != nil {
		fatal("Error writing output file", "path", GlobalConfig.OutputFile, "error", err)
	}

	slog.Info("Successfully signed file", "input", GlobalConfig.InputFile, "output", GlobalConfig.OutputFile)
}
