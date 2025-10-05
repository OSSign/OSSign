package main

import (
	"bytes"
	"context"
	"crypto"
	"fmt"

	"github.com/ossign/ossign/pkg/transformers"
	"github.com/sassoftware/relic/v8/lib/certloader"
	"github.com/sassoftware/relic/v8/lib/fruit/dmg"
	rvfs "github.com/sassoftware/relic/v8/lib/vfs"
)

const (
	udifName = "udifheader.bin"
	dmgName  = "contents.dmg"
)

func SignDmg(input *rvfs.File, signerCert *certloader.Certificate, filename string, outfile *rvfs.File, ctx context.Context) error {
	args, payload, err := transformers.DmgExtractFiles(input)
	if err != nil {
		return fmt.Errorf("Error extracting DMG files: %v", err)
	}

	requirements, ok := args["requirements"]
	if !ok {
		if reqs := GlobalConfig.GetParamDefault("requirements", ""); reqs != "" {
			requirements = []byte(reqs)
		} else {
			return fmt.Errorf("No requirements file found in DMG")
		}
	}

	transformer, err := transformers.NewDmgTransformer(input, requirements)
	if err != nil {
		return fmt.Errorf("Error creating MSI transformer: %v", err)
	}

	params := &dmg.SignatureParams{
		HashFunc:        crypto.SHA256,
		SigningIdentity: GlobalConfig.GetParamDefault("signingIdentity", "Developer ID Application: Unknown"),
	}

	udifBytes := args[udifName]
	patch, _, err := dmg.Sign(ctx, udifBytes, payload, signerCert, params)
	if err != nil {
		return err
	}

	return transformer.Apply(outfile, "application/x-binary-patch", bytes.NewReader(patch.Dump()))
}
