package main

import (
	"bytes"
	"context"
	"crypto"
	"fmt"

	"github.com/ossign/ossign/pkg/transformers"
	"github.com/sassoftware/relic/v8/lib/certloader"
	"github.com/sassoftware/relic/v8/lib/fruit/csblob"
	"github.com/sassoftware/relic/v8/lib/fruit/machos"
	rvfs "github.com/sassoftware/relic/v8/lib/vfs"
)

func SignMachos(input *rvfs.File, signerCert *certloader.Certificate, filename string, outfile *rvfs.File, ctx context.Context) error {
	transformer, err := transformers.NewMachosTransformer(input)
	if err != nil {
		return fmt.Errorf("Error creating MSI transformer: %v", err)
	}

	transReader, err := transformer.GetReader()
	if err != nil {
		return fmt.Errorf("Error getting transformer reader: %v", err)
	}

	args, payload, err := transformers.DmgExtractFiles(transReader)
	if err != nil {
		return fmt.Errorf("Error extracting DMG files: %v", err)
	}

	params := &csblob.SignatureParams{
		HashFunc:        crypto.SHA256,
		SigningIdentity: GlobalConfig.GetParamDefault("signingIdentity", "Developer ID Application: Unknown"),
	}

	if v := args["info-plist"]; v != nil {
		params.InfoPlist = v
	}
	if v := args["entitlements"]; v != nil {
		params.Entitlement = v
	}
	if v := args["requirements"]; v != nil {
		params.Requirements = v
	}
	if v := args["resources"]; v != nil {
		params.Resources = v
	}

	patch, _, err := machos.Sign(ctx, payload, signerCert, params)
	if err != nil {
		return err
	}

	return transformer.Apply(outfile, "application/x-binary-patch", bytes.NewReader(patch.Dump()))
}
