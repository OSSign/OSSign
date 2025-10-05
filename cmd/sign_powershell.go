package main

import (
	"bytes"
	"context"
	"fmt"

	"github.com/ossign/ossign/pkg/signers"
	"github.com/ossign/ossign/pkg/transformers"
	"github.com/sassoftware/relic/v8/lib/certloader"
	rvfs "github.com/sassoftware/relic/v8/lib/vfs"
)

func SignPowershell(input *rvfs.File, signerCert *certloader.Certificate, filename string, outfile *rvfs.File, ctx context.Context) error {
	transformer := transformers.NewNoFileTransformer(input)
	transformReader, err := transformer.GetReader()
	if err != nil {
		return fmt.Errorf("Error getting transformer reader: %v", err)
	}

	signed, err := signers.SignPowershell(transformReader, signerCert, filename, ctx)
	if err != nil {
		return fmt.Errorf("Error signing file: %v", err)
	}

	return transformer.Apply(outfile, "application/x-binary-patch", bytes.NewReader(signed))
}
