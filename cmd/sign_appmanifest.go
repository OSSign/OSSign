package main

import (
	"context"
	"fmt"

	"github.com/ossign/ossign/pkg/signers"
	"github.com/sassoftware/relic/v8/lib/certloader"
	rvfs "github.com/sassoftware/relic/v8/lib/vfs"
)

func SignAppmanifest(input *rvfs.File, signerCert *certloader.Certificate, filename string, outfile *rvfs.File, ctx context.Context) error {
	signed, err := signers.SignAppmanifest(input, signerCert, filename, ctx)
	if err != nil {
		return fmt.Errorf("Error signing file: %v", err)
	}

	_, err = outfile.Write(signed)
	if err != nil {
		return fmt.Errorf("Error writing signed data to output file: %v", err)
	}

	return nil
}
