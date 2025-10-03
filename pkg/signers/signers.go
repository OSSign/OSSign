package signers

import (
	"context"
	"crypto"
	"fmt"
	"io"
	"time"

	"github.com/sassoftware/relic/v8/lib/audit"
	"github.com/sassoftware/relic/v8/lib/authenticode"
	"github.com/sassoftware/relic/v8/lib/certloader"
	"github.com/sassoftware/relic/v8/signers"
	"github.com/spf13/pflag"
)

func SignPowershell(r io.Reader, cert *certloader.Certificate, filename string, ctx context.Context) ([]byte, error) {
	common := pflag.NewFlagSet("common", pflag.ExitOnError)
	common.Bool("no-timestamp", false, "Do not attach a trusted timestamp even if the selected key configures one")

	signopts := signers.SignOpts{
		Hash: crypto.SHA256,
		Flags: &signers.FlagValues{
			Defs:   common,
			Values: map[string]string{},
		},
		Audit: &audit.Info{
			StartTime:  time.Now(),
			Attributes: map[string]interface{}{},
		},
	}

	sigStyle, ok := authenticode.GetSigStyle(filename)
	if !ok {
		return nil, fmt.Errorf("unknown signature style %s", filename)
	}

	digest, err := authenticode.DigestPowershell(r, sigStyle, signopts.Hash)
	if err != nil {
		return nil, err
	}

	patch, ts, err := digest.Sign(ctx, cert, &authenticode.OpusParams{
		Description: "This software has been signed by OSSign",
		URL:         "https://ossign.org",
	})
	if err != nil {
		return nil, err
	}

	signopts.Audit.SetCounterSignature(ts.CounterSignature)
	return signopts.SetBinPatch(patch)

	// style, ok := authenticode.GetSigStyle(filename)
	// if !ok {
	// 	return nil, fmt.Errorf("unknown signature style %s", filename)
	// }

	// digest, err := authenticode.DigestPowershell(r, style, crypto.SHA256)
	// if err != nil {
	// 	return nil, err
	// }

	// so := &authenticode.OpusParams{
	// 	Description: "This software has been signed by OSSign",
	// 	URL:         "https://ossign.org",
	// }

	// patch, _, err := digest.Sign(ctx, cert, so)
	// if err != nil {
	// 	return nil, err
	// }

	// return patch.Dump(), err
}

func SignPecoff(r io.Reader, cert *certloader.Certificate, filename string, ctx context.Context) ([]byte, error) {
	digest, err := authenticode.DigestPE(r, crypto.SHA256, true)
	if err != nil {
		return nil, err
	}
	patch, _, err := digest.Sign(ctx, cert, &authenticode.OpusParams{
		Description: "This software has been signed by OSSign",
		URL:         "https://ossign.org",
	})

	return patch.Dump(), err
}

func SignMsi(r io.Reader, cert *certloader.Certificate, filename string, ctx context.Context) ([]byte, error) {
	sum, err := authenticode.DigestMsiTar(r, crypto.SHA256, false)
	if err != nil {
		return nil, err
	}

	ts, err := authenticode.SignMSIImprint(ctx, sum, crypto.SHA256, cert, &authenticode.OpusParams{
		Description: "This software has been signed by OSSign",
		URL:         "https://ossign.org",
	})
	if err != nil {
		return nil, err
	}

	return ts.Raw, nil
}
