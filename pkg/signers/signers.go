package signers

import (
	"context"
	"crypto"
	"fmt"
	"io"
	"time"

	"github.com/sassoftware/relic/v8/lib/appmanifest"
	"github.com/sassoftware/relic/v8/lib/audit"
	"github.com/sassoftware/relic/v8/lib/authenticode"
	"github.com/sassoftware/relic/v8/lib/certloader"
	"github.com/sassoftware/relic/v8/lib/pkcs9"
	"github.com/sassoftware/relic/v8/lib/signappx"
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

	if err != nil {
		return nil, err
	}

	return patch.Dump(), nil
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

func SignAppmanifest(r io.Reader, cert *certloader.Certificate, filename string, ctx context.Context) ([]byte, error) {
	blob, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	signed, err := appmanifest.Sign(blob, cert, crypto.SHA256)

	if cert.Timestamper != nil {
		tsreq := &pkcs9.Request{
			EncryptedDigest: signed.EncryptedDigest,
			Legacy:          false,
			Hash:            crypto.SHA256,
		}

		token, err := cert.Timestamper.Timestamp(ctx, tsreq)
		if err != nil {
			return nil, err
		}
		if err := signed.AddTimestamp(token); err != nil {
			return nil, err
		}
	}

	return signed.Signed, nil
}

func SignAppx(r io.Reader, cert *certloader.Certificate, filename string, ctx context.Context) ([]byte, error) {
	digest, err := signappx.DigestAppxTar(r, crypto.SHA256, false)
	if err != nil {
		return nil, err
	}

	patch, _, _, err := digest.Sign(ctx, cert, &authenticode.OpusParams{
		Description: "This software has been signed by OSSign",
		URL:         "https://ossign.org",
	})
	if err != nil {
		return nil, err
	}

	return patch.Dump(), nil
}
