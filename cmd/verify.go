package main

import (
	"crypto"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/sassoftware/relic/v8/lib/authenticode"
	"github.com/sassoftware/relic/v8/lib/certloader"
	"github.com/sassoftware/relic/v8/lib/pkcs7"
	"github.com/sassoftware/relic/v8/lib/pkcs9"
	"github.com/sassoftware/relic/v8/lib/signappx"
	"github.com/spf13/cobra"
)

// testModeMarker is part of the subject of certificates the OSSign Server
// generates for policies in test mode.
const testModeMarker = "OSSign TEST MODE"

var verifyCmd = &cobra.Command{
	Use:   "verify <file>",
	Short: "Verify the Authenticode signature of a file and show who signed it",
	Long: `Verifies the embedded signature of a PE/COFF, MSI, CAB, APPX/MSIX or PowerShell
file, prints the signer certificate and timestamp, and warns when the file was
signed with an OSSign Server test-mode certificate (exit code 2).

With --detached <file.p7s> the file is any content and the signature is a
detached CMS/PKCS#7 signature over it, as published by OSSign Server next to
review-report.json.

With --cert the signer must match the given PEM certificate (exit code 3 otherwise).
Signature or digest failures exit with code 1.`,
	Args: cobra.ExactArgs(1),
	RunE: runVerify,
}

var (
	verifyExpectedCert string
	verifyDetachedSig  string
)

func init() {
	verifyCmd.Flags().StringVar(&verifyExpectedCert, "cert", "", "PEM certificate the signer must match")
	verifyCmd.Flags().StringVar(&verifyDetachedSig, "detached", "", "detached CMS/PKCS#7 signature file (.p7s) over the given file")
	rootCmd.AddCommand(verifyCmd)
}

// verifyDetached checks a detached CMS signature over content.
func verifyDetached(sigPath, contentPath string) (signerInfo, error) {
	sig, err := os.ReadFile(sigPath)
	if err != nil {
		return signerInfo{}, err
	}
	if len(sig) == 0 {
		return signerInfo{}, fmt.Errorf("%s is empty: the report was published unsigned", sigPath)
	}
	content, err := os.ReadFile(contentPath)
	if err != nil {
		return signerInfo{}, err
	}
	psd, err := pkcs7.Unmarshal(sig)
	if err != nil {
		return signerInfo{}, fmt.Errorf("parsing signature: %w", err)
	}
	v, err := psd.Content.Verify(content, false)
	if err != nil {
		return signerInfo{}, err
	}
	info := signerInfo{Cert: v.Certificate}
	if t, err := v.SignerInfo.SigningTime(); err == nil {
		info.SignedAt = t
	}
	return info, nil
}

type signerInfo struct {
	Cert      *x509.Certificate
	Hash      crypto.Hash
	Timestamp *pkcs9.CounterSignature
	Opus      *authenticode.SpcSpOpusInfo
	SignedAt  time.Time
}

func runVerify(cmd *cobra.Command, args []string) error {
	path := args[0]
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return err
	}

	var signers []signerInfo
	ext := strings.ToLower(filepath.Ext(path))
	if verifyDetachedSig != "" {
		ext = "detached"
	}
	switch ext {
	case "detached":
		s, err := verifyDetached(verifyDetachedSig, path)
		if err != nil {
			return fail(err)
		}
		signers = append(signers, s)
	case ".exe", ".dll", ".sys", ".ocx", ".scr", ".efi", ".cpl", ".drv", ".mun", ".node":
		sigs, err := authenticode.VerifyPE(f, false)
		if err != nil {
			return fail(err)
		}
		for _, s := range sigs {
			signers = append(signers, signerInfo{Cert: s.Certificate, Hash: s.ImageHashFunc, Timestamp: s.CounterSignature, Opus: s.OpusInfo})
		}
	case ".msi":
		s, err := authenticode.VerifyMSI(f, false)
		if err != nil {
			return fail(err)
		}
		signers = append(signers, signerInfo{Cert: s.Certificate, Hash: s.HashFunc, Timestamp: s.CounterSignature, Opus: s.OpusInfo})
	case ".cab":
		s, err := authenticode.VerifyCab(f, false)
		if err != nil {
			return fail(err)
		}
		signers = append(signers, signerInfo{Cert: s.Certificate, Hash: s.HashFunc, Timestamp: s.CounterSignature, Opus: s.OpusInfo})
	case ".appx", ".msix", ".appxbundle", ".msixbundle":
		s, err := signappx.Verify(f, st.Size(), false)
		if err != nil {
			return fail(err)
		}
		signers = append(signers, signerInfo{Cert: s.Signature.Certificate, Hash: s.Hash, Timestamp: s.Signature.CounterSignature, Opus: s.OpusInfo})
	case ".ps1", ".psm1", ".psd1", ".ps1xml":
		style, ok := authenticode.GetSigStyle(path)
		if !ok {
			return fail(fmt.Errorf("unknown PowerShell signature style for %s", path))
		}
		s, err := authenticode.VerifyPowershell(f, style, false)
		if err != nil {
			return fail(err)
		}
		signers = append(signers, signerInfo{Cert: s.Certificate, Hash: s.HashFunc, Timestamp: s.CounterSignature, Opus: s.OpusInfo})
	default:
		return fail(fmt.Errorf("don't know how to verify %s files", ext))
	}
	if len(signers) == 0 {
		return fail(fmt.Errorf("no signature found"))
	}

	var expected *x509.Certificate
	if verifyExpectedCert != "" {
		pemData, err := os.ReadFile(verifyExpectedCert)
		if err != nil {
			return err
		}
		certs, err := certloader.ParseX509Certificates(pemData)
		if err != nil || len(certs) == 0 {
			return fmt.Errorf("--cert: no certificate found in %s", verifyExpectedCert)
		}
		expected = certs[0]
	}

	exit := 0
	for i, s := range signers {
		if len(signers) > 1 {
			fmt.Printf("Signature %d of %d\n", i+1, len(signers))
		}
		fmt.Printf("  Signer:     %s\n", s.Cert.Subject.String())
		fmt.Printf("  Issuer:     %s\n", s.Cert.Issuer.String())
		fmt.Printf("  Serial:     %s\n", s.Cert.SerialNumber.Text(16))
		fmt.Printf("  Valid:      %s to %s\n", s.Cert.NotBefore.UTC().Format(time.RFC3339), s.Cert.NotAfter.UTC().Format(time.RFC3339))
		if s.Hash != 0 {
			fmt.Printf("  Digest:     %s (verified)\n", s.Hash)
		}
		if s.Opus != nil && s.Opus.ProgramName.String() != "" {
			fmt.Printf("  Program:    %s\n", s.Opus.ProgramName.String())
		}
		if s.Timestamp != nil {
			fmt.Printf("  Timestamp:  %s by %s\n", s.Timestamp.SigningTime.UTC().Format(time.RFC3339), s.Timestamp.Certificate.Subject.CommonName)
		} else if !s.SignedAt.IsZero() {
			fmt.Printf("  Signed at:  %s (signer's clock, not a trusted timestamp)\n", s.SignedAt.UTC().Format(time.RFC3339))
		} else {
			fmt.Printf("  Timestamp:  none\n")
		}
		if strings.Contains(s.Cert.Subject.String(), testModeMarker) {
			fmt.Printf("  WARNING:    signed with an OSSign Server TEST MODE certificate; this signature is not trusted\n")
			if exit == 0 {
				exit = 2
			}
		}
		if expected != nil {
			if s.Cert.Equal(expected) {
				fmt.Printf("  Expected:   matches %s\n", verifyExpectedCert)
			} else {
				fmt.Printf("  Expected:   DOES NOT MATCH %s\n", verifyExpectedCert)
				exit = 3
			}
		}
	}
	if exit != 0 {
		os.Exit(exit)
	}
	fmt.Println("Signature OK")
	return nil
}

func fail(err error) error {
	fmt.Fprintf(os.Stderr, "verification failed: %v\n", err)
	os.Exit(1)
	return nil
}
