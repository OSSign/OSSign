package transformers

import (
	"crypto"
	"io"

	"github.com/ossign/ossign/pkg/authenticode"
	"github.com/ossign/ossign/pkg/comdoc"
	"github.com/sassoftware/relic/v8/lib/vfs"
)

type MsiTransformer struct {
	f     *vfs.File
	cdf   *comdoc.ComDoc
	exsig []byte
}

func NewMsiTransformer(f *vfs.File) (*MsiTransformer, error) {
	cdf, err := comdoc.ReadFile(f)
	if err != nil {
		return nil, err
	}
	return &MsiTransformer{f: f, cdf: cdf}, nil
}

func transform(f *vfs.File) (Transformer, error) {
	cdf, err := comdoc.ReadFile(f)
	if err != nil {
		return nil, err
	}
	var exsig []byte
	exsig, err = authenticode.PrehashMSI(cdf, crypto.SHA256)
	if err != nil {
		return nil, err
	}
	return &MsiTransformer{f, cdf, exsig}, nil
}

// transform the MSI to a tar stream for upload
func (t *MsiTransformer) GetReader() (io.Reader, error) {
	r, w := io.Pipe()
	go func() {
		_ = w.CloseWithError(authenticode.MsiToTar(t.cdf, w))
	}()
	return r, nil
}

// apply a signed PKCS#7 blob to an already-open MSI document
func (t *MsiTransformer) Apply(dest *vfs.File, mimeType string, result io.Reader) error {
	t.cdf.Close()
	blob, err := io.ReadAll(result)
	if err != nil {
		return err
	}
	// copy src to dest if needed, otherwise open in-place
	// f, err := atomicfile.WriteInPlace(t.f, dest)
	// if err != nil {
	// 	return err
	// }
	// defer f.Close()

	if _, err := t.f.Seek(0, 0); err != nil {
		return err
	}
	if _, err := io.Copy(dest, t.f); err != nil {
		return err
	}
	if _, err := dest.Seek(0, 0); err != nil {
		return err
	}

	cdf, err := comdoc.WriteFile(dest)
	if err != nil {
		return err
	}
	if err := authenticode.InsertMSISignature(cdf, blob, t.exsig); err != nil {
		return err
	}
	if err := cdf.Close(); err != nil {
		return err
	}
	return nil
}
