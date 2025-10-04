package transformers

import (
	"io"

	"github.com/ossign/ossign/pkg/binpatch"
	"github.com/sassoftware/relic/v8/lib/vfs"
)

// type Transformer interface {
// 	// Return a stream that will be uploaded to a remote server. This may be
// 	// called multiple times in case of failover.
// 	GetReader() (stream io.Reader, err error)
// 	// Apply a HTTP response to the named destination file
// 	Apply(dest *vfs.File, mimetype string, result io.Reader) error
// }

type NoFileTransformer struct {
	f *vfs.File
}

func (n NoFileTransformer) GetReader() (io.Reader, error) {
	if n.f == nil {
		return nil, nil // No file to read from
	}
	return n.f, nil
}

func (n NoFileTransformer) Apply(dest *vfs.File, mimetype string, result io.Reader) error {
	if mimetype == "application/x-binary-patch" {
		return ApplyBinPatchStream(n.f, dest, result)
	}

	if n.f == nil {
		return nil // No file to apply the result to
	}
	if _, err := io.Copy(dest, result); err != nil {
		return err
	}

	return nil
}

func ApplyBinPatchStream(src *vfs.File, dest *vfs.File, result io.Reader) error {
	blob, err := io.ReadAll(result)
	if err != nil {
		return err
	}
	patch, err := binpatch.Load(blob)
	if err != nil {
		return err
	}

	return patch.Apply(src, dest)
}

func NewNoFileTransformer(f *vfs.File) NoFileTransformer {
	return NoFileTransformer{f: f}
}
