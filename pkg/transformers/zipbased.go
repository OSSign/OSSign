package transformers

import (
	"archive/tar"
	"errors"
	"fmt"
	"io"
	"io/ioutil"

	"github.com/sassoftware/relic/v8/lib/vfs"
	"github.com/sassoftware/relic/v8/lib/zipslicer"
)

const (
	TarMemberCD  = "zipdir.bin"
	TarMemberZip = "contents.zip"
)

type ZipTransformer struct {
	f *vfs.File
}

func NewZipTransformer(f *vfs.File) (Transformer, error) {
	return &ZipTransformer{f}, nil
}

// Make a tar archive with two members:
// - the central directory of the zip file
// - the complete zip file
// This lets us process the zip in one pass, which normally isn't possible with
// the directory at the end.
func ZipToTar(r *vfs.File, w io.Writer) error {
	size, err := r.Seek(0, io.SeekEnd)
	if err != nil {
		return err
	}
	dirLoc, err := zipslicer.FindDirectory(r, size)
	if err != nil {
		return err
	}
	tw := tar.NewWriter(w)
	if _, err := r.Seek(dirLoc, 0); err != nil {
		return err
	}
	if err := tarAddStream(tw, r, TarMemberCD, size-dirLoc); err != nil {
		return err
	}
	if _, err := r.Seek(0, 0); err != nil {
		return err
	}
	if err := tarAddStream(tw, r, TarMemberZip, size); err != nil {
		return err
	}
	return tw.Close()
}

// Wrap the zip in a tarball with the central directory first so that it can be
// processed as a stream
func (t *ZipTransformer) GetReader() (io.Reader, error) {
	r, w := io.Pipe()
	go func() {
		_ = w.CloseWithError(ZipToTar(t.f, w))
	}()
	return r, nil
}

func (t *ZipTransformer) Apply(dest *vfs.File, mimeType string, result io.Reader) error {
	return ApplyBinPatchStream(t.f, dest, result)
}

func tarAddStream(tw *tar.Writer, r io.Reader, name string, size int64) error {
	hdr := &tar.Header{Name: name, Mode: 0644, Size: size}
	if err := tw.WriteHeader(hdr); err != nil {
		return err
	}
	if _, err := io.CopyN(tw, r, size); err != nil {
		return err
	}
	return nil
}

// Read a tar stream produced by ZipToTar and return the zip directory. Files
// must be read from the zip in order or an error will be raised.
func ReadZipTar(r io.Reader) (*zipslicer.Directory, error) {
	tr := tar.NewReader(r)
	hdr, err := tr.Next()
	if err != nil {
		return nil, fmt.Errorf("error reading tar: %w", err)
	} else if hdr.Name != TarMemberCD {
		return nil, errors.New("invalid tarzip")
	}
	zipdir, err := ioutil.ReadAll(tr)
	if err != nil {
		return nil, fmt.Errorf("error reading tar: %w", err)
	}
	hdr, err = tr.Next()
	if err != nil {
		return nil, err
	} else if hdr.Name != TarMemberZip {
		return nil, errors.New("invalid tarzip")
	}
	zr := &zipTarReader{tr: tr}
	return zipslicer.ReadStream(zr, hdr.Size, zipdir)
}

type zipTarReader struct {
	tr *tar.Reader
}

func (z *zipTarReader) Read(d []byte) (int, error) {
	if z.tr == nil {
		return 0, io.EOF
	}
	n, err := z.tr.Read(d)
	if err == io.EOF {
		_, err2 := z.tr.Next()
		if err2 == nil {
			err = errors.New("invalid tarzip")
		} else if err2 != io.EOF {
			err = err2
		}
		z.tr = nil
	}
	return n, err
}
