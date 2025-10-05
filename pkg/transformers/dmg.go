package transformers

import (
	"archive/tar"
	"errors"
	"fmt"
	"io"
	"io/ioutil"

	"github.com/sassoftware/relic/v8/lib/vfs"
)

const (
	udifName = "udifheader.bin"
	dmgName  = "contents.dmg"
)

var fileArgs = []string{"requirements"}

func NewDmgTransformer(f *vfs.File, requirements []byte) (Transformer, error) {
	if _, err := f.Seek(-512, io.SeekEnd); err != nil {
		return nil, err
	}
	udifBytes := make([]byte, 512)
	if _, err := io.ReadFull(f, udifBytes); err != nil {
		return nil, err
	}
	t := &transformer{
		f:     f,
		files: []tarFile{{Name: udifName, Data: udifBytes}},
	}
	t.files = append(t.files, tarFile{Name: "requirements", Data: requirements})

	return t, nil
}

func NewMachosTransformer(f *vfs.File) (Transformer, error) {
	// this transformer packs extra files specified on the cmdline into a tarball
	t := &transformer{f: f}
	return t, nil
}

type transformer struct {
	f     *vfs.File
	files []tarFile
}

type tarFile struct {
	Name string
	Data []byte
}

func (t *transformer) GetReader() (io.Reader, error) {
	r, w := io.Pipe()
	go func() {
		_ = w.CloseWithError(t.send(w))
	}()
	return r, nil
}

func (t *transformer) send(w io.Writer) error {
	tw := tar.NewWriter(w)
	// write extra files
	for _, f := range t.files {
		hdr := &tar.Header{Name: f.Name, Mode: 0644, Size: int64(len(f.Data))}
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if _, err := tw.Write(f.Data); err != nil {
			return err
		}
	}
	// write binary
	size, err := t.f.Seek(0, io.SeekEnd)
	if err != nil {
		return err
	}
	hdr := &tar.Header{Name: dmgName, Mode: 0644, Size: size}
	if err := tw.WriteHeader(hdr); err != nil {
		return err
	}
	if _, err := t.f.Seek(0, 0); err != nil {
		return err
	}
	if _, err := io.Copy(tw, t.f); err != nil {
		return err
	}
	return tw.Close()
}

func (t *transformer) Apply(dest *vfs.File, mimeType string, result io.Reader) error {
	return ApplyBinPatchStream(t.f, dest, result)
}

func DmgExtractFiles(r io.Reader) (args map[string][]byte, exec io.Reader, err error) {
	tr := tar.NewReader(r)
	args = make(map[string][]byte)
files:
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil, nil, errors.New("tar missing file \"exec\"")
		} else if err != nil {
			return nil, nil, err
		}
		if hdr.Name == dmgName {
			return args, tr, nil
		}
		for _, argName := range append(fileArgs, udifName) {
			if argName == hdr.Name {
				blob, err := ioutil.ReadAll(tr)
				if err != nil {
					return nil, nil, err
				}
				args[argName] = blob
				continue files
			}
		}
		return nil, nil, fmt.Errorf("unexpected tar file %q", hdr.Name)
	}
}
