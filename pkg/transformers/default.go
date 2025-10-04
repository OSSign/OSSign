package transformers

import (
	"fmt"
	"io"

	"github.com/ossign/ossign/pkg/binpatch"
	"github.com/sassoftware/relic/v8/lib/vfs"
)

type defaultTransformer struct {
	f *vfs.File
}

func (p defaultTransformer) GetReader() (io.Reader, error) {
	if _, err := p.f.Seek(0, io.SeekStart); err != nil {
		return nil, fmt.Errorf("seeking input file: %w", err)
	}
	return p.f, nil
}

// If the response is a binpatch, apply it. Otherwise overwrite the destination
// file with the response
func (p defaultTransformer) Apply(dest *vfs.File, mimetype string, result io.Reader) error {
	return ApplyBinPatch(p.f, dest, result)

	// if mimetype == "application/x-binary-patch" {
	// 	fmt.Println("Applying binary patch to", dest.Name())
	// }

	// fmt.Println("Overwriting", dest.Name(), "with result")
	// // f, err := atomicfile.WriteAny(dest)
	// // if err != nil {
	// // 	return err
	// // }
	// if _, err := io.Copy(dest, result); err != nil {
	// 	return err
	// }
	// // TODO: Need this?
	// // p.f.Close()
	// // return f.Commit()
	// return nil
}

func ApplyBinPatch(src *vfs.File, dest *vfs.File, result io.Reader) error {
	srcLen := src.Size()
	destLen := dest.Size()

	fmt.Println("Applying binary patch from", src.Name(), "to", dest.Name(), "with sizes:", srcLen, destLen)

	blob, err := io.ReadAll(result)
	if err != nil {
		return err
	}
	patch, err := binpatch.Load(blob)
	if err != nil {
		return err
	}

	for _, f := range patch.Patches {
		fmt.Println("Applying patch at ", f.Offset)
	}

	return patch.Apply(src, dest)
}

func NewDefaultTransformer(f *vfs.File) defaultTransformer {
	return defaultTransformer{f: f}
}
