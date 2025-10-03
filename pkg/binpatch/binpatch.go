//
// Copyright (c) SAS Institute Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

// A means of conveying a series of edits to binary files. Each item in a
// patchset consists of an offset into the old file, the number of bytes to
// remove, and the octet string to replace it with.
package binpatch

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"

	"github.com/sassoftware/relic/v8/lib/vfs"
)

const (
	MimeType = "application/x-binary-patch"

	uint32Max = 0xffffffff
)

type PatchSet struct {
	Patches []PatchHeader
	Blobs   [][]byte
}

type PatchSetHeader struct {
	Version, NumPatches uint32
}

type PatchHeader struct {
	Offset           int64
	OldSize, NewSize uint32
}

// Create a new, empty PatchSet
func New() *PatchSet {
	return new(PatchSet)
}

// Add a new patch region to a PatchSet. The bytes beginning at "offset" and
// running for "oldSize" are removed and replaced with "blob". oldSize may be 0.
func (p *PatchSet) Add(offset, oldSize int64, blob []byte) {
	if len(p.Patches) > 0 {
		i := len(p.Patches) - 1
		last := p.Patches[i]
		lastEnd := last.Offset + int64(last.OldSize)
		lastBlob := p.Blobs[i]
		oldCombo := int64(last.OldSize) + oldSize
		newCombo := int64(len(lastBlob)) + int64(len(blob))
		if offset == lastEnd && oldCombo <= uint32Max && newCombo <= uint32Max {
			// coalesce this patch into the previous one
			p.Patches[i].OldSize = uint32(oldCombo)
			p.Patches[i].NewSize = uint32(newCombo)
			if len(blob) > 0 {
				newBlob := make([]byte, newCombo)
				copy(newBlob, lastBlob)
				copy(newBlob[len(lastBlob):], blob)
				p.Blobs[i] = newBlob
			}
			return
		}
	}
	for oldSize > uint32Max {
		p.Patches = append(p.Patches, PatchHeader{offset, uint32Max, 0})
		p.Blobs = append(p.Blobs, nil)
		offset += uint32Max
		oldSize -= uint32Max
	}
	p.Patches = append(p.Patches, PatchHeader{offset, uint32(oldSize), uint32(len(blob))})
	p.Blobs = append(p.Blobs, blob)
}

// Unmarshal a PatchSet from bytes
func Load(blob []byte) (*PatchSet, error) {
	r := bytes.NewReader(blob)
	var h PatchSetHeader
	if err := binary.Read(r, binary.BigEndian, &h); err != nil {
		return nil, err
	} else if h.Version != 1 {
		return nil, fmt.Errorf("unsupported binpatch version %d", h.Version)
	}
	num := int(h.NumPatches)
	p := &PatchSet{
		Patches: make([]PatchHeader, num),
		Blobs:   make([][]byte, num),
	}
	if err := binary.Read(r, binary.BigEndian, p.Patches); err != nil {
		return nil, err
	}
	for i, hdr := range p.Patches {
		p.Blobs[i] = make([]byte, int(hdr.NewSize))
		if _, err := io.ReadFull(r, p.Blobs[i]); err != nil {
			return nil, err
		}
	}
	return p, nil
}

// Marshal a PatchSet to bytes
func (p *PatchSet) Dump() []byte {
	sort.Sort(sorter{p})
	header := PatchSetHeader{1, uint32(len(p.Patches))}
	size := 8 + 16*len(p.Patches)
	for _, hdr := range p.Patches {
		size += int(hdr.NewSize)
	}
	buf := bytes.NewBuffer(make([]byte, 0, size))
	_ = binary.Write(buf, binary.BigEndian, header)
	_ = binary.Write(buf, binary.BigEndian, p.Patches)
	for _, blob := range p.Blobs {
		_, _ = buf.Write(blob)
	}
	return buf.Bytes()
}

// Apply a PatchSet by taking the input file, transforming it, and writing the
// result to outpath. If outpath is the same name as infile then the file will
// be updated in-place if a direct overwrite is possible. If they are not the
// same file, or the patch requires moving parts of the old file, then the
// output will be written to a temporary file then renamed over the destination
// path.
func (p *PatchSet) Apply(infile *vfs.File, outfile *vfs.File) error {
	size := infile.Size()

	if infile.Size() != outfile.Size() {
		fmt.Println("Input and output file sizes differ, rewriting output file")
		n, err := outfile.Seek(0, 0)
		if err != nil {
			return fmt.Errorf("failed to seek output file: %v", err)
		}
		fmt.Println("Seeking output file to", n, "bytes")

		err = outfile.Truncate(0)
		if err != nil {
			return fmt.Errorf("failed to truncate output file: %v", err)
		}

		n, err = infile.Seek(0, 0)
		if err != nil {
			return fmt.Errorf("failed to seek input file: %v", err)
		}
		fmt.Println("Seeking input file to", n, "bytes")

		if n, err := io.Copy(outfile, infile); err != nil {
			return fmt.Errorf("failed to copy input file to output file: %v", err)
		} else {
			fmt.Println("Copied", n, "bytes from input file to output file")
		}

		n, err = outfile.Seek(0, 0)
		if err != nil {
			return fmt.Errorf("failed to seek output file after copy: %v", err)
		}
		fmt.Println("Seeking output file to", n, "bytes after copy")

		fmt.Println("Copied input file to output file, now applying patches. Sizes after copy:", infile.Size(), outfile.Size())
	}

	for i, patch := range p.Patches {
		if patch.OldSize == patch.NewSize {
			continue
		} else if i != len(p.Patches)-1 {
			fmt.Println("Patch at", patch.Offset, "has old size", patch.OldSize, "and new size", patch.NewSize, "but is not the last patch. Rewriting output file.")
			return p.applyRewrite(infile, outfile)
		}

		oldEnd := patch.Offset + int64(patch.OldSize)
		if oldEnd != size {
			fmt.Println("Last patch at", patch.Offset, "has old size", patch.OldSize, "and new size", patch.NewSize, "but does not match end of input file. Rewriting output file.")
			return p.applyRewrite(infile, outfile)
		}

		size = patch.Offset + int64(patch.NewSize)
	}

	for i, patch := range p.Patches {
		if _, err := outfile.WriteAt(p.Blobs[i], patch.Offset); err != nil {
			return fmt.Errorf("failed to write patch blob at offset %d: %v", patch.Offset, err)
		}
	}

	return outfile.Truncate(size)
}

// Apply a patch by writing the patched result to a new file. This is the
// fallback case whenever an in-place write isn't possible.
func (p *PatchSet) applyRewrite(infile *vfs.File, outfile *vfs.File) error {
	if _, err := infile.Seek(0, 0); err != nil {
		return err
	}

	var pos int64
	for i, patch := range p.Patches {
		blob := p.Blobs[i]
		delta := patch.Offset - pos
		if delta < 0 {
			return errors.New("patches out of order")
		}
		// Copy data before the patch
		if delta > 0 {
			if _, err := io.CopyN(outfile, infile, delta); err != nil {
				return err
			}
			pos += delta
		}
		// Skip the old data on the input file
		delta = int64(patch.OldSize)
		if _, err := infile.Seek(delta, io.SeekCurrent); err != nil {
			return err
		}
		pos += delta
		// Write the new data to the output file
		if _, err := outfile.Write(blob); err != nil {
			return err
		}
	}
	// Copy everything after the last patch
	if _, err := io.Copy(outfile, infile); err != nil {
		return err
	}
	// infile.Close()
	return nil
}

func canOverwrite(ininfo, outinfo os.FileInfo) bool {
	if !outinfo.Mode().IsRegular() {
		return false
	}
	if !os.SameFile(ininfo, outinfo) {
		return false
	}

	return true
}

type sorter struct {
	p *PatchSet
}

func (s sorter) Len() int {
	return len(s.p.Patches)
}

func (s sorter) Less(i, j int) bool {
	return s.p.Patches[i].Offset < s.p.Patches[j].Offset
}

func (s sorter) Swap(i, j int) {
	s.p.Patches[i], s.p.Patches[j] = s.p.Patches[j], s.p.Patches[i]
	s.p.Blobs[i], s.p.Blobs[j] = s.p.Blobs[j], s.p.Blobs[i]
}
