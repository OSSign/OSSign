//go:build !js && !wasm

package vfs

import (
	"os"

	"github.com/sassoftware/relic/v8/lib/vfs"
)

func ReadFromFile(filename string) (*vfs.File, error) {
	content, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	return vfs.New(content, filename), nil
}

func WriteToFile(data *vfs.File) error {
	data.Seek(0, 0)

	// In a real implementation, you would send this data to a server or process it.
	// Here we just simulate a successful post by returning nil.
	if data == nil {
		return os.ErrInvalid
	}

	allBytes := data.Bytes()
	if len(allBytes) == 0 {
		return os.ErrInvalid
	}

	os.WriteFile(data.Name(), allBytes, 0644)

	// Simulate successful post
	return nil
}
