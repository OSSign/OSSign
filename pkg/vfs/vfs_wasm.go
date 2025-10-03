//go:build js || wasm || (js && wasm)

package vfs

import (
	"fmt"
	"io"
	"net/http"

	"github.com/sassoftware/relic/v8/lib/vfs"
)

func ReadFromFile(filename string) (*vfs.File, error) {
	resp, err := http.Get("http://localhost:51817/" + filename)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get file: %s", resp.Status)
	}

	btes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %v", err)
	}

	if err := resp.Body.Close(); err != nil {
		return nil, fmt.Errorf("failed to close response body: %v", err)
	}

	return vfs.New(btes, filename), nil
}

func WriteToFile(data *vfs.File) error {
	data.Seek(0, 0)

	resp, err := http.Post("http://localhost:51817/"+data.Name(), "application/octet-stream", data)
	if err != nil {
		return fmt.Errorf("failed to post file: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to post file: %s", resp.Status)
	}

	if err := resp.Body.Close(); err != nil {
		return fmt.Errorf("failed to close response body: %v", err)
	}

	return nil
}
