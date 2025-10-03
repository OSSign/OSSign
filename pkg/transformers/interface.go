package transformers

import (
	"io"

	"github.com/sassoftware/relic/v8/lib/vfs"
)

type Transformer interface {
	// Return a stream that will be uploaded to a remote server. This may be
	// called multiple times in case of failover.
	GetReader() (stream io.Reader, err error)
	// Apply a HTTP response to the named destination file
	Apply(dest *vfs.File, mimetype string, result io.Reader) error
}
