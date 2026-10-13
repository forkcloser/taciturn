package protocol_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/forkcloser/taciturn/internal/protocol"
)

// Past the bound: every decoder either decodes or reports one of the
// package's sentinels, never panics, and a decoded value re-encodes to the
// bytes it came from where an encoder exists.
func FuzzDecoders(f *testing.F) {
	for _, d := range decoders() {
		f.Add(d.valid)
	}

	f.Add([]byte{})
	f.Add([]byte{0xFF, 0xFF, 0xFF, 0xFF})

	f.Fuzz(func(t *testing.T, data []byte) {
		for _, d := range decoders() {
			if err := d.decode(
				data,
			); err != nil && !errors.Is(err, protocol.ErrInvalid) &&
				!errors.Is(err, protocol.ErrTooLarge) {
				t.Fatalf("%s: %v", d.name, err)
			}
		}

		if ext, err := protocol.ParseExtension(data); err == nil {
			if len(ext.Name)+4+len(ext.Contents) != len(data) {
				t.Fatalf("extension did not consume its input: %+v", ext)
			}
		} else if !errors.Is(err, protocol.ErrInvalid) {
			t.Fatalf("extension: %v", err)
		}
	})
}

func FuzzFrame(f *testing.F) {
	f.Add([]byte{0, 0, 0, 1, 11})
	f.Add([]byte{0, 0, 0, 0})
	f.Add([]byte{0, 1, 0, 1, 0})

	f.Fuzz(func(t *testing.T, data []byte) {
		msg, err := protocol.ReadMessage(bytes.NewReader(data))
		if err != nil {
			return
		}

		var buf bytes.Buffer
		if _, err := msg.WriteTo(&buf); err != nil {
			t.Fatalf("re-encode: %v", err)
		}

		if !bytes.Equal(buf.Bytes(), data[:buf.Len()]) {
			t.Fatalf("re-encoded frame differs: %x vs %x", buf.Bytes(), data[:buf.Len()])
		}
	})
}
