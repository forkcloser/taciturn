package protocol_test

import (
	"bytes"
	"errors"
	"io"
	"testing"

	"github.com/forkcloser/taciturn/internal/protocol"
)

// decoder is one of the package's parsers, as a function over bytes: the
// walk below needs only that a valid input decodes and every other does not.
type decoder struct {
	name   string
	valid  []byte
	decode func([]byte) error
}

func decoders() []decoder {
	return []decoder{
		{"sign request", signReq, func(b []byte) error { _, err := protocol.ParseSignRequest(b); return err }},
		{"session bind", bindBody, func(b []byte) error { _, err := protocol.ParseSessionBind(b); return err }},
		{"userauth", userauth, func(b []byte) error { _, err := protocol.ParseUserauthRequest(b); return err }},
		{"sshsig", sshsig, func(b []byte) error { _, err := protocol.ParseSSHSigRequest(b); return err }},
	}
}

// Every proper prefix of a valid encoding is truncated inside some field,
// and the empty input is the first of them; every extension by one byte is
// a trailing byte. Both are ErrInvalid, for every decoder that consumes its
// input exactly.
func TestEveryPrefixAndExtensionIsInvalid(t *testing.T) {
	t.Parallel()

	for _, d := range decoders() {
		t.Run(d.name, func(t *testing.T) {
			t.Parallel()

			if err := d.decode(d.valid); err != nil {
				t.Fatalf("the valid encoding: %v", err)
			}

			for n := range d.valid {
				if err := d.decode(d.valid[:n]); !errors.Is(err, protocol.ErrInvalid) {
					t.Fatalf("prefix of %d bytes: %v", n, err)
				}
			}

			if err := d.decode(append(append([]byte{}, d.valid...), 0)); !errors.Is(err, protocol.ErrInvalid) {
				t.Fatalf("one trailing byte: %v", err)
			}
		})
	}
}

// A length field that claims more than follows is refused before anything
// is read, at every length field and for every claim from one past the
// truth to the maximum a uint32 holds.
func TestOverlongLengthsAreInvalid(t *testing.T) {
	t.Parallel()

	for _, d := range decoders() {
		t.Run(d.name, func(t *testing.T) {
			t.Parallel()

			for _, off := range lengthFieldOffsets(d.valid) {
				for _, claim := range []uint32{uint32(len(d.valid)), 1 << 16, 1<<31 + 1, 1<<32 - 1} {
					mutated := append([]byte{}, d.valid...)
					mutated[off] = byte(claim >> 24)
					mutated[off+1] = byte(claim >> 16)
					mutated[off+2] = byte(claim >> 8)
					mutated[off+3] = byte(claim)

					if err := d.decode(mutated); !errors.Is(err, protocol.ErrInvalid) {
						t.Fatalf("length at %d set to %d: %v", off, claim, err)
					}
				}
			}
		})
	}
}

// lengthFieldOffsets finds the uint32 length prefixes of a fixture by
// walking it as the fixtures are built: every string the builders wrote.
// It re-derives them from the fixture's own layout rather than from the
// decoder, so a decoder that skipped a field would still be caught.
func lengthFieldOffsets(valid []byte) []int {
	offsets := make([]int, 0)

	for _, d := range decoders() {
		if !bytes.Equal(d.valid, valid) {
			continue
		}

		switch d.name {
		case "sign request":
			offsets = walkStrings(valid, 0, 2)
		case "session bind":
			offsets = walkStrings(valid, 0, 3)
		case "userauth":
			offsets = walkStrings(valid, 0, 1)
			offsets = append(offsets, walkStrings(valid, offsets[0]+4+len(sessID)+1, 3)...)
			last := offsets[len(offsets)-1]
			offsets = append(offsets, walkStrings(valid, last+4+len("publickey")+1, 2)...)
		case "sshsig":
			offsets = walkStrings(valid, len("SSHSIG"), 4)
		}
	}

	return offsets
}

func walkStrings(b []byte, off, count int) []int {
	offsets := make([]int, 0)

	for range count {
		offsets = append(offsets, off)
		n := int(b[off])<<24 | int(b[off+1])<<16 | int(b[off+2])<<8 | int(b[off+3])
		off += 4 + n
	}

	return offsets
}

// A frame is read whole or not at all: every prefix of a framed message
// ends the stream inside the frame, which is the transport's
// io.ErrUnexpectedEOF (or io.EOF for the empty stream), never ErrInvalid.
func TestEveryFramePrefixIsATransportError(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	if _, err := (protocol.Message{Type: protocol.TypeSignRequest, Payload: signReq}).WriteTo(&buf); err != nil {
		t.Fatal(err)
	}

	wire := buf.Bytes()
	for n := range wire {
		_, err := protocol.ReadMessage(bytes.NewReader(wire[:n]))

		want := io.ErrUnexpectedEOF
		if n == 0 {
			want = io.EOF
		}

		if !errors.Is(err, want) {
			t.Fatalf("prefix of %d bytes: %v", n, err)
		}
	}

	if _, err := protocol.ReadMessage(bytes.NewReader(wire)); err != nil {
		t.Fatalf("whole frame: %v", err)
	}
}

// Every message type round-trips through the frame with payloads at the
// edges: empty, one byte, and the largest the frame admits.
func TestFrameRoundTripAtTheEdges(t *testing.T) {
	t.Parallel()

	for _, typ := range []protocol.Type{0, protocol.TypeFailure, protocol.TypeSignRequest, protocol.TypeExtension, 255} {
		for _, size := range []int{0, 1, protocol.MaxMessage - 1} {
			msg := protocol.Message{Type: typ, Payload: bytes.Repeat([]byte{0x7E}, size)}

			var buf bytes.Buffer
			if _, err := msg.WriteTo(&buf); err != nil {
				t.Fatalf("type %d size %d: %v", typ, size, err)
			}

			back, err := protocol.ReadMessage(&buf)
			if err != nil || back.Type != typ || !bytes.Equal(back.Payload, msg.Payload) {
				t.Fatalf("type %d size %d: %+v %v", typ, size, back.Type, err)
			}
		}

		if _, err := (protocol.Message{Type: typ, Payload: make([]byte, protocol.MaxMessage)}).WriteTo(
			io.Discard,
		); !errors.Is(
			err,
			protocol.ErrTooLarge,
		) {
			t.Fatalf("type %d one over: %v", typ, err)
		}
	}
}
