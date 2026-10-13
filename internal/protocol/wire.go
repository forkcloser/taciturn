package protocol

import (
	"encoding/binary"
	"fmt"
	"math/big"
)

const (
	uint32Size = 4
	byteSize   = 1
)

// reader decodes the SSH wire types of RFC 4251 section 5 from a buffer,
// in order, and refuses to read past its end.
type reader struct {
	buf []byte
	off int
}

func newReader(buf []byte) *reader {
	return &reader{buf: buf}
}

func (r *reader) remaining() int {
	return len(r.buf) - r.off
}

// done is the last call on a reader: a field left over is ErrInvalid.
func (r *reader) done() error {
	if r.remaining() != 0 {
		return fmt.Errorf("%d trailing bytes: %w", r.remaining(), ErrInvalid)
	}

	return nil
}

func (r *reader) take(n int) ([]byte, error) {
	if n < 0 || n > r.remaining() {
		return nil, fmt.Errorf("field of %d bytes with %d left: %w", n, r.remaining(), ErrInvalid)
	}

	out := r.buf[r.off : r.off+n]
	r.off += n

	return out, nil
}

func (r *reader) byte() (byte, error) {
	b, err := r.take(byteSize)
	if err != nil {
		return 0, err
	}

	return b[0], nil
}

func (r *reader) bool() (bool, error) {
	b, err := r.byte()
	if err != nil {
		return false, err
	}

	return b != 0, nil
}

func (r *reader) uint32() (uint32, error) {
	b, err := r.take(uint32Size)
	if err != nil {
		return 0, err
	}

	return binary.BigEndian.Uint32(b), nil
}

// bytes reads an RFC 4251 "string": a uint32 length and that many bytes.
// The slice aliases the buffer; a caller that keeps it copies it.
func (r *reader) bytes() ([]byte, error) {
	length, err := r.uint32()
	if err != nil {
		return nil, err
	}

	if int64(length) > int64(r.remaining()) {
		return nil, fmt.Errorf("string of %d bytes with %d left: %w", length, r.remaining(), ErrInvalid)
	}

	return r.take(int(length))
}

func (r *reader) string() (string, error) {
	b, err := r.bytes()
	if err != nil {
		return "", err
	}

	return string(b), nil
}

// builder encodes the same wire types, appending to a buffer.
type builder struct {
	buf []byte
}

func (b *builder) putUint32(value uint32) {
	b.buf = binary.BigEndian.AppendUint32(b.buf, value)
}

func (b *builder) putBytes(value []byte) {
	b.putUint32(uint32(len(value))) // #nosec G115 -- a message is bounded by MaxMessage, far below 2^32
	b.buf = append(b.buf, value...)
}

func (b *builder) putString(value string) {
	b.putBytes([]byte(value))
}

// putMPInt encodes a non-negative integer as an RFC 4251 "mpint": big-endian
// two's complement, so a leading zero byte precedes a value whose high bit
// is set, and zero is the empty string.
func (b *builder) putMPInt(value *big.Int) {
	if value.Sign() == 0 {
		b.putUint32(0)

		return
	}

	raw := value.Bytes()
	if raw[0]&0x80 != 0 {
		raw = append([]byte{0}, raw...)
	}

	b.putBytes(raw)
}
