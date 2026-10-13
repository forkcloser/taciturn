package protocol_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/forkcloser/taciturn/internal/protocol"
)

// A public key blob round-trips through the encoder and the decoder, and
// the decoder is held to the same bound as the other decoders: every
// prefix, every extension and every overlong length is ErrInvalid, as are
// another algorithm, another curve and a malformed point.
func TestECDSAP256PublicKeyPointRoundTrip(t *testing.T) {
	t.Parallel()

	point := append([]byte{4}, bytes.Repeat([]byte{0x33}, 64)...)

	blob, err := protocol.ECDSAP256PublicKey(point)
	if err != nil {
		t.Fatal(err)
	}

	back, err := protocol.ECDSAP256PublicKeyPoint(blob)
	if err != nil || !bytes.Equal(back, point) {
		t.Fatalf("round trip: %x %v", back, err)
	}

	for n := range blob {
		if _, err = protocol.ECDSAP256PublicKeyPoint(blob[:n]); !errors.Is(err, protocol.ErrInvalid) {
			t.Fatalf("prefix of %d bytes: %v", n, err)
		}
	}

	if _, err = protocol.ECDSAP256PublicKeyPoint(
		append(append([]byte{}, blob...), 0),
	); !errors.Is(
		err,
		protocol.ErrInvalid,
	) {
		t.Fatalf("trailing byte: %v", err)
	}

	for _, off := range walkStrings(blob, 0, 3) {
		mutated := append([]byte{}, blob...)
		mutated[off], mutated[off+1], mutated[off+2], mutated[off+3] = 0xFF, 0xFF, 0xFF, 0xFF

		if _, err = protocol.ECDSAP256PublicKeyPoint(mutated); !errors.Is(err, protocol.ErrInvalid) {
			t.Fatalf("length at %d overlong: %v", off, err)
		}
	}

	wrong := map[string][]byte{
		"ed25519":     cat(str([]byte("ssh-ed25519")), str([]byte("nistp256")), str(point)),
		"other curve": cat(str([]byte(protocol.AlgorithmECDSAP256)), str([]byte("nistp384")), str(point)),
		"compressed point": cat(
			str([]byte(protocol.AlgorithmECDSAP256)),
			str([]byte("nistp256")),
			str(append([]byte{2}, point[1:33]...)),
		),
		"short point": cat(str([]byte(protocol.AlgorithmECDSAP256)), str([]byte("nistp256")), str(point[:64])),
		"empty":       nil,
	}

	for name, data := range wrong {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			if _, err := protocol.ECDSAP256PublicKeyPoint(data); !errors.Is(err, protocol.ErrInvalid) {
				t.Fatalf("got %v", err)
			}
		})
	}
}
