package protocol

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"math/big"
)

// The names of the one key type the agent serves, RFC 5656 section 3.1.
const (
	AlgorithmECDSAP256 = "ecdsa-sha2-nistp256"
	curveP256          = "nistp256"
	// p256PointSize is an uncompressed P-256 point, 0x04 then two 32-byte
	// coordinates, RFC 5656 section 3.1 and SEC 1 section 2.3.3.
	p256PointSize = 65
)

// ECDSAP256PublicKey encodes an uncompressed P-256 point as the public key
// blob of RFC 5656 section 3.1: the algorithm name, the curve name and the
// point. A point that is not 65 bytes starting with 0x04 is ErrInvalid.
func ECDSAP256PublicKey(point []byte) ([]byte, error) {
	if len(point) != p256PointSize || point[0] != 0x04 {
		return nil, fmt.Errorf("P-256 point of %d bytes: %w", len(point), ErrInvalid)
	}

	var out builder

	out.putString(AlgorithmECDSAP256)
	out.putString(curveP256)
	out.putBytes(point)

	return out.buf, nil
}

// ECDSAP256PublicKeyPoint decodes a public key blob made by
// ECDSAP256PublicKey back to its point. Any other blob, another algorithm
// or curve, a malformed point, trailing bytes, is ErrInvalid.
func ECDSAP256PublicKeyPoint(blob []byte) ([]byte, error) {
	input := newReader(blob)

	algorithm, err := input.string()
	if err != nil {
		return nil, fmt.Errorf("public key algorithm: %w", err)
	}

	if algorithm != AlgorithmECDSAP256 {
		return nil, fmt.Errorf("public key algorithm %q: %w", algorithm, ErrInvalid)
	}

	curve, err := input.string()
	if err != nil {
		return nil, fmt.Errorf("public key curve: %w", err)
	}

	if curve != curveP256 {
		return nil, fmt.Errorf("public key curve %q: %w", curve, ErrInvalid)
	}

	point, err := input.bytes()
	if err != nil {
		return nil, fmt.Errorf("public key point: %w", err)
	}

	if len(point) != p256PointSize || point[0] != 0x04 {
		return nil, fmt.Errorf("P-256 point of %d bytes: %w", len(point), ErrInvalid)
	}

	if err := input.done(); err != nil {
		return nil, fmt.Errorf("public key: %w", err)
	}

	return point, nil
}

// ECDSAP256Signature encodes an ECDSA signature as the blob of RFC 5656
// section 3.1.2: the algorithm name, then r and s as mpints in one string.
// Either value negative is ErrInvalid.
func ECDSAP256Signature(sigR, sigS *big.Int) ([]byte, error) {
	if sigR.Sign() < 0 || sigS.Sign() < 0 {
		return nil, fmt.Errorf("negative signature value: %w", ErrInvalid)
	}

	var inner builder

	inner.putMPInt(sigR)
	inner.putMPInt(sigS)

	var out builder

	out.putString(AlgorithmECDSAP256)
	out.putBytes(inner.buf)

	return out.buf, nil
}

// Fingerprint is the SHA-256 fingerprint of a public key blob in the form
// ssh-keygen -l prints: "SHA256:" and the unpadded base64 of the digest.
func Fingerprint(blob []byte) string {
	sum := sha256.Sum256(blob)

	return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
}
