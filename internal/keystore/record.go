package keystore

import (
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/forkcloser/taciturn/internal/policy"
	"github.com/forkcloser/taciturn/internal/protocol"
)

// Class is the enclave access class a key was created with, which decides
// when the enclave agrees to use it.
type Class string

// The two classes a key can have (docs/design.md, "Keys").
const (
	// ClassAfterFirstUnlock signs from the first unlock after boot until the
	// next boot, screen locked or not.
	ClassAfterFirstUnlock Class = "after-first-unlock"
	// ClassWhenUnlocked signs only while the user's session is unlocked.
	ClassWhenUnlocked Class = "when-unlocked"
)

// Record is what the store knows about a key besides its blob.
type Record struct {
	// Fingerprint is "SHA256:" and the unpadded base64 digest of PublicKey,
	// the key's identity everywhere.
	Fingerprint string `json:"fingerprint"`
	// Name is the operator's handle for the key, unique in the store.
	Name string `json:"name"`
	// PublicKey is the key's OpenSSH wire blob.
	PublicKey []byte    `json:"publicKey"`
	Class     Class     `json:"class"`
	Created   time.Time `json:"created"`
	// Retired is set when the agent must no longer serve the key.
	Retired *time.Time    `json:"retired,omitempty"`
	Policy  policy.Policy `json:"policy"`
	// Predecessor and Successor are the fingerprints a rotation links.
	Predecessor string `json:"predecessor,omitempty"`
	Successor   string `json:"successor,omitempty"`
}

// The bounds on a name and a blob.
const (
	MaxNameLength = 64
	MaxBlob       = 4096
)

const fingerprintPrefix = "SHA256:"

// fingerprintDigestLength is the unpadded base64 of 32 bytes.
const fingerprintDigestLength = 43

// ValidateName says whether a name is one the store accepts.
func ValidateName(name string) error {
	if name == "" || len(name) > MaxNameLength {
		return fmt.Errorf("name of %d characters: %w", len(name), ErrInvalid)
	}

	if name[0] == '.' || name[0] == '-' {
		return fmt.Errorf("name %q starts with %q: %w", name, name[:1], ErrInvalid)
	}

	for _, c := range name {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '.', c == '_', c == '@', c == '-':
		default:
			return fmt.Errorf("name %q contains %q: %w", name, string(c), ErrInvalid)
		}
	}

	return nil
}

// ValidateFingerprint says whether a string has the shape of a fingerprint.
func ValidateFingerprint(fingerprint string) error {
	digest, ok := strings.CutPrefix(fingerprint, fingerprintPrefix)
	if !ok || len(digest) != fingerprintDigestLength {
		return fmt.Errorf("fingerprint %q: %w", fingerprint, ErrInvalid)
	}

	if _, err := base64.RawStdEncoding.DecodeString(digest); err != nil {
		return fmt.Errorf("fingerprint %q: %w", fingerprint, ErrInvalid)
	}

	return nil
}

// validate checks a record the caller hands in.
func (r Record) validate() error {
	if err := ValidateName(r.Name); err != nil {
		return err
	}

	if r.Class != ClassAfterFirstUnlock && r.Class != ClassWhenUnlocked {
		return fmt.Errorf("class %q: %w", r.Class, ErrInvalid)
	}

	if r.Created.IsZero() {
		return fmt.Errorf("record without a creation time: %w", ErrInvalid)
	}

	if _, err := protocol.ECDSAP256PublicKeyPoint(r.PublicKey); err != nil {
		return fmt.Errorf("public key: %w", ErrInvalid)
	}

	if want := protocol.Fingerprint(r.PublicKey); r.Fingerprint != want {
		return fmt.Errorf("fingerprint %q is not the key's %q: %w", r.Fingerprint, want, ErrInvalid)
	}

	for _, linked := range []string{r.Predecessor, r.Successor} {
		if linked == "" {
			continue
		}

		if err := ValidateFingerprint(linked); err != nil {
			return err
		}
	}

	return nil
}

// fileID is a fingerprint as a file name: the digest in the URL-safe
// alphabet, so no '/' and no '+'.
func fileID(fingerprint string) string {
	digest := strings.TrimPrefix(fingerprint, fingerprintPrefix)

	return strings.NewReplacer("/", "_", "+", "-").Replace(digest)
}
