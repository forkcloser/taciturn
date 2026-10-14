package enclave

import (
	"fmt"
	"strings"
)

// Class is the access class a key is made with.
type Class int

// The classes, as the keychain names them.
const (
	// ClassAfterFirstUnlock is kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly.
	ClassAfterFirstUnlock Class = iota + 1
	// ClassWhenUnlocked is kSecAttrAccessibleWhenUnlockedThisDeviceOnly.
	ClassWhenUnlocked
)

// PointSize is an uncompressed P-256 point: 0x04 and two 32-byte
// coordinates, the form Public returns and Load takes.
const PointSize = 65

// MaxLabel bounds a keychain label; a fingerprint is 50 characters.
const MaxLabel = 128

// AccessGroupSuffix is the end of the keychain access group keys live
// under, <team>.org.forkcloser.taciturn: the bundle identifier, which the
// provisioning profile ties to the team (docs/design.md, decision 16).
const AccessGroupSuffix = "org.forkcloser.taciturn"

// Key is a signing key held by the enclave, as a reference the framework
// gave this process. Close releases it; a Key left unclosed is released
// when it is collected. The reference lives in its own holder, released
// once whether Close, the collector or both ask. The wrapped form of the
// key stays inside the package: the keychain protects the item, not the
// material, so nothing exports it (docs/design.md F16).
type Key struct {
	handle *keyHandle
	blob   []byte
	public []byte
}

// Public is the public key as an uncompressed P-256 point.
func (k *Key) Public() []byte {
	return append([]byte(nil), k.public...)
}

// Close releases the framework's reference. Closing twice is harmless.
func (k *Key) Close() {
	k.handle.release()
}

// ValidateLabel says whether a string can label a key in the keychain:
// printable, no control characters, within MaxLabel.
func ValidateLabel(label string) error {
	if label == "" || len(label) > MaxLabel {
		return fmt.Errorf("label of %d bytes: %w", len(label), ErrInvalid)
	}

	if strings.ContainsFunc(label, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		return fmt.Errorf("label %q with control characters: %w", label, ErrInvalid)
	}

	return nil
}
