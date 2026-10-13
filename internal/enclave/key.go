package enclave

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

// Key is a signing key held by the enclave, as a reference the framework
// gave this process. Close releases it; a Key left unclosed is released
// when it is collected. The reference lives in its own holder, released
// once whether Close, the collector or both ask.
type Key struct {
	handle *keyHandle
	blob   []byte
	public []byte
}

// Blob is the enclave's wrapped copy of the key, to store.
func (k *Key) Blob() []byte {
	return append([]byte(nil), k.blob...)
}

// Public is the public key as an uncompressed P-256 point.
func (k *Key) Public() []byte {
	return append([]byte(nil), k.public...)
}

// Close releases the framework's reference. Closing twice is harmless.
func (k *Key) Close() {
	k.handle.release()
}
