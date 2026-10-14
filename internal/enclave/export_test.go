package enclave

// BlobForTest hands a test the wrapped form of a key it generated itself,
// to feed Import the way the CLI feeds it a v0.1 blob file. Tests only:
// nothing outside this file reads a blob out of a Key (docs/design.md F16).
func BlobForTest(key *Key) []byte {
	return append([]byte(nil), key.blob...)
}
