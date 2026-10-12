package keystore

import "errors"

var (
	// ErrInvalid is a name, a fingerprint, a blob or a record the store
	// refuses as the caller's mistake.
	ErrInvalid = errors.New("invalid key record")
	// ErrExists is a key or a name already in the store.
	ErrExists = errors.New("key already exists")
	// ErrNotFound is a key or a name the store does not have.
	ErrNotFound = errors.New("key not found")
	// ErrCorrupt is a store whose files do not agree with each other or
	// with themselves.
	ErrCorrupt = errors.New("corrupt key store")
	// ErrInsecure is a store directory or file readable by others.
	ErrInsecure = errors.New("key store not private")
)
