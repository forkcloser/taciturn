package enclave

import "errors"

var (
	// ErrUnavailable is an enclave or a keychain that cannot be reached: no
	// such hardware, a virtual machine, a sandbox that denies the security
	// daemons, a process the framework will not serve, or a process without
	// the keychain-access-groups entitlement, which is any build run
	// outside the signed bundle.
	ErrUnavailable = errors.New("secure enclave unavailable")
	// ErrRefused is an operation the enclave declined on a key it knows: the
	// key's class does not allow it now (a locked screen for
	// ClassWhenUnlocked) or the framework reported an authorization failure.
	ErrRefused = errors.New("secure enclave refused")
	// ErrInvalid is a blob, a label or a class the enclave does not accept.
	ErrInvalid = errors.New("invalid enclave key")
	// ErrMismatch is a loaded key whose public half is not the one the
	// caller stored: the keychain answered with another key.
	ErrMismatch = errors.New("enclave key does not match its public key")
	// ErrNotFound is a label no key in the keychain carries, within the
	// access groups this process is entitled to.
	ErrNotFound = errors.New("no such key in the keychain")
	// ErrExists is a label a key in the keychain already carries.
	ErrExists = errors.New("key already in the keychain")
	// ErrInternal is a failure of the framework that is none of the above,
	// with its OSStatus in the message.
	ErrInternal = errors.New("security framework failure")
)
