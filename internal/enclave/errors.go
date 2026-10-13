package enclave

import "errors"

var (
	// ErrUnavailable is an enclave that cannot be reached: no such hardware,
	// a virtual machine, a sandbox that denies the security daemons, a
	// process the framework will not serve.
	ErrUnavailable = errors.New("secure enclave unavailable")
	// ErrRefused is an operation the enclave declined on a key it knows: the
	// key's class does not allow it now (a locked screen for
	// ClassWhenUnlocked) or the framework reported an authorization failure.
	ErrRefused = errors.New("secure enclave refused")
	// ErrInvalid is a blob or a class the enclave does not accept.
	ErrInvalid = errors.New("invalid enclave key")
	// ErrMismatch is a loaded key whose public half is not the one the
	// caller stored: the enclave answered with another key.
	ErrMismatch = errors.New("enclave key does not match its public key")
	// ErrInternal is a failure of the framework that is none of the above,
	// with its OSStatus in the message.
	ErrInternal = errors.New("security framework failure")
)
