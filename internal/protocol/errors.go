package protocol

import "errors"

var (
	// ErrInvalid is a message or a signed-data blob that is not what the
	// format says: a truncated field, a wrong constant, trailing bytes.
	ErrInvalid = errors.New("malformed agent message")
	// ErrTooLarge is a message or a field over one of the package's bounds.
	ErrTooLarge = errors.New("agent message too large")
)
