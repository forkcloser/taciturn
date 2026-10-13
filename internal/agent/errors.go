package agent

import "errors"

var (
	// ErrInvalid is a socket path the agent refuses, or a configuration
	// without a store.
	ErrInvalid = errors.New("invalid agent configuration")
	// ErrBusy is a socket path another agent holds.
	ErrBusy = errors.New("another agent holds the socket")
)
