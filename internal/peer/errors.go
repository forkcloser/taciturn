package peer

import "errors"

var (
	// ErrForeign is a peer running as another user.
	ErrForeign = errors.New("peer belongs to another user")
	// ErrUnavailable is a connection whose peer cannot be identified: not a
	// unix socket, a closed connection, or a build without the framework.
	ErrUnavailable = errors.New("peer identity unavailable")
	// ErrInvalid is a requirement string the framework does not parse.
	ErrInvalid = errors.New("invalid code requirement")
)
