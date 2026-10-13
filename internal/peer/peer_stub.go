//go:build !(darwin && cgo)

package peer

import (
	"fmt"
	"net"
)

// codeHandle is nothing without the framework.
type codeHandle struct{}

// Identify is ErrUnavailable: there is no peer identity without
// Security.framework.
func Identify(*net.UnixConn) (*Identity, error) {
	return nil, fmt.Errorf("built without cgo on darwin: %w", ErrUnavailable)
}

// Satisfies is ErrUnavailable: no Identity exists without the framework.
func (i *Identity) Satisfies(string) (bool, error) {
	return false, fmt.Errorf("built without cgo on darwin: %w", ErrUnavailable)
}

// ValidRequirement is ErrUnavailable: nothing parses a requirement without
// the framework.
func ValidRequirement(string) error {
	return fmt.Errorf("built without cgo on darwin: %w", ErrUnavailable)
}

// Close has nothing to release.
func (i *Identity) Close() {}
