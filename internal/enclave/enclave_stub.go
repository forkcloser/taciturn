//go:build !(darwin && cgo)

package enclave

import (
	"fmt"
	"math/big"
)

// keyHandle is nothing without the framework; no Key is ever made here.
type keyHandle struct{}

func (h *keyHandle) release() {}

// Available is false: there is no enclave without Security.framework.
func Available() bool {
	return false
}

// Generate is ErrUnavailable: there is no enclave without Security.framework.
func Generate(Class) (*Key, error) {
	return nil, fmt.Errorf("built without cgo on darwin: %w", ErrUnavailable)
}

// Load is ErrUnavailable: there is no enclave without Security.framework.
func Load([]byte, []byte) (*Key, error) {
	return nil, fmt.Errorf("built without cgo on darwin: %w", ErrUnavailable)
}

// Sign is ErrUnavailable: no Key exists without Security.framework.
func (k *Key) Sign([]byte) (*big.Int, *big.Int, error) {
	return nil, nil, fmt.Errorf("built without cgo on darwin: %w", ErrUnavailable)
}
