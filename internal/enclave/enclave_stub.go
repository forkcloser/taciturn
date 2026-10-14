//go:build !(darwin && cgo)

package enclave

import (
	"fmt"
	"math/big"
)

// keyHandle is nothing without the framework; no Key is ever made here.
type keyHandle struct{}

func (h *keyHandle) release() {}

func unavailable() error {
	return fmt.Errorf("built without cgo on darwin: %w", ErrUnavailable)
}

// AccessGroup is ErrUnavailable: there is no keychain without Security.framework.
func AccessGroup() (string, error) {
	return "", unavailable()
}

// Available is false: there is no enclave without Security.framework.
func Available() bool {
	return false
}

// Generate is ErrUnavailable: there is no enclave without Security.framework.
func Generate(Class) (*Key, error) {
	return nil, unavailable()
}

// Store is ErrUnavailable: no Key exists without Security.framework.
func (k *Key) Store(string) error {
	return unavailable()
}

// Load is ErrUnavailable: there is no keychain without Security.framework.
func Load(string, []byte) (*Key, error) {
	return nil, unavailable()
}

// Import is ErrUnavailable: there is no enclave without Security.framework.
func Import([]byte, []byte, string) (*Key, error) {
	return nil, unavailable()
}

// Delete is ErrUnavailable: there is no keychain without Security.framework.
func Delete(string) error {
	return unavailable()
}

// Sign is ErrUnavailable: no Key exists without Security.framework.
func (k *Key) Sign([]byte) (*big.Int, *big.Int, error) {
	return nil, nil, unavailable()
}
