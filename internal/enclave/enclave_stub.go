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

// Generate is ErrUnavailable for a class it would make: there is no
// enclave without Security.framework. A bad argument is ErrInvalid here as
// everywhere.
func Generate(class Class) (*Key, error) {
	err := validateClass(class)
	if err != nil {
		return nil, err
	}

	return nil, unavailable()
}

// Store is ErrUnavailable: no Key exists without Security.framework.
func (k *Key) Store(string) error {
	return unavailable()
}

// Load is ErrUnavailable for arguments it would look up: there is no
// keychain without Security.framework.
func Load(label string, public []byte) (*Key, error) {
	err := ValidateLabel(label)
	if err != nil {
		return nil, err
	}

	err = validatePoint(public)
	if err != nil {
		return nil, err
	}

	return nil, unavailable()
}

// Import is ErrUnavailable for arguments it would load: there is no
// enclave without Security.framework.
func Import(blob, public []byte, label string) (*Key, error) {
	if len(blob) == 0 {
		return nil, fmt.Errorf("empty blob: %w", ErrInvalid)
	}

	err := validatePoint(public)
	if err != nil {
		return nil, err
	}

	err = ValidateLabel(label)
	if err != nil {
		return nil, err
	}

	return nil, unavailable()
}

// Delete is ErrUnavailable for a label it would remove: there is no
// keychain without Security.framework.
func Delete(label string) error {
	err := ValidateLabel(label)
	if err != nil {
		return err
	}

	return unavailable()
}

// Sign is ErrUnavailable: no Key exists without Security.framework.
func (k *Key) Sign([]byte) (*big.Int, *big.Int, error) {
	return nil, nil, unavailable()
}
