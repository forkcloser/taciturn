//go:build darwin && cgo

package cli_test

// haveFramework says this build links Security.framework, so that the
// agent can identify the peer of a connection.
const haveFramework = true
