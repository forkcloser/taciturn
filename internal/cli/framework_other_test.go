//go:build !(darwin && cgo)

package cli_test

// haveFramework says this build links Security.framework: without it the
// agent identifies no peer and answers no connection, and the test that
// asks one for its keys skips.
const haveFramework = false
