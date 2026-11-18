//go:build !(darwin && cgo)

package peer_test

// haveFramework says this build links Security.framework: without it no
// peer is ever identified, and the tests that need one skip.
const haveFramework = false
