//go:build darwin && cgo

package agent_test

// haveFramework says this build links Security.framework: a peer that
// cannot be identified here is a failure, not a reason to skip.
const haveFramework = true
