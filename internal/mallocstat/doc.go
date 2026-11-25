// Package mallocstat says how many bytes the C allocator has in use, for
// the tests that hold cgo code to leaving nothing behind: what Security.framework
// allocates for a peer or a key is invisible to Go's own heap statistics,
// and a test file cannot use cgo to ask. Nothing but tests imports it.
package mallocstat
