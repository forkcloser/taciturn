//go:build !(darwin && cgo)

package mallocstat

// Bytes is false in a build that cannot ask the allocator: one without cgo,
// which runs no C code to leak either.
func Bytes() (uint64, bool) {
	return 0, false
}
