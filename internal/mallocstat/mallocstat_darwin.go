//go:build darwin && cgo

package mallocstat

/*
#include <malloc/malloc.h>
#include <stdint.h>

static uint64_t taciturn_bytes_in_use(void) {
	malloc_statistics_t stats;
	malloc_zone_statistics(NULL, &stats);
	return stats.size_in_use;
}
*/
import "C"

// Bytes is the number of bytes in use across every malloc zone of the
// process, and true: the build can ask. Bytes, not blocks: on macOS 15 the
// allocator's count of blocks in use rises with every block handed out and
// does not come back with its release, while its bytes do.
func Bytes() (uint64, bool) {
	return uint64(C.taciturn_bytes_in_use()), true
}
