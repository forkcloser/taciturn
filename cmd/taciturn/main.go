// Command taciturn is an ssh-agent for keys in the Mac's Secure Enclave,
// and the command line that manages them. The scaffold names the binary
// and its version stamp; the command arrives with its packages.
package main

import (
	"fmt"
	"os"
)

// version is stamped at build time via -X main.version: goreleaser injects
// the release version, `just build go` injects `git describe`; a plain
// `go build` reports "dev".
var version = "dev"

func main() {
	_, _ = fmt.Fprintln(os.Stdout, "taciturn "+version)
}
