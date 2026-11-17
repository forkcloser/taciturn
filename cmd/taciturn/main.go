// Command taciturn is an ssh-agent for keys in the Mac's Secure Enclave,
// and the command line that manages them.
//
// Usage:
//
//	taciturn agent | install | uninstall | status | doctor | log | version
//	taciturn key create|list|show|allow|disallow|peers|sshsig|delete|import|rotate|retire|signers
//
// Everything but the exit lives in internal/cli.
package main

import (
	"os"

	"github.com/forkcloser/taciturn/internal/cli"
)

// version is stamped at build time via -X main.version: the release's
// `package` recipe injects the release version, `just do build go` injects
// `git describe`; a plain `go build` reports "dev".
var version = "dev"

func main() {
	os.Exit(cli.Run(version, os.Args[1:], os.Stdout, os.Stderr))
}
