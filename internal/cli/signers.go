package cli

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/forkcloser/taciturn/internal/keystore"
	"github.com/forkcloser/taciturn/internal/protocol"
)

var errNoHostKeys = errors.New("no host keys for the host in the known_hosts file")

// The allowed-signers timestamp, ssh-keygen(1) ALLOWED SIGNERS:
// YYYYMMDDHHMM[SS][Z].
const signersTimeLayout = "20060102150405Z"

// allowedSigner is the key's line for an allowed-signers file: the
// principal, one options field (the git namespace and the validity window
// from the key's creation to its retirement, comma-separated, as
// ssh-keygen reads it: a second space-separated field would be taken for
// the key type), and the key.
func allowedSigner(principal string, record keystore.Record) string {
	options := []string{
		`namespaces="git"`,
		`valid-after="` + record.Created.UTC().Format(signersTimeLayout) + `"`,
	}

	if record.Retired != nil {
		options = append(options, `valid-before="`+record.Retired.UTC().Format(signersTimeLayout)+`"`)
	}

	return strings.Join([]string{
		principal,
		strings.Join(options, ","),
		protocol.AlgorithmECDSAP256,
		base64.StdEncoding.EncodeToString(record.PublicKey),
	}, " ")
}

// hostKeysFrom reads the host's keys out of a known_hosts file: every entry
// naming the host exactly, plain or bracketed with a port; a marker line
// (@cert-authority, @revoked) is not a host key. Each line is read on its
// own. One x/crypto does not read is left out, and skipped names it when it
// is the host's: the agent verifies a binding with x/crypto too, so such a
// key could never be bound to.
func hostKeysFrom(path, host string) (keys [][]byte, skipped []string, err error) {
	data, err := os.ReadFile(path) // #nosec G304 -- the operator's -known-hosts flag
	if err != nil {
		return nil, nil, fmt.Errorf("known_hosts: %w", err)
	}

	for number, line := range bytes.Split(data, []byte("\n")) {
		marker, hosts, key, _, _, err := ssh.ParseKnownHosts(line)

		switch {
		case errors.Is(err, io.EOF):
			// Blank, or a comment.
		case err != nil:
			if names(unreadHosts(line), host) {
				skipped = append(skipped, fmt.Sprintf("line %d: %v", number+1, err))
			}
		case marker == "" && names(hosts, host):
			keys = append(keys, key.Marshal())
		}
	}

	if len(keys) == 0 {
		if len(skipped) > 0 {
			return nil, nil, fmt.Errorf(
				"%s in %s: %w: unreadable: %s",
				host,
				path,
				errNoHostKeys,
				strings.Join(skipped, "; "),
			)
		}

		return nil, nil, fmt.Errorf("%s in %s: %w", host, path, errNoHostKeys)
	}

	return keys, skipped, nil
}

// unreadHosts is the host field of a line x/crypto refused, or nothing for
// a marker line.
func unreadHosts(line []byte) []string {
	fields := bytes.Fields(line)
	if len(fields) == 0 || fields[0][0] == '@' {
		return nil
	}

	return strings.Split(string(fields[0]), ",")
}

// names says whether one of a line's host entries is the host.
func names(entries []string, host string) bool {
	for _, entry := range entries {
		if entry == host || strings.HasPrefix(entry, "["+host+"]:") {
			return true
		}
	}

	return false
}
