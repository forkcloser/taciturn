package cli

import (
	"encoding/base64"
	"errors"
	"fmt"
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
// principal, the git namespace, the validity window from the key's
// creation to its retirement, and the key.
func allowedSigner(principal string, record keystore.Record) string {
	parts := []string{
		principal,
		`namespaces="git"`,
		`valid-after="` + record.Created.UTC().Format(signersTimeLayout) + `"`,
	}

	if record.Retired != nil {
		parts = append(parts, `valid-before="`+record.Retired.UTC().Format(signersTimeLayout)+`"`)
	}

	parts = append(parts, protocol.AlgorithmECDSAP256, base64.StdEncoding.EncodeToString(record.PublicKey))

	return strings.Join(parts, " ")
}

// hostKeysFrom reads the host's keys out of a known_hosts file: every
// entry naming the host exactly, plain or bracketed with a port.
func hostKeysFrom(path, host string) ([][]byte, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- the operator's -known-hosts flag
	if err != nil {
		return nil, fmt.Errorf("known_hosts: %w", err)
	}

	var keys [][]byte

	for len(data) > 0 {
		marker, hosts, key, _, rest, err := ssh.ParseKnownHosts(data)
		if err != nil {
			break
		}

		data = rest

		if marker != "" {
			continue
		}

		for _, entry := range hosts {
			if entry == host || strings.HasPrefix(entry, "["+host+"]:") {
				keys = append(keys, key.Marshal())

				break
			}
		}
	}

	if len(keys) == 0 {
		return nil, fmt.Errorf("%s in %s: %w", host, path, errNoHostKeys)
	}

	return keys, nil
}
