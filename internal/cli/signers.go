package cli

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1" // #nosec G505 -- the hash OpenSSH's known_hosts format fixes for a host name
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
// naming the host exactly, plain, hashed (HashKnownHosts) or bracketed with
// a port. A marker line is not a host key; a @revoked one takes its key
// away from the hosts it covers, wherever in the file it stands, as it does
// for ssh (sshd(8), SSH_KNOWN_HOSTS FILE FORMAT). Each line is read on its
// own. One x/crypto does not read is left out, the agent verifying a
// binding with x/crypto too, so that such a key could never be bound to.
// leftOut says, a line each, which keys of the host were left out and why.
func hostKeysFrom(path, host string) (keys [][]byte, leftOut []string, err error) {
	data, err := os.ReadFile(path) // #nosec G304 -- the operator's -known-hosts flag
	if err != nil {
		return nil, nil, fmt.Errorf("known_hosts: %w", err)
	}

	var found, revoked []knownLine

	for number, line := range bytes.Split(data, []byte("\n")) {
		marker, hosts, key, _, _, err := ssh.ParseKnownHosts(line)

		switch {
		case errors.Is(err, io.EOF):
			// Blank, or a comment.
		case err != nil:
			if _, ok := named(unreadHosts(line), host); ok {
				leftOut = append(leftOut, fmt.Sprintf("line %d cannot be read: %v", number+1, err))
			}
		case marker == "revoked":
			revoked = append(revoked, knownLine{number: number + 1, hosts: hosts, key: plainKey(key)})
		case marker == "":
			if name, ok := named(hosts, host); ok {
				found = append(found, knownLine{number: number + 1, hosts: []string{name}, key: key.Marshal()})
			}
		}
	}

	for _, line := range found {
		if by, ok := line.revokedBy(revoked); ok {
			leftOut = append(leftOut, fmt.Sprintf("line %d is revoked by line %d", line.number, by))

			continue
		}

		keys = append(keys, line.key)
	}

	if len(keys) == 0 {
		return nil, nil, noHostKeys(path, host, leftOut)
	}

	return keys, leftOut, nil
}

// noHostKeys is the error for a host the file holds no usable key for,
// with what was left out when something was.
func noHostKeys(path, host string, leftOut []string) error {
	if len(leftOut) > 0 {
		return fmt.Errorf("%s in %s: %w: left out: %s", host, path, errNoHostKeys, strings.Join(leftOut, "; "))
	}

	return fmt.Errorf("%s in %s: %w", host, path, errNoHostKeys)
}

// knownLine is a known_hosts line that was read: a key of the host, with
// the one entry that names the host, or a @revoked line with its entries.
type knownLine struct {
	number int
	hosts  []string
	key    []byte
}

// revokedBy is the number of the @revoked line that carries the line's key
// for the name the line gives the host.
func (l knownLine) revokedBy(revoked []knownLine) (int, bool) {
	for _, line := range revoked {
		if bytes.Equal(line.key, l.key) && covers(line.hosts, l.hosts[0]) {
			return line.number, true
		}
	}

	return 0, false
}

// plainKey is the key a @revoked line revokes: the key itself, and for a
// certificate the key it certifies, ssh comparing the keys and not what is
// certified about them (sshkey.c, sshkey_equal_public).
func plainKey(key ssh.PublicKey) []byte {
	if certificate, ok := key.(*ssh.Certificate); ok {
		return certificate.Key.Marshal()
	}

	return key.Marshal()
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

// named is the name under which one of a line's host entries is the host:
// the host itself, plain or hashed, or the host bracketed with a port.
func named(entries []string, host string) (string, bool) {
	for _, entry := range entries {
		switch {
		case entry == host, hashedIs(entry, host):
			return host, true
		case strings.HasPrefix(entry, "["+host+"]:"):
			return entry, true
		}
	}

	return "", false
}

// covers says whether the host field of a @revoked line covers a name, as
// ssh reads it (hostfile.c, match_maybe_hashed; match.c, match_pattern_list,
// case folded). A field that begins as a hash is one hashed name, the whole
// of it. Any other is a list of patterns: one matches the name, and none
// that matches it stands under a '!'.
func covers(entries []string, name string) bool {
	name = strings.ToLower(name)

	if len(entries) > 0 && strings.HasPrefix(entries[0], hashDelimiter) {
		return len(entries) == 1 && hashedIs(entries[0], name)
	}

	covered := false

	for _, entry := range entries {
		pattern, negated := strings.CutPrefix(strings.ToLower(entry), "!")

		switch {
		case !wildcard(pattern, name):
		case negated:
			return false
		default:
			covered = true
		}
	}

	return covered
}

// wildcard is ssh's match_pattern: '*' in the pattern is any run of
// characters, '?' any one, and every other character itself.
func wildcard(pattern, text string) bool {
	// Where the last '*' stood, and how much of the text it has taken.
	star, taken := -1, 0
	index, read := 0, 0

	for read < len(text) {
		switch {
		case index < len(pattern) && pattern[index] == '*':
			star, taken = index, read
			index++
		case index < len(pattern) && (pattern[index] == '?' || pattern[index] == text[read]):
			index++
			read++
		case star >= 0:
			taken++
			index, read = star+1, taken
		default:
			return false
		}
	}

	return strings.Trim(pattern[index:], "*") == ""
}

// The hashed form of a known_hosts entry, sshd(8) SSH_KNOWN_HOSTS FILE
// FORMAT: "|1|", the salt and HMAC-SHA1 of the host name under it, both
// base64.
const (
	hashDelimiter = "|"
	hashedPrefix  = "|1|"
	hashedParts   = 2
)

func hashedIs(entry, host string) bool {
	rest, ok := strings.CutPrefix(entry, hashedPrefix)
	if !ok {
		return false
	}

	parts := strings.Split(rest, "|")
	if len(parts) != hashedParts {
		return false
	}

	salt, err := base64.StdEncoding.DecodeString(parts[0])
	if err != nil {
		return false
	}

	want, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return false
	}

	mac := hmac.New(sha1.New, salt)
	mac.Write([]byte(host))

	return hmac.Equal(mac.Sum(nil), want)
}
