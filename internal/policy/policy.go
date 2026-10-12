package policy

import (
	"bytes"
	"path/filepath"
	"slices"
	"strings"

	"github.com/forkcloser/taciturn/internal/protocol"
)

// Destination is one place a key may authenticate to: a user name on a
// server known by its host keys. Host is a label for the log; the host keys
// are what the protocol carries and what the decision compares.
type Destination struct {
	User     string   `json:"user"`
	Host     string   `json:"host"`
	HostKeys [][]byte `json:"hostKeys"`
}

// PeerAny is the one peer entry that admits every connecting process.
const PeerAny = "any"

// PeerPathPrefix marks a peer entry that names the connecting executable by
// path, as a filepath.Match pattern; any other entry is a code-signing
// requirement the agent evaluated on the peer.
const PeerPathPrefix = "path="

// Policy is what a key's owner allowed.
type Policy struct {
	Destinations []Destination `json:"destinations"`
	// Namespaces are the SSHSIG namespaces the key may sign in.
	Namespaces []string `json:"namespaces"`
	// Peers names the processes that may ask: PeerAny, PeerPathPrefix and
	// a pattern, or a code-signing requirement. Empty admits none.
	Peers []string `json:"peers"`
}

// Peer is what the agent established about the connecting process: its
// executable path, and the requirement strings it evaluated as satisfied.
type Peer struct {
	Path      string
	Satisfied []string
}

// Connection is the state of one agent connection as the agent recorded it.
type Connection struct {
	Peer Peer
	// BindRefused records a session-bind the agent did not accept; the
	// connection is then dead to every key, as in OpenSSH's agent.
	BindRefused bool
	// Bound says a session binding is recorded; the fields below are then
	// facts the agent verified.
	Bound      bool
	Forwarding bool
	HostKey    []byte
	SessionID  []byte
}

// Decision is the outcome and the rule that produced it, in words the log
// prints as they are.
type Decision struct {
	Allowed bool
	Rule    string
}

func refuse(rule string) Decision {
	return Decision{Rule: rule}
}

func allow(rule string) Decision {
	return Decision{Allowed: true, Rule: rule}
}

// The rules, as the log names them.
const (
	RuleForwarding    = "connection bound for forwarding"
	RuleBindRefused   = "session binding refused earlier on this connection"
	RuleNoDestination = "no destination with the bound host key"
	RuleNothing       = "the policy allows nothing"
	RuleVisible       = "the policy allows something"
	RuleVisibleBound  = "a destination has the bound host key"
	RuleNotUserauth   = "signed data is not a user-authentication request"
	RuleSessionID     = "session identifier differs from the binding"
	RuleKeyMismatch   = "the request names another key"
	RuleAlgorithm     = "the request names another algorithm"
	RuleUser          = "no destination with the bound host key allows this user"
	RuleNotSSHSig     = "signed data is not an SSHSIG request"
	RuleNamespace     = "namespace not allowed"
	RulePeer          = "peer not allowed"
	RuleAllowedAuth   = "user-authentication within a destination"
	RuleAllowedSSHSig = "SSHSIG within an allowed namespace"
)

// Visible says whether the key is listed to the connection.
func Visible(conn Connection, pol Policy) Decision {
	if conn.Bound && conn.Forwarding {
		return refuse(RuleForwarding)
	}

	if conn.BindRefused {
		return refuse(RuleBindRefused)
	}

	if !conn.Bound {
		if len(pol.Destinations) == 0 && len(pol.Namespaces) == 0 {
			return refuse(RuleNothing)
		}

		return allow(RuleVisible)
	}

	if len(destinationsFor(pol, conn.HostKey)) == 0 {
		return refuse(RuleNoDestination)
	}

	return allow(RuleVisibleBound)
}

// Sign decides a signature request for the key whose public blob is
// keyBlob, over data as the client sent it.
func Sign(conn Connection, pol Policy, keyBlob, data []byte) Decision {
	if conn.Bound && conn.Forwarding {
		return refuse(RuleForwarding)
	}

	if conn.BindRefused {
		return refuse(RuleBindRefused)
	}

	if conn.Bound {
		return signBound(conn, pol, keyBlob, data)
	}

	return signUnbound(conn, pol, data)
}

func signBound(conn Connection, pol Policy, keyBlob, data []byte) Decision {
	req, err := protocol.ParseUserauthRequest(data)
	if err != nil {
		return refuse(RuleNotUserauth)
	}

	if !bytes.Equal(req.SessionID, conn.SessionID) {
		return refuse(RuleSessionID)
	}

	if !bytes.Equal(req.KeyBlob, keyBlob) {
		return refuse(RuleKeyMismatch)
	}

	if req.PublicKeyAlgorithm != protocol.AlgorithmECDSAP256 {
		return refuse(RuleAlgorithm)
	}

	if !userAllowed(destinationsFor(pol, conn.HostKey), req.User) {
		return refuse(RuleUser)
	}

	if !peerAllowed(pol.Peers, conn.Peer) {
		return refuse(RulePeer)
	}

	return allow(RuleAllowedAuth)
}

func signUnbound(conn Connection, pol Policy, data []byte) Decision {
	req, err := protocol.ParseSSHSigRequest(data)
	if err != nil {
		return refuse(RuleNotSSHSig)
	}

	if !slices.Contains(pol.Namespaces, req.Namespace) {
		return refuse(RuleNamespace)
	}

	if !peerAllowed(pol.Peers, conn.Peer) {
		return refuse(RulePeer)
	}

	return allow(RuleAllowedSSHSig)
}

// destinationsFor is every destination whose host keys include hostKey.
func destinationsFor(pol Policy, hostKey []byte) []Destination {
	var out []Destination

	for _, d := range pol.Destinations {
		for _, k := range d.HostKeys {
			if bytes.Equal(k, hostKey) {
				out = append(out, d)

				break
			}
		}
	}

	return out
}

func userAllowed(destinations []Destination, user string) bool {
	for _, d := range destinations {
		if d.User == user {
			return true
		}
	}

	return false
}

func peerAllowed(peers []string, peer Peer) bool {
	for _, entry := range peers {
		switch {
		case entry == PeerAny:
			return true
		case strings.HasPrefix(entry, PeerPathPrefix):
			// A bad pattern matches nothing: filepath.Match reports it as
			// an error, and an entry that cannot match must not admit.
			if ok, err := filepath.Match(strings.TrimPrefix(entry, PeerPathPrefix), peer.Path); err == nil && ok {
				return true
			}
		case slices.Contains(peer.Satisfied, entry):
			return true
		}
	}

	return false
}
