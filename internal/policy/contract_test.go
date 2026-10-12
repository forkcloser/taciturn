// The contract of package policy is the rule list in its package comment,
// from docs/design.md "Policy, and the decision the agent makes". The
// tests here state each rule on one case; bounded_test.go walks the whole
// table: every connection state, every shape of signed data, every policy
// edge, and asserts the decision each combination must reach.
package policy_test

import (
	"bytes"
	"testing"

	"github.com/forkcloser/taciturn/internal/policy"
	"github.com/forkcloser/taciturn/internal/protocol"
)

func str(b []byte) []byte {
	return append([]byte{0, 0, 0, byte(len(b))}, b...)
}

func cat(parts ...[]byte) []byte {
	out := make([]byte, 0)
	for _, p := range parts {
		out = append(out, p...)
	}

	return out
}

var (
	keyBlob = cat(
		str([]byte(protocol.AlgorithmECDSAP256)),
		str([]byte("nistp256")),
		str(bytes.Repeat([]byte{4}, 65)),
	)
	otherKeyBlob = cat(
		str([]byte(protocol.AlgorithmECDSAP256)),
		str([]byte("nistp256")),
		str(bytes.Repeat([]byte{5}, 65)),
	)
	githubKey    = cat(str([]byte("ssh-ed25519")), str(bytes.Repeat([]byte{1}, 32)))
	otherHostKey = cat(str([]byte("ssh-ed25519")), str(bytes.Repeat([]byte{2}, 32)))
	sessionID    = bytes.Repeat([]byte{0xAB}, 32)
	otherSession = bytes.Repeat([]byte{0xCD}, 32)
)

func userauthFor(sid []byte, user, algorithm string, key []byte) []byte {
	return cat(
		str(sid),
		[]byte{50},
		str([]byte(user)),
		str([]byte("ssh-connection")),
		str([]byte("publickey")),
		[]byte{1},
		str([]byte(algorithm)),
		str(key),
	)
}

func sshsigFor(namespace string) []byte {
	return cat(
		[]byte("SSHSIG"),
		str([]byte(namespace)),
		str(nil),
		str([]byte("sha512")),
		str(bytes.Repeat([]byte{7}, 64)),
	)
}

func github() policy.Policy {
	return policy.Policy{
		Destinations: []policy.Destination{{User: "git", Host: "github.com", HostKeys: [][]byte{githubKey}}},
		Namespaces:   []string{"git"},
		Peers:        []string{"path=/usr/bin/ssh*"},
	}
}

func sshPeer() policy.Peer {
	return policy.Peer{Path: "/usr/bin/ssh"}
}

func bound(hostKey []byte) policy.Connection {
	return policy.Connection{Peer: sshPeer(), Bound: true, HostKey: hostKey, SessionID: sessionID}
}

func unbound() policy.Connection {
	return policy.Connection{Peer: sshPeer()}
}

func expect(t *testing.T, got policy.Decision, allowed bool, rule string) {
	t.Helper()

	if got.Allowed != allowed || got.Rule != rule {
		t.Fatalf("got %+v, want allowed=%v rule=%q", got, allowed, rule)
	}
}

func TestAuthenticationWithinADestination(t *testing.T) {
	t.Parallel()

	data := userauthFor(sessionID, "git", protocol.AlgorithmECDSAP256, keyBlob)
	expect(t, policy.Sign(bound(githubKey), github(), keyBlob, data), true, policy.RuleAllowedAuth)
	expect(t, policy.Visible(bound(githubKey), github()), true, policy.RuleVisibleBound)
}

func TestSSHSigWithinANamespace(t *testing.T) {
	t.Parallel()

	expect(t, policy.Sign(unbound(), github(), keyBlob, sshsigFor("git")), true, policy.RuleAllowedSSHSig)
	expect(t, policy.Visible(unbound(), github()), true, policy.RuleVisible)
}

func TestForwardingSeesNothing(t *testing.T) {
	t.Parallel()

	conn := bound(githubKey)
	conn.Forwarding = true

	expect(t, policy.Visible(conn, github()), false, policy.RuleForwarding)
	expect(
		t,
		policy.Sign(conn, github(), keyBlob, userauthFor(sessionID, "git", protocol.AlgorithmECDSAP256, keyBlob)),
		false,
		policy.RuleForwarding,
	)
	expect(t, policy.Sign(conn, github(), keyBlob, sshsigFor("git")), false, policy.RuleForwarding)
}

func TestARefusedBindingKillsTheConnection(t *testing.T) {
	t.Parallel()

	conn := unbound()
	conn.BindRefused = true

	expect(t, policy.Visible(conn, github()), false, policy.RuleBindRefused)
	expect(t, policy.Sign(conn, github(), keyBlob, sshsigFor("git")), false, policy.RuleBindRefused)
}

func TestBoundRefusals(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		conn policy.Connection
		pol  policy.Policy
		data []byte
		rule string
	}{
		"sshsig data on a bound connection": {bound(githubKey), github(), sshsigFor("git"), policy.RuleNotUserauth},
		"garbage":                           {bound(githubKey), github(), []byte{1, 2, 3}, policy.RuleNotUserauth},
		"another session": {
			bound(githubKey),
			github(),
			userauthFor(otherSession, "git", protocol.AlgorithmECDSAP256, keyBlob),
			policy.RuleSessionID,
		},
		"another key": {
			bound(githubKey),
			github(),
			userauthFor(sessionID, "git", protocol.AlgorithmECDSAP256, otherKeyBlob),
			policy.RuleKeyMismatch,
		},
		"another algorithm": {
			bound(githubKey),
			github(),
			userauthFor(sessionID, "git", "ssh-ed25519", keyBlob),
			policy.RuleAlgorithm,
		},
		"another user": {
			bound(githubKey),
			github(),
			userauthFor(sessionID, "root", protocol.AlgorithmECDSAP256, keyBlob),
			policy.RuleUser,
		},
		"another host": {
			bound(otherHostKey),
			github(),
			userauthFor(sessionID, "git", protocol.AlgorithmECDSAP256, keyBlob),
			policy.RuleUser,
		},
		"wrong peer": {
			policy.Connection{
				Peer:      policy.Peer{Path: "/tmp/evil"},
				Bound:     true,
				HostKey:   githubKey,
				SessionID: sessionID,
			},
			github(),
			userauthFor(sessionID, "git", protocol.AlgorithmECDSAP256, keyBlob),
			policy.RulePeer,
		},
	}

	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			expect(t, policy.Sign(c.conn, c.pol, keyBlob, c.data), false, c.rule)
		})
	}

	expect(t, policy.Visible(bound(otherHostKey), github()), false, policy.RuleNoDestination)
}

func TestUnboundRefusals(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		conn policy.Connection
		data []byte
		rule string
	}{
		"userauth without a binding": {
			unbound(),
			userauthFor(sessionID, "git", protocol.AlgorithmECDSAP256, keyBlob),
			policy.RuleNotSSHSig,
		},
		"garbage":           {unbound(), []byte("SSHSIG"), policy.RuleNotSSHSig},
		"another namespace": {unbound(), sshsigFor("file"), policy.RuleNamespace},
		"wrong peer": {
			policy.Connection{Peer: policy.Peer{Path: "/tmp/evil"}},
			sshsigFor("git"),
			policy.RulePeer,
		},
	}

	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			expect(t, policy.Sign(c.conn, github(), keyBlob, c.data), false, c.rule)
		})
	}

	expect(t, policy.Visible(unbound(), policy.Policy{Peers: []string{policy.PeerAny}}), false, policy.RuleNothing)
}

func TestPeerEntries(t *testing.T) {
	t.Parallel()

	data := sshsigFor("git")

	cases := map[string]struct {
		peers   []string
		peer    policy.Peer
		allowed bool
	}{
		"any": {[]string{policy.PeerAny}, policy.Peer{Path: "/tmp/evil"}, true},
		"path pattern": {
			[]string{"path=/opt/*/bin/ssh"},
			policy.Peer{Path: "/opt/openssh/bin/ssh"},
			true,
		},
		"path pattern, other binary": {
			[]string{"path=/opt/*/bin/ssh"},
			policy.Peer{Path: "/opt/openssh/bin/scp"},
			false,
		},
		"path pattern, deeper path":  {[]string{"path=/opt/*/bin/ssh"}, policy.Peer{Path: "/opt/a/b/bin/ssh"}, false},
		"bad pattern admits nothing": {[]string{"path=/opt/[/ssh"}, policy.Peer{Path: "/opt/[/ssh"}, false},
		"requirement satisfied": {
			[]string{`anchor apple and identifier "com.apple.ssh"`},
			policy.Peer{Path: "/usr/bin/ssh", Satisfied: []string{`anchor apple and identifier "com.apple.ssh"`}},
			true,
		},
		"requirement not satisfied": {
			[]string{`anchor apple and identifier "com.apple.ssh"`},
			policy.Peer{Path: "/usr/bin/ssh"},
			false,
		},
		"no entries": {nil, policy.Peer{Path: "/usr/bin/ssh", Satisfied: []string{"anything"}}, false},
		"second entry matches": {
			[]string{"path=/nowhere", "path=/usr/bin/ssh"},
			policy.Peer{Path: "/usr/bin/ssh"},
			true,
		},
		"empty entry matches nothing": {[]string{""}, policy.Peer{Path: ""}, false},
		"path= alone matches no path": {[]string{"path="}, policy.Peer{Path: ""}, true},
	}

	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			pol := github()
			pol.Peers = c.peers

			got := policy.Sign(policy.Connection{Peer: c.peer}, pol, keyBlob, data)
			if got.Allowed != c.allowed {
				t.Fatalf("got %+v", got)
			}
		})
	}
}
