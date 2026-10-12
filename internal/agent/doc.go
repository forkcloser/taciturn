// Package agent is the ssh-agent: a unix socket the sessions' ssh and
// ssh-keygen connect to, answered from the key store and the enclave
// within the policy.
//
// Listen takes the socket; Serve accepts connections until the context
// ends. Each connection is identified by its peer (package peer; a peer of
// another user is closed at once), carries its own binding state (package
// policy), reads one framed request at a time within an idle deadline
// (package protocol), and answers:
//
//   - request-identities: the keys the policy lists to this connection;
//   - sign-request: the signature, when the policy allows it, made by the
//     enclave with the key loaded from its blob and checked against its
//     public key first;
//   - extension session-bind@openssh.com: recorded once the host key's
//     signature over the session identifier verifies; a second binding
//     that is not the same, or one that does not verify, refuses and marks
//     the connection, which then sees no key;
//   - extension query: the one extension supported;
//   - everything else, add, remove, lock and the rest: failure.
//
// Every request writes one audit record through the logger: the peer, the
// request, the key, the destination, and the rule that decided. A refusal
// tells the client nothing but SSH_AGENT_FAILURE.
//
// Limits: a message is bounded by package protocol; a connection that
// sends nothing for IdleTimeout is closed; at most MaxConnections are
// served at once, the rest wait in the listen backlog.
package agent
