package agent

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/forkcloser/taciturn/internal/enclave"
	"github.com/forkcloser/taciturn/internal/keystore"
	"github.com/forkcloser/taciturn/internal/peer"
	"github.com/forkcloser/taciturn/internal/policy"
	"github.com/forkcloser/taciturn/internal/protocol"
)

var (
	errKeyRetired = errors.New("key retired")
	errKeyUnknown = errors.New("key unknown")
)

// The audit record's attribute for the shape of signed data.
const attrData = "data"

// connection is one client, from accept to close.
type connection struct {
	server   *Server
	conn     *net.UnixConn
	identity *peer.Identity
	state    policy.Connection
	log      *slog.Logger
}

func (s *Server) handleConnection(conn *net.UnixConn) {
	defer func() { _ = conn.Close() }()

	log := s.config.Logger.With("connection", s.next.Add(1))

	identity, err := peer.Identify(conn)
	if err != nil {
		log.Warn("connection refused", "reason", err.Error())

		return
	}

	defer identity.Close()

	log = log.With(
		"peer_pid", identity.PID,
		"peer_path", identity.Path,
		"peer_identifier", identity.Identifier,
		"peer_cdhash", identity.CDHash,
		"peer_signed", identity.ValidSignature,
		"peer_parents", parentChain(identity.Parents),
	)

	client := &connection{
		server:   s,
		conn:     conn,
		identity: identity,
		state:    policy.Connection{Peer: policy.Peer{Path: identity.Path}},
		log:      log,
	}

	log.Debug("connection open")

	client.loop()

	log.Debug("connection closed")
}

func parentChain(parents []peer.Process) string {
	parts := make([]string, 0, len(parents))

	for _, process := range parents {
		if process.Path == "" {
			parts = append(parts, strconv.Itoa(process.PID))

			continue
		}

		parts = append(parts, strconv.Itoa(process.PID)+":"+process.Path)
	}

	return strings.Join(parts, " < ")
}

// loop reads requests until the client goes away, the deadline passes or
// a message cannot be read.
func (c *connection) loop() {
	for {
		if err := c.conn.SetReadDeadline(time.Now().Add(c.server.config.IdleTimeout)); err != nil {
			return
		}

		msg, err := protocol.ReadMessage(c.conn)
		if err != nil {
			if !errors.Is(err, io.EOF) {
				c.log.Info("request unreadable", "reason", err.Error())
			}

			return
		}

		response := c.handle(msg)

		if err := c.conn.SetWriteDeadline(time.Now().Add(c.server.config.IdleTimeout)); err != nil {
			return
		}

		if _, err := response.WriteTo(c.conn); err != nil {
			c.log.Info("response unwritable", "reason", err.Error())

			return
		}
	}
}

// handle answers one request: the three the agent serves, failure for the
// rest.
func (c *connection) handle(msg protocol.Message) protocol.Message {
	if msg.Type == protocol.TypeRequestIdentities {
		return c.identities()
	}

	if msg.Type == protocol.TypeSignRequest {
		return c.sign(msg.Payload)
	}

	if msg.Type == protocol.TypeExtension {
		return c.extension(msg.Payload)
	}

	c.audit("refuse", "request", msg.Type.String(), "rule", "request type not served")

	return protocol.Failure()
}

// audit writes the one record a request leaves.
func (c *connection) audit(outcome string, attrs ...any) {
	c.log.Info("request", append([]any{"outcome", outcome, "bound", c.boundTo()}, attrs...)...)
}

// boundTo names the connection's binding for the log.
func (c *connection) boundTo() string {
	switch {
	case c.state.BindRefused:
		return "refused"
	case !c.state.Bound:
		return "none"
	case c.state.Forwarding:
		return "forwarding " + protocol.Fingerprint(c.state.HostKey)
	default:
		return "auth " + protocol.Fingerprint(c.state.HostKey)
	}
}

func (c *connection) identities() protocol.Message {
	records, err := c.server.config.Store.List()
	if err != nil {
		c.audit("refuse", "request", "identities", "rule", "key store unreadable", "error", err.Error())

		return protocol.Failure()
	}

	var listed []protocol.Identity

	hidden := 0

	for _, record := range records {
		if record.Retired != nil {
			continue
		}

		if decision := policy.Visible(c.state, record.Policy); !decision.Allowed {
			hidden++

			continue
		}

		listed = append(listed, protocol.Identity{Blob: record.PublicKey, Comment: record.Name})
	}

	c.audit("allow", "request", "identities", "listed", len(listed), "hidden", hidden)

	return protocol.IdentitiesAnswer(listed)
}

func (c *connection) sign(payload []byte) protocol.Message {
	request, err := protocol.ParseSignRequest(payload)
	if err != nil {
		c.audit("refuse", "request", "sign", "rule", "malformed sign request")

		return protocol.Failure()
	}

	record, err := c.findKey(request.KeyBlob)
	if err != nil {
		c.audit("refuse", "request", "sign", "rule", err.Error(), "key", protocol.Fingerprint(request.KeyBlob))

		return protocol.Failure()
	}

	c.state.Peer.Satisfied = c.satisfied(record.Policy.Peers)

	decision := policy.Sign(c.state, record.Policy, record.PublicKey, request.Data)
	attrs := []any{"request", "sign", "key", record.Fingerprint, "name", record.Name, "rule", decision.Rule}
	attrs = append(attrs, describe(request.Data)...)

	if !decision.Allowed {
		c.audit("refuse", attrs...)

		return protocol.Failure()
	}

	signature, err := signWithEnclave(record, request.Data)
	if err != nil {
		c.audit("refuse", append(attrs, "error", err.Error())...)

		return protocol.Failure()
	}

	c.audit("allow", attrs...)

	return protocol.SignResponse(signature)
}

// findKey is the live record whose public key is blob.
func (c *connection) findKey(blob []byte) (keystore.Record, error) {
	records, err := c.server.config.Store.List()
	if err != nil {
		return keystore.Record{}, fmt.Errorf("key store unreadable: %w", err)
	}

	for _, record := range records {
		if bytes.Equal(record.PublicKey, blob) {
			if record.Retired != nil {
				return keystore.Record{}, errKeyRetired
			}

			return record, nil
		}
	}

	return keystore.Record{}, errKeyUnknown
}

// satisfied evaluates the policy's code-signing requirements on the peer:
// every entry that is neither "any" nor a path pattern.
func (c *connection) satisfied(entries []string) []string {
	var out []string

	for _, entry := range entries {
		if entry == policy.PeerAny || strings.HasPrefix(entry, policy.PeerPathPrefix) {
			continue
		}

		ok, err := c.identity.Satisfies(entry)
		if err != nil {
			c.log.Warn("requirement not evaluated", "requirement", entry, "reason", err.Error())

			continue
		}

		if ok {
			out = append(out, entry)
		}
	}

	return out
}

// describe names what the data to sign is, for the log.
func describe(data []byte) []any {
	if req, err := protocol.ParseUserauthRequest(data); err == nil {
		return []any{attrData, "userauth", "user", req.User}
	}

	if req, err := protocol.ParseSSHSigRequest(data); err == nil {
		return []any{attrData, "sshsig", "namespace", req.Namespace}
	}

	return []any{attrData, "other"}
}

// signWithEnclave loads the key from the keychain by its fingerprint,
// checks it against the record's public key, and signs.
func signWithEnclave(record keystore.Record, data []byte) ([]byte, error) {
	point, err := protocol.ECDSAP256PublicKeyPoint(record.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("stored public key: %w", err)
	}

	key, err := enclave.Load(record.Fingerprint, point)
	if err != nil {
		return nil, fmt.Errorf("loading key from the keychain: %w", err)
	}

	defer key.Close()

	sigR, sigS, err := key.Sign(data)
	if err != nil {
		return nil, fmt.Errorf("enclave: %w", err)
	}

	signature, err := protocol.ECDSAP256Signature(sigR, sigS)
	if err != nil {
		return nil, fmt.Errorf("encoding signature: %w", err)
	}

	return signature, nil
}

func (c *connection) extension(payload []byte) protocol.Message {
	ext, err := protocol.ParseExtension(payload)
	if err != nil {
		c.audit("refuse", "request", "extension", "rule", "malformed extension")

		return protocol.Failure()
	}

	switch ext.Name {
	case protocol.ExtensionQuery:
		c.audit("allow", "request", "extension", "extension", ext.Name)

		return protocol.QueryResponse([]string{protocol.ExtensionSessionBind})
	case protocol.ExtensionSessionBind:
		return c.bind(ext.Contents)
	default:
		c.audit("refuse", "request", "extension", "extension", ext.Name, "rule", "extension not supported")

		return protocol.Failure()
	}
}

// bind records the session binding once the host key's proof verifies.
func (c *connection) bind(contents []byte) protocol.Message {
	bind, err := protocol.ParseSessionBind(contents)
	if err != nil {
		return c.refuseBind("malformed session-bind", "")
	}

	hostKey := protocol.Fingerprint(bind.HostKey)

	if c.state.Bound {
		same := bytes.Equal(c.state.HostKey, bind.HostKey) &&
			bytes.Equal(c.state.SessionID, bind.SessionID) &&
			c.state.Forwarding == bind.Forwarding

		if same {
			c.audit("allow", "request", "session-bind", "host", hostKey, "rule", "binding already recorded")

			return protocol.Success()
		}

		return c.refuseBind("connection already bound", hostKey)
	}

	if c.state.BindRefused {
		return c.refuseBind("an earlier binding was refused", hostKey)
	}

	public, err := ssh.ParsePublicKey(bind.HostKey)
	if err != nil {
		return c.refuseBind("host key unparseable", hostKey)
	}

	var signature ssh.Signature
	if err := ssh.Unmarshal(bind.Signature, &signature); err != nil {
		return c.refuseBind("host key signature unparseable", hostKey)
	}

	if err := public.Verify(bind.SessionID, &signature); err != nil {
		return c.refuseBind("host key signature does not verify", hostKey)
	}

	c.state.Bound = true
	c.state.Forwarding = bind.Forwarding
	c.state.HostKey = append([]byte(nil), bind.HostKey...)
	c.state.SessionID = append([]byte(nil), bind.SessionID...)

	c.audit(
		"allow",
		"request",
		"session-bind",
		"host",
		hostKey,
		"forwarding",
		bind.Forwarding,
		"rule",
		"host key proof verified",
	)

	return protocol.Success()
}

func (c *connection) refuseBind(rule, hostKey string) protocol.Message {
	c.state.BindRefused = true
	c.audit("refuse", "request", "session-bind", "host", hostKey, "rule", rule)

	return protocol.Failure()
}
