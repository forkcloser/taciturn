package protocol

import "fmt"

// SignRequest is SSH_AGENTC_SIGN_REQUEST, RFC 9987 section 4.5: the public
// key blob naming the key, the data to sign, and flags that mean something
// for RSA only.
type SignRequest struct {
	KeyBlob []byte
	Data    []byte
	Flags   uint32
}

// ParseSignRequest decodes a sign request's payload.
func ParseSignRequest(payload []byte) (SignRequest, error) {
	input := newReader(payload)

	keyBlob, err := input.bytes()
	if err != nil {
		return SignRequest{}, fmt.Errorf("sign request key: %w", err)
	}

	data, err := input.bytes()
	if err != nil {
		return SignRequest{}, fmt.Errorf("sign request data: %w", err)
	}

	flags, err := input.uint32()
	if err != nil {
		return SignRequest{}, fmt.Errorf("sign request flags: %w", err)
	}

	if err := input.done(); err != nil {
		return SignRequest{}, fmt.Errorf("sign request: %w", err)
	}

	return SignRequest{KeyBlob: keyBlob, Data: data, Flags: flags}, nil
}

// The extension names the agent knows, PROTOCOL.agent section 1 and RFC
// 9987 section 4.7.1.
const (
	ExtensionSessionBind = "session-bind@openssh.com"
	ExtensionQuery       = "query"
)

// Extension is SSH_AGENTC_EXTENSION: a name and the bytes after it, whose
// shape the name decides.
type Extension struct {
	Name     string
	Contents []byte
}

// ParseExtension decodes an extension request's payload.
func ParseExtension(payload []byte) (Extension, error) {
	input := newReader(payload)

	name, err := input.string()
	if err != nil {
		return Extension{}, fmt.Errorf("extension name: %w", err)
	}

	contents, err := input.take(input.remaining())
	if err != nil {
		return Extension{}, fmt.Errorf("extension contents: %w", err)
	}

	return Extension{Name: name, Contents: contents}, nil
}

// MaxSessionID bounds a session identifier, as OpenSSH's agent does
// (AGENT_MAX_SID_LEN): an exchange hash is at most 64 bytes.
const MaxSessionID = 128

// SessionBind is the session-bind@openssh.com extension, PROTOCOL.agent
// section 1: the server's host key, the session identifier, the host key's
// signature over it from the key exchange, and whether the connection is
// bound for forwarding rather than authentication.
type SessionBind struct {
	HostKey    []byte
	SessionID  []byte
	Signature  []byte
	Forwarding bool
}

// ParseSessionBind decodes the contents of a session-bind extension.
func ParseSessionBind(contents []byte) (SessionBind, error) {
	input := newReader(contents)

	hostKey, err := input.bytes()
	if err != nil {
		return SessionBind{}, fmt.Errorf("session-bind host key: %w", err)
	}

	sessionID, err := input.bytes()
	if err != nil {
		return SessionBind{}, fmt.Errorf("session-bind session id: %w", err)
	}

	if len(sessionID) > MaxSessionID {
		return SessionBind{}, fmt.Errorf("session id of %d bytes: %w", len(sessionID), ErrTooLarge)
	}

	signature, err := input.bytes()
	if err != nil {
		return SessionBind{}, fmt.Errorf("session-bind signature: %w", err)
	}

	forwarding, err := input.bool()
	if err != nil {
		return SessionBind{}, fmt.Errorf("session-bind forwarding flag: %w", err)
	}

	if err := input.done(); err != nil {
		return SessionBind{}, fmt.Errorf("session-bind: %w", err)
	}

	return SessionBind{HostKey: hostKey, SessionID: sessionID, Signature: signature, Forwarding: forwarding}, nil
}
