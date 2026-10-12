package protocol

import (
	"fmt"
)

// The constants a public-key user-authentication request carries, RFC 4252
// section 7: the message number, the service and the method.
const (
	msgUserauthRequest   = 50
	userauthService      = "ssh-connection"
	userauthMethodPubkey = "publickey"
)

// UserauthRequest is the data a client asks to have signed for public-key
// authentication, RFC 4252 section 7: the session identifier of the
// connection, then the SSH_MSG_USERAUTH_REQUEST it will send. The session
// identifier is what ties the signature to one server; the user is who the
// client claims to be there; the key blob is the key it will present.
type UserauthRequest struct {
	SessionID          []byte
	User               string
	PublicKeyAlgorithm string
	KeyBlob            []byte
}

// ParseUserauthRequest decodes signed data as a user-authentication request.
// Data of any other shape, a wrong message number, a service other than
// ssh-connection, a method other than publickey, a signature flag that is
// not set, an empty session identifier, is ErrInvalid.
func ParseUserauthRequest(data []byte) (UserauthRequest, error) {
	input := newReader(data)

	sessionID, err := input.bytes()
	if err != nil {
		return UserauthRequest{}, fmt.Errorf("userauth session id: %w", err)
	}

	if len(sessionID) == 0 {
		return UserauthRequest{}, fmt.Errorf("empty userauth session id: %w", ErrInvalid)
	}

	msg, err := input.byte()
	if err != nil {
		return UserauthRequest{}, fmt.Errorf("userauth message number: %w", err)
	}

	if msg != msgUserauthRequest {
		return UserauthRequest{}, fmt.Errorf("message number %d is not a userauth request: %w", msg, ErrInvalid)
	}

	user, err := input.string()
	if err != nil {
		return UserauthRequest{}, fmt.Errorf("userauth user: %w", err)
	}

	service, err := input.string()
	if err != nil {
		return UserauthRequest{}, fmt.Errorf("userauth service: %w", err)
	}

	if service != userauthService {
		return UserauthRequest{}, fmt.Errorf("userauth service %q: %w", service, ErrInvalid)
	}

	method, err := input.string()
	if err != nil {
		return UserauthRequest{}, fmt.Errorf("userauth method: %w", err)
	}

	if method != userauthMethodPubkey {
		return UserauthRequest{}, fmt.Errorf("userauth method %q: %w", method, ErrInvalid)
	}

	signatureFollows, err := input.bool()
	if err != nil {
		return UserauthRequest{}, fmt.Errorf("userauth signature flag: %w", err)
	}

	if !signatureFollows {
		return UserauthRequest{}, fmt.Errorf("userauth request without a signature: %w", ErrInvalid)
	}

	algorithm, err := input.string()
	if err != nil {
		return UserauthRequest{}, fmt.Errorf("userauth algorithm: %w", err)
	}

	keyBlob, err := input.bytes()
	if err != nil {
		return UserauthRequest{}, fmt.Errorf("userauth key: %w", err)
	}

	if err := input.done(); err != nil {
		return UserauthRequest{}, fmt.Errorf("userauth request: %w", err)
	}

	return UserauthRequest{SessionID: sessionID, User: user, PublicKeyAlgorithm: algorithm, KeyBlob: keyBlob}, nil
}

// sshsigMagic opens the data ssh-keygen -Y sign asks to have signed,
// PROTOCOL.sshsig "Signed data".
const sshsigMagic = "SSHSIG"

// SSHSigRequest is the data a client asks to have signed for an SSHSIG
// signature: the namespace the signature is for ("git" for a commit), the
// hash algorithm, and the hash of the message.
type SSHSigRequest struct {
	Namespace     string
	HashAlgorithm string
	Hash          []byte
}

// ParseSSHSigRequest decodes signed data as an SSHSIG request. The magic,
// the namespace, an empty reserved string, the hash algorithm and the hash;
// anything else is ErrInvalid.
func ParseSSHSigRequest(data []byte) (SSHSigRequest, error) {
	input := newReader(data)

	magic, err := input.take(len(sshsigMagic))
	if err != nil {
		return SSHSigRequest{}, fmt.Errorf("sshsig magic: %w", err)
	}

	if string(magic) != sshsigMagic {
		return SSHSigRequest{}, fmt.Errorf("sshsig magic %q: %w", magic, ErrInvalid)
	}

	namespace, err := input.string()
	if err != nil {
		return SSHSigRequest{}, fmt.Errorf("sshsig namespace: %w", err)
	}

	reserved, err := input.bytes()
	if err != nil {
		return SSHSigRequest{}, fmt.Errorf("sshsig reserved: %w", err)
	}

	if len(reserved) != 0 {
		return SSHSigRequest{}, fmt.Errorf("sshsig reserved field of %d bytes: %w", len(reserved), ErrInvalid)
	}

	hashAlgorithm, err := input.string()
	if err != nil {
		return SSHSigRequest{}, fmt.Errorf("sshsig hash algorithm: %w", err)
	}

	hash, err := input.bytes()
	if err != nil {
		return SSHSigRequest{}, fmt.Errorf("sshsig hash: %w", err)
	}

	if err := input.done(); err != nil {
		return SSHSigRequest{}, fmt.Errorf("sshsig request: %w", err)
	}

	return SSHSigRequest{Namespace: namespace, HashAlgorithm: hashAlgorithm, Hash: hash}, nil
}
