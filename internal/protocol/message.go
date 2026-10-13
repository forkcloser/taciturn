package protocol

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// Type is the first byte of a message, RFC 9987 section 5.1 and OpenSSH's
// authfd.h. Every number a client could send is named, so the log can say
// what was refused; the agent answers three of them.
type Type byte

// The message numbers. Request numbers are the client's, answer numbers
// the agent's.
const (
	TypeFailure                 Type = 5
	TypeSuccess                 Type = 6
	TypeRequestIdentities       Type = 11
	TypeIdentitiesAnswer        Type = 12
	TypeSignRequest             Type = 13
	TypeSignResponse            Type = 14
	TypeAddIdentity             Type = 17
	TypeRemoveIdentity          Type = 18
	TypeRemoveAllIdentities     Type = 19
	TypeAddSmartcardKey         Type = 20
	TypeRemoveSmartcardKey      Type = 21
	TypeLock                    Type = 22
	TypeUnlock                  Type = 23
	TypeAddIDConstrained        Type = 25
	TypeAddSmartcardConstrained Type = 26
	TypeExtension               Type = 27
	TypeExtensionFailure        Type = 28
	TypeExtensionResponse       Type = 29
)

// String names a known type and numbers an unknown one.
func (t Type) String() string {
	switch t {
	case TypeFailure:
		return "failure"
	case TypeSuccess:
		return "success"
	case TypeRequestIdentities:
		return "request-identities"
	case TypeIdentitiesAnswer:
		return "identities-answer"
	case TypeSignRequest:
		return "sign-request"
	case TypeSignResponse:
		return "sign-response"
	case TypeAddIdentity:
		return "add-identity"
	case TypeRemoveIdentity:
		return "remove-identity"
	case TypeRemoveAllIdentities:
		return "remove-all-identities"
	case TypeAddSmartcardKey:
		return "add-smartcard-key"
	case TypeRemoveSmartcardKey:
		return "remove-smartcard-key"
	case TypeLock:
		return "lock"
	case TypeUnlock:
		return "unlock"
	case TypeAddIDConstrained:
		return "add-identity-constrained"
	case TypeAddSmartcardConstrained:
		return "add-smartcard-key-constrained"
	case TypeExtension:
		return "extension"
	case TypeExtensionFailure:
		return "extension-failure"
	case TypeExtensionResponse:
		return "extension-response"
	default:
		return fmt.Sprintf("type-%d", byte(t))
	}
}

// MaxMessage bounds a message, type byte included, on both directions.
// OpenSSH's agent allows 256 KiB; an identities answer for a handful of
// P-256 keys is a few hundred bytes and a sign request a few hundred more.
const MaxMessage = 64 * 1024

// Message is one framed agent message: its type and the bytes after it.
type Message struct {
	Type    Type
	Payload []byte
}

// ReadMessage reads one framed message, RFC 9987 section 3: a uint32
// length, then that many bytes of which the first is the type. A length of
// zero is ErrInvalid, one over MaxMessage is ErrTooLarge, and a stream that
// ends inside a frame is io.ErrUnexpectedEOF, from the transport, never
// reclassified. The payload is the message's own copy.
func ReadMessage(r io.Reader) (Message, error) {
	var head [uint32Size]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return Message{}, fmt.Errorf("reading message length: %w", err)
	}

	length := binary.BigEndian.Uint32(head[:])
	if length == 0 {
		return Message{}, fmt.Errorf("empty message: %w", ErrInvalid)
	}

	if length > MaxMessage {
		return Message{}, fmt.Errorf("message of %d bytes: %w", length, ErrTooLarge)
	}

	body := make([]byte, length)
	if _, err := io.ReadFull(r, body); err != nil {
		// A stream that ends right after the length is still inside the
		// frame; ReadFull says plain EOF when it got nothing.
		if errors.Is(err, io.EOF) {
			err = io.ErrUnexpectedEOF
		}

		return Message{}, fmt.Errorf("reading message body: %w", err)
	}

	return Message{Type: Type(body[0]), Payload: body[1:]}, nil
}

// WriteTo frames the message and writes it in one call.
func (m Message) WriteTo(w io.Writer) (int64, error) {
	length := byteSize + len(m.Payload)
	if length > MaxMessage {
		return 0, fmt.Errorf("message of %d bytes: %w", length, ErrTooLarge)
	}

	frame := make([]byte, 0, uint32Size+length)
	frame = binary.BigEndian.AppendUint32(frame, uint32(length)) // #nosec G115 -- bounded by MaxMessage just above
	frame = append(frame, byte(m.Type))
	frame = append(frame, m.Payload...)

	n, err := w.Write(frame)
	if err != nil {
		return int64(n), fmt.Errorf("writing message: %w", err)
	}

	return int64(n), nil
}
