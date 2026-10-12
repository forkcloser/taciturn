package protocol

// Identity is one entry of an identities answer: a public key blob and the
// comment ssh-add -L prints after it.
type Identity struct {
	Blob    []byte
	Comment string
}

// Failure is the one answer to anything refused, RFC 9987 section 4.1: the
// client learns nothing but the refusal.
func Failure() Message {
	return Message{Type: TypeFailure}
}

// Success is SSH_AGENT_SUCCESS, the answer to a session-bind the agent
// accepted.
func Success() Message {
	return Message{Type: TypeSuccess}
}

// IdentitiesAnswer encodes SSH_AGENT_IDENTITIES_ANSWER, RFC 9987 section
// 4.4: a count, then each key as blob and comment.
func IdentitiesAnswer(identities []Identity) Message {
	var out builder

	out.putUint32(uint32(len(identities))) // #nosec G115 -- the answer is bounded by MaxMessage on write

	for _, id := range identities {
		out.putBytes(id.Blob)
		out.putString(id.Comment)
	}

	return Message{Type: TypeIdentitiesAnswer, Payload: out.buf}
}

// SignResponse encodes SSH_AGENT_SIGN_RESPONSE, RFC 9987 section 4.5: the
// signature blob as one string.
func SignResponse(signatureBlob []byte) Message {
	var out builder

	out.putBytes(signatureBlob)

	return Message{Type: TypeSignResponse, Payload: out.buf}
}

// ExtensionResponse encodes SSH_AGENT_EXTENSION_RESPONSE for a named
// extension, its contents already encoded.
func ExtensionResponse(name string, contents []byte) Message {
	var out builder

	out.putString(name)
	out.buf = append(out.buf, contents...)

	return Message{Type: TypeExtensionResponse, Payload: out.buf}
}

// QueryResponse answers the "query" extension, RFC 9987 section 4.7.1: the
// extension names the agent supports.
func QueryResponse(supported []string) Message {
	var out builder

	for _, name := range supported {
		out.putString(name)
	}

	return ExtensionResponse(ExtensionQuery, out.buf)
}
