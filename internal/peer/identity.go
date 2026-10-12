package peer

// Process is one entry of a peer's parent chain, for the log.
type Process struct {
	PID  int    `json:"pid"`
	Path string `json:"path,omitempty"`
}

// Identity is what the kernel and the framework say about the peer.
type Identity struct {
	PID int    `json:"pid"`
	UID uint32 `json:"uid"`
	// Path is the executable's path as the framework resolves it.
	Path string `json:"path"`
	// Identifier is the code signature's identifier; an ad-hoc signature's
	// is the file's name, and proves nothing.
	Identifier string `json:"identifier,omitempty"`
	// CDHash is the code directory hash, hex: the build that connected.
	CDHash string `json:"cdhash,omitempty"`
	// ValidSignature says the code matches its signature.
	ValidSignature bool `json:"validSignature"`
	// Parents is the chain above the peer, nearest first, best effort.
	Parents []Process `json:"parents,omitempty"`

	code codeHandle
}

// MaxParents bounds the parent chain read for the log.
const MaxParents = 8
