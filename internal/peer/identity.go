package peer

// Process is one entry of a peer's parent chain, for the log.
type Process struct {
	PID  int
	Path string
}

// Identity is what the kernel and the framework say about the peer.
type Identity struct {
	PID int
	// Path is the executable's path as the framework resolves it: for the
	// main executable of a bundle, the bundle's directory.
	Path string
	// Identifier is the code signature's identifier; an ad-hoc signature's
	// is the file's name, and proves nothing.
	Identifier string
	// CDHash is the code directory hash, hex. It and Identifier are read
	// from the code at Path: the build that connected, unless the file was
	// replaced since. They are for the log; a requirement is what decides.
	CDHash string
	// ValidSignature says the code matches its signature.
	ValidSignature bool
	// Parents is the chain above the peer, nearest first, best effort.
	Parents []Process

	code codeHandle
}

// MaxParents bounds the parent chain read for the log.
const MaxParents = 8
