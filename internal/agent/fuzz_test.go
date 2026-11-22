package agent_test

import (
	"bytes"
	"errors"
	"io"
	"net"
	"slices"
	"testing"
	"time"

	"github.com/forkcloser/taciturn/internal/protocol"
)

// Past the bound: the socket takes bytes from any process of the user.
// Whatever a connection sends, the agent answers each frame it can read
// with one of its own answers, never a signature here, where no enclave
// holds the store's key; it closes a connection it cannot read; and it
// still serves the next client.
func FuzzConnection(f *testing.F) {
	frame := func(kind protocol.Type, payload []byte) []byte {
		var out bytes.Buffer

		if _, err := (protocol.Message{Type: kind, Payload: payload}).WriteTo(&out); err != nil {
			f.Fatal(err)
		}

		return out.Bytes()
	}

	f.Add(frame(protocol.TypeRequestIdentities, nil))
	f.Add(frame(protocol.TypeSignRequest, []byte{0}))
	f.Add(frame(protocol.TypeExtension, []byte{0, 0, 0, 5, 'q', 'u', 'e', 'r', 'y'}))
	f.Add(bytes.Repeat(frame(protocol.TypeRequestIdentities, nil), 3))
	f.Add(frame(protocol.TypeRemoveAllIdentities, nil))
	f.Add([]byte{0, 0, 0, 0})
	f.Add([]byte{0xff, 0xff, 0xff, 0xff, 13})
	f.Add([]byte{0, 0, 0, 9, 13, 1})
	f.Add([]byte{})

	// What the agent answers with, and nothing else.
	answers := []protocol.Type{
		protocol.TypeFailure, protocol.TypeSuccess, protocol.TypeIdentitiesAnswer, protocol.TypeExtensionResponse,
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		requirePeerIdentity(t)

		r := start(t)

		if err := r.store.Create(botKey(t, "bot", github(newHost(t)))); err != nil {
			t.Fatal(err)
		}

		conn, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: r.socket, Net: "unix"})
		if err != nil {
			t.Fatal(err)
		}

		defer func() { _ = conn.Close() }()

		if err = conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
			t.Fatal(err)
		}

		// Written while the answers are read: an agent that answers many
		// frames must not wait on a client that has not started reading.
		go func() {
			_, _ = conn.Write(data)
			_ = conn.CloseWrite()
		}()

		// Every answer is a frame of the agent's, to the end of the stream:
		// the agent closes once it has read the client's last frame, or the
		// first it cannot read.
		for {
			answer, readErr := protocol.ReadMessage(conn)
			if errors.Is(readErr, io.EOF) {
				break
			}

			if readErr != nil {
				t.Fatalf("the agent's answers do not end in whole frames: %v", readErr)
			}

			if !slices.Contains(answers, answer.Type) {
				t.Fatalf("the agent answered %s", answer.Type)
			}
		}

		keys, err := r.client(t).List()
		if err != nil || len(keys) != 1 {
			t.Fatalf("the agent after this connection: %d keys, %v", len(keys), err)
		}
	})
}
