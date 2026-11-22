package agent_test

import (
	"context"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/forkcloser/taciturn/internal/agent"
	"github.com/forkcloser/taciturn/internal/keystore"
	"github.com/forkcloser/taciturn/internal/mallocstat"
	"github.com/forkcloser/taciturn/internal/protocol"
)

// footprint is what a connection could leave behind in the agent's process:
// a goroutine, a descriptor, an object on Go's heap, bytes on C's, where
// Security.framework keeps what it gives for a peer.
type footprint struct {
	goroutines  int
	descriptors int
	objects     uint64
	allocated   uint64
}

// settled is the footprint once the goroutines are back to the count given:
// a connection's goroutine ends after the client has closed, so the count
// is waited for, within a bound, and a goroutine that never ends fails here.
func settled(t *testing.T, goroutines int) footprint {
	t.Helper()

	deadline := time.Now().Add(10 * time.Second)
	for runtime.NumGoroutine() > goroutines {
		if time.Now().After(deadline) {
			t.Fatalf("%d goroutines, %d before the connections", runtime.NumGoroutine(), goroutines)
		}

		time.Sleep(time.Millisecond)
	}

	// More than once: what a collection finds unreachable through a
	// finalizer is freed by the next.
	for range 3 {
		//revive:disable-next-line:call-to-gc // the count is of what survives a collection
		runtime.GC()
	}

	var stats runtime.MemStats

	runtime.ReadMemStats(&stats)

	open, err := os.ReadDir("/dev/fd")
	if err != nil {
		t.Fatal(err)
	}

	// A build without cgo cannot ask C's allocator, and has nothing there to
	// leak.
	allocated, _ := mallocstat.Bytes()

	return footprint{
		goroutines: runtime.NumGoroutine(), descriptors: len(open), objects: stats.HeapObjects, allocated: allocated,
	}
}

// The agent lives for weeks and serves a connection per ssh and per
// signature: a connection leaves nothing behind. After the connections that
// warm the process up, four thousand more leave the same goroutines and the
// same descriptors, and less than the least a leak could be: on Go's heap,
// fewer live objects than one a connection; on C's, fewer bytes than the
// allocator's smallest block a connection (the reference to a peer's code
// alone, left unreleased, is tens of kilobytes and a descriptor a connection).
//
// Go's heap is counted in objects, not bytes: the runtime keeps the
// descriptors of the goroutines it has run, a few hundred bytes each, ever
// fewer of them as its pool fills (some 120 over two thousand connections,
// 700 over thirty-two thousand), which is more than a word a connection and
// far from an object a connection. C's is counted in bytes, not blocks: on
// macOS 15 the allocator's count of blocks in use only rises.
//
// C's bytes are not still either. What the allocator and the framework keep
// for themselves moves by tens of kilobytes over four thousand connections,
// up and down on macOS 15, up and ever less on macOS 26 and 27, where a
// window has come within a tenth of the bound (58 KiB of 62.5). So a window
// under the bound ends the test, one four times over it fails it, and one
// between the two is told from a leak by the next: a leak leaves as much
// behind every window, the settling does not, and three windows over the
// bound are a leak.
//
// What that holds: where the allocator is still, one smallest block kept a
// connection fails the test. Where its own bytes fall in a window, by up to
// 23 KiB on macOS 15, the fall hides as much of a leak in that window, which
// then ends the test: there it is two smallest blocks a connection, 32
// bytes, that fail it whatever the allocator does.
func TestConnectionsLeaveNothingBehind(t *testing.T) { //nolint:paralleltest // it counts the process's own
	requirePeerIdentity(t)

	const (
		warmUp  = 1000
		rounds  = 4000
		windows = 3
		// The allocator's quantum, its smallest block.
		smallest = 16
		// A window that leaves this much a connection is not the settling.
		plain = 4 * smallest
	)

	dir := shortDir(t)

	store, err := keystore.Open(filepath.Join(dir, "keys"))
	if err != nil {
		t.Fatal(err)
	}

	h := newHost(t)
	record := botKey(t, "bot", github(h))

	if err = store.Create(record); err != nil {
		t.Fatal(err)
	}

	socket := filepath.Join(dir, "a.sock")

	// The log is discarded: a journal kept in memory would be the growth.
	server, err := agent.Listen(socket, agent.Config{Store: store, Logger: slog.New(slog.DiscardHandler)})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)

	go func() { done <- server.Serve(ctx) }()

	t.Cleanup(func() {
		cancel()

		if err := <-done; err != nil {
			t.Errorf("Serve: %v", err)
		}

		_ = server.Close()
	})

	bind := h.bind(t, sessionID(), false)
	unknown := botKey(t, "unknown", github(h))

	// One connection: a listing, a signature refused, a binding, a listing
	// on the binding, then the client goes.
	round := func() {
		conn, err := net.Dial("unix", socket)
		if err != nil {
			t.Fatal(err)
		}

		client := wire{conn}

		client.ask(t, protocol.TypeRequestIdentities, nil)
		client.sign(t, unknown.PublicKey, sshsig("git"))
		client.extension(t, protocol.ExtensionSessionBind, bind)
		client.ask(t, protocol.TypeRequestIdentities, nil)

		if err = conn.Close(); err != nil {
			t.Fatal(err)
		}
	}

	idle := runtime.NumGoroutine()

	for range warmUp {
		round()
	}

	before := settled(t, idle)

	for window := 1; ; window++ {
		for range rounds {
			round()
		}

		after := settled(t, idle)

		t.Logf("window %d: before %+v, after %+v", window, before, after)

		if after.goroutines != before.goroutines || after.descriptors != before.descriptors {
			t.Fatalf("%d connections left goroutines or descriptors: before %+v, after %+v", rounds, before, after)
		}

		if after.objects >= before.objects+rounds {
			t.Fatalf("%d connections left objects on Go's heap: before %+v, after %+v", rounds, before, after)
		}

		switch {
		case after.allocated < before.allocated+rounds*smallest:
			return
		case after.allocated >= before.allocated+rounds*plain, window == windows:
			t.Fatalf("%d connections left bytes on C's heap, window %d: before %+v, after %+v",
				rounds, window, before, after)
		}

		before = after
	}
}
