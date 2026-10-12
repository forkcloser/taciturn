package agent

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mycophonic/primordium/filesystem/flock"
	"github.com/mycophonic/primordium/filesystem/pathcheck"

	"github.com/forkcloser/taciturn/internal/keystore"
)

// Config is what the agent serves with.
type Config struct {
	// Store holds the keys; required.
	Store *keystore.Store
	// Logger receives the audit records and the diagnostics; nil means
	// slog's default.
	Logger *slog.Logger
	// IdleTimeout closes a connection that sends nothing for that long;
	// zero means DefaultIdleTimeout.
	IdleTimeout time.Duration
	// MaxConnections bounds the connections served at once; zero means
	// DefaultMaxConnections.
	MaxConnections int
}

// The defaults.
const (
	DefaultIdleTimeout    = 10 * time.Second
	DefaultMaxConnections = 64

	socketMode fs.FileMode = 0o600
	lockSuffix             = ".lock"
)

// Server is a listening agent.
type Server struct {
	config   Config
	listener *net.UnixListener
	lock     *os.File
	slots    chan struct{}
	wg       sync.WaitGroup
	next     atomic.Uint64
}

// Listen takes the socket at path: a stale socket file is removed, a path
// that is something else is ErrInvalid, a socket another agent holds (the
// lock file beside it) is ErrBusy. The socket is created private.
func Listen(path string, config Config) (*Server, error) {
	if config.Store == nil {
		return nil, fmt.Errorf("no key store: %w", ErrInvalid)
	}

	if err := pathcheck.ValidateSocket(path); err != nil {
		return nil, fmt.Errorf("socket path: %w", errors.Join(ErrInvalid, err))
	}

	if config.Logger == nil {
		config.Logger = slog.Default()
	}

	if config.IdleTimeout <= 0 {
		config.IdleTimeout = DefaultIdleTimeout
	}

	if config.MaxConnections <= 0 {
		config.MaxConnections = DefaultMaxConnections
	}

	// The lock file must exist for the advisory lock to be taken on it.
	lockFile, err := os.OpenFile(
		path+lockSuffix,
		os.O_RDONLY|os.O_CREATE,
		socketMode,
	) // #nosec G304 -- the validated socket path and a fixed suffix
	if err != nil {
		return nil, fmt.Errorf("agent lock file: %w", err)
	}

	if err = lockFile.Close(); err != nil {
		return nil, fmt.Errorf("agent lock file: %w", err)
	}

	lock, err := flock.TryLock(path + lockSuffix)
	if err != nil {
		return nil, fmt.Errorf("agent lock %s: %w", path+lockSuffix, ErrBusy)
	}

	if err = removeStaleSocket(path); err != nil {
		_ = flock.Unlock(lock)

		return nil, err
	}

	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		_ = flock.Unlock(lock)

		return nil, fmt.Errorf("listening on %s: %w", path, err)
	}

	// The directory is private already; the socket is made private too,
	// after creation, since the listener honours the umask.
	if err := os.Chmod(path, socketMode); err != nil {
		_ = listener.Close()
		_ = flock.Unlock(lock)

		return nil, fmt.Errorf("securing %s: %w", path, err)
	}

	listener.SetUnlinkOnClose(true)

	return &Server{
		config:   config,
		listener: listener,
		lock:     lock,
		slots:    make(chan struct{}, config.MaxConnections),
	}, nil
}

// removeStaleSocket unlinks a socket file left by an earlier agent; a
// path that exists and is not a socket is ErrInvalid.
func removeStaleSocket(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}

	if err != nil {
		return fmt.Errorf("socket path: %w", err)
	}

	if info.Mode().Type() != fs.ModeSocket {
		return fmt.Errorf("%s exists and is not a socket: %w", path, ErrInvalid)
	}

	if err := os.Remove(path); err != nil {
		return fmt.Errorf("removing stale socket: %w", err)
	}

	return nil
}

// Serve accepts connections until the context ends or the listener is
// closed, then waits for the connections in flight. It returns nil on a
// clean stop.
func (s *Server) Serve(ctx context.Context) error {
	stop := context.AfterFunc(ctx, func() { _ = s.listener.Close() })
	defer stop()

	for {
		conn, err := s.listener.AcceptUnix()
		if err != nil {
			s.wg.Wait()

			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}

			return fmt.Errorf("accept: %w", err)
		}

		s.slots <- struct{}{}

		s.wg.Go(func() {
			defer func() { <-s.slots }()

			s.handleConnection(conn)
		})
	}
}

// Close stops the listener, unlinks the socket and releases the lock.
// Connections in flight finish on their own.
func (s *Server) Close() error {
	err := s.listener.Close()

	if unlockErr := flock.Unlock(s.lock); unlockErr != nil && err == nil {
		err = unlockErr
	}

	if err != nil {
		return fmt.Errorf("closing agent: %w", err)
	}

	return nil
}
