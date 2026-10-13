package cli

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/forkcloser/taciturn/internal/agent"
	"github.com/forkcloser/taciturn/internal/enclave"
	"github.com/forkcloser/taciturn/internal/keystore"
	"github.com/forkcloser/taciturn/internal/launchd"
	"github.com/forkcloser/taciturn/internal/protocol"
)

const (
	auditFileMode = fs.FileMode(0o600)
	followPeriod  = 500 * time.Millisecond
	socketMode    = fs.FileMode(0o600)
)

var errDoctor = errors.New("doctor found problems")

// runAgent serves the socket until interrupted. The audit log is the
// agent's only output; a line on stderr says where it is.
func runAgent(ctx context.Context, args []string, stderr io.Writer) error {
	loc, err := resolve()
	if err != nil {
		return err
	}

	set := flagSet("agent", stderr)
	storePath := storeFlag(set, loc)
	socket := set.String("socket", loc.socket, "the socket to serve")
	auditPath := set.String("audit", loc.audit, "the audit log file")

	if err = parse(set, args); err != nil {
		return err
	}

	store, err := openStore(*storePath)
	if err != nil {
		return err
	}

	if err = ensurePrivateDir(filepath.Dir(*socket)); err != nil {
		return err
	}

	audit, err := openAudit(*auditPath)
	if err != nil {
		return err
	}

	defer func() { _ = audit.Close() }()

	logger := slog.New(slog.NewJSONHandler(audit, nil))

	server, err := agent.Listen(*socket, agent.Config{Store: store, Logger: logger})
	if err != nil {
		return fmt.Errorf("agent: %w", err)
	}

	_, _ = fmt.Fprintf(stderr, "taciturn: serving %s, audit log %s\n", *socket, *auditPath)

	logger.InfoContext(ctx, "agent started", "socket", *socket, "store", *storePath)

	if err = server.Serve(ctx); err != nil {
		_ = server.Close()

		return fmt.Errorf("agent: %w", err)
	}

	logger.InfoContext(ctx, "agent stopped")

	if err = server.Close(); err != nil {
		return fmt.Errorf("agent: %w", err)
	}

	return nil
}

// openAudit opens the audit log for appending, private, its directory
// private when it has to be made.
func openAudit(path string) (*os.File, error) {
	if err := os.MkdirAll(filepath.Dir(path), privateDirMode); err != nil {
		return nil, fmt.Errorf("audit log directory: %w", err)
	}

	file, err := os.OpenFile(
		path,
		os.O_WRONLY|os.O_CREATE|os.O_APPEND,
		auditFileMode,
	) // #nosec G304 -- the resolved audit path or the operator's -audit flag
	if err != nil {
		return nil, fmt.Errorf("audit log: %w", err)
	}

	return file, nil
}

// executable is this binary's real path, the one launchd can run.
func executable() (string, error) {
	path, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("own path: %w", err)
	}

	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", fmt.Errorf("own path: %w", err)
	}

	return resolved, nil
}

func runInstall(ctx context.Context, args []string, stdout io.Writer) error {
	set := flagSet("install", stdout)
	if err := parse(set, args); err != nil {
		return err
	}

	loc, err := resolve()
	if err != nil {
		return err
	}

	binary, err := executable()
	if err != nil {
		return err
	}

	paths := launchd.DefaultPaths(loc.home)
	paths.Logs = loc.logs

	if err = launchd.Install(ctx, paths, binary); err != nil {
		return fmt.Errorf("install: %w", err)
	}

	_, _ = fmt.Fprintf(
		stdout,
		"installed %s (%s); socket %s; audit log %s\n",
		launchd.Label,
		binary,
		loc.socket,
		loc.audit,
	)
	_, _ = fmt.Fprintf(stdout, "the sessions' sandbox must allow the socket: %s\n", loc.socket)

	return nil
}

func runUninstall(ctx context.Context, args []string, stdout io.Writer) error {
	set := flagSet("uninstall", stdout)
	if err := parse(set, args); err != nil {
		return err
	}

	loc, err := resolve()
	if err != nil {
		return err
	}

	paths := launchd.DefaultPaths(loc.home)
	paths.Logs = loc.logs

	if err = launchd.Uninstall(ctx, paths); err != nil {
		return fmt.Errorf("uninstall: %w", err)
	}

	_, _ = fmt.Fprintf(stdout, "removed %s; the keys stay in %s\n", launchd.Label, loc.store)

	return nil
}

func runStatus(ctx context.Context, args []string, stdout io.Writer) error {
	loc, err := resolve()
	if err != nil {
		return err
	}

	set := flagSet("status", stdout)
	socket := set.String("socket", loc.socket, "the socket to check")

	if err = parse(set, args); err != nil {
		return err
	}

	status, err := launchd.ReadStatus(ctx)
	if err != nil {
		return fmt.Errorf("status: %w", err)
	}

	_, _ = fmt.Fprintln(stdout, describeStatus(status))
	_, _ = fmt.Fprintln(stdout, describeSocket(*socket))

	return nil
}

func describeStatus(status launchd.Status) string {
	switch {
	case !status.Loaded:
		return launchd.Label + ": not installed"
	case status.Running:
		return fmt.Sprintf("%s: running, pid %d, %s", launchd.Label, status.PID, status.Program)
	default:
		return launchd.Label + ": installed, not running"
	}
}

func describeSocket(path string) string {
	info, err := os.Lstat(path)

	switch {
	case errors.Is(err, fs.ErrNotExist):
		return "socket " + path + ": absent"
	case err != nil:
		return "socket " + path + ": " + err.Error()
	case info.Mode().Type() != fs.ModeSocket:
		return "socket " + path + ": not a socket"
	case info.Mode().Perm() != socketMode:
		return fmt.Sprintf("socket %s: mode %o, not %o", path, info.Mode().Perm(), socketMode)
	default:
		return "socket " + path + ": present, private"
	}
}

// doctor collects findings and counts the failed ones.
type doctor struct {
	out      io.Writer
	problems int
}

func (d *doctor) check(ok bool, line string) {
	mark := "ok  "
	if !ok {
		mark = "FAIL"
		d.problems++
	}

	_, _ = fmt.Fprintf(d.out, "%s %s\n", mark, line)
}

// runDoctor checks everything and reports each finding; the exit code says
// whether all of it is right.
func runDoctor(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	loc, err := resolve()
	if err != nil {
		return report(err, stderr)
	}

	set := flagSet("doctor", stderr)
	storePath := storeFlag(set, loc)
	socket := set.String("socket", loc.socket, "the socket to check")

	if err = parse(set, args); err != nil {
		return report(err, stderr)
	}

	doc := &doctor{out: stdout}

	doc.check(enclave.Available(), "secure enclave reachable from this process")

	store, err := keystore.Open(*storePath)
	doc.check(err == nil, "key store "+*storePath+describeErr(err))

	if store != nil {
		doc.checkKeys(store)
	}

	status, err := launchd.ReadStatus(ctx)
	doc.check(err == nil && status.Running, describeStatus(status)+describeErr(err))

	doc.check(socketPrivate(*socket), describeSocket(*socket))

	if doc.problems > 0 {
		return report(fmt.Errorf("%w: %d", errDoctor, doc.problems), stderr)
	}

	return exitOK
}

func (d *doctor) checkKeys(store *keystore.Store) {
	records, err := store.List()
	d.check(err == nil, fmt.Sprintf("key store readable, %d keys%s", len(records), describeErr(err)))

	for _, record := range records {
		err := checkKey(store, record)
		d.check(err == nil, "key "+record.Name+" "+record.Fingerprint+describeErr(err))
	}
}

func describeErr(err error) string {
	if err == nil {
		return ""
	}

	return ": " + err.Error()
}

// checkKey loads a stored key through the enclave and checks it against
// its public key, without signing.
func checkKey(store *keystore.Store, record keystore.Record) error {
	blob, err := store.Blob(record.Fingerprint)
	if err != nil {
		return storeError(err)
	}

	point, err := protocol.ECDSAP256PublicKeyPoint(record.PublicKey)
	if err != nil {
		return fmt.Errorf("stored public key: %w", err)
	}

	key, err := enclave.Load(blob, point)
	if err != nil {
		return fmt.Errorf("enclave: %w", err)
	}

	key.Close()

	return nil
}

// auditRecord is the shape of a line the agent writes, as far as the log
// command reads it. The keys are the agent's, snake_case as slog's lint
// wants them written.
type auditRecord struct {
	Time    time.Time `json:"time"`
	Message string    `json:"msg"`
	Outcome string    `json:"outcome"`
	Request string    `json:"request"`
	Name    string    `json:"name"`
	Key     string    `json:"key"`
	Rule    string    `json:"rule"`
	Data    string    `json:"data"`
	User    string    `json:"user"`
	Host    string    `json:"host"`
	Peer    string    `json:"peer_path"` //nolint:tagliatelle // the agent's slog key, snake_case by sloglint
}

func runLog(ctx context.Context, args []string, stdout io.Writer) error {
	loc, err := resolve()
	if err != nil {
		return err
	}

	set := flagSet("log", stdout)
	auditPath := set.String("audit", loc.audit, "the audit log file")
	follow := set.Bool("follow", false, "keep reading as the agent writes")
	asJSON := set.Bool("json", false, "print the records as the agent wrote them")
	keyName := set.String("key", "", "only this key's records")

	if err = parse(set, args); err != nil {
		return err
	}

	file, err := os.Open(*auditPath) // #nosec G304 -- the resolved audit path or the operator's -audit flag
	if err != nil {
		return fmt.Errorf("audit log: %w", err)
	}

	defer func() { _ = file.Close() }()

	return tail(ctx, bufio.NewReader(file), stdout, *follow, *asJSON, *keyName)
}

// tail prints the records in the reader and, when following, keeps
// reading what the agent appends until the context ends.
func tail(ctx context.Context, reader *bufio.Reader, stdout io.Writer, follow, asJSON bool, keyName string) error {
	for {
		line, err := reader.ReadString('\n')
		if line != "" {
			printRecord(stdout, strings.TrimRight(line, "\n"), asJSON, keyName)
		}

		if err == nil {
			continue
		}

		if !errors.Is(err, io.EOF) {
			return fmt.Errorf("audit log: %w", err)
		}

		if !follow {
			return nil
		}

		select {
		case <-ctx.Done():
			return nil
		case <-time.After(followPeriod):
		}
	}
}

func printRecord(stdout io.Writer, line string, asJSON bool, keyName string) {
	var record auditRecord
	if err := json.Unmarshal([]byte(line), &record); err != nil {
		// A line that is not a record is shown as it is, unless the reader
		// asked for one key's records, which it is not.
		if keyName == "" {
			_, _ = fmt.Fprintln(stdout, line)
		}

		return
	}

	if keyName != "" && record.Name != keyName {
		return
	}

	if asJSON {
		_, _ = fmt.Fprintln(stdout, line)

		return
	}

	if record.Message != "request" {
		_, _ = fmt.Fprintf(stdout, "%s %s\n", record.Time.Format(time.RFC3339), record.Message)

		return
	}

	fields := []string{record.Time.Format(time.RFC3339), record.Outcome, record.Request}

	for _, field := range []string{record.Name, record.Data, record.User, record.Host, record.Peer} {
		if field != "" {
			fields = append(fields, field)
		}
	}

	if record.Rule != "" {
		fields = append(fields, "-", record.Rule)
	}

	_, _ = fmt.Fprintln(stdout, strings.Join(fields, " "))
}

// socketPrivate says the path is a socket of the agent's mode.
func socketPrivate(path string) bool {
	info, err := os.Lstat(path)
	if err != nil {
		return false
	}

	return info.Mode().Type() == fs.ModeSocket && info.Mode().Perm() == socketMode
}
