// Package cli is the taciturn command: argument parsing, dispatch and
// reporting, behind one entry point the binary calls. It lives here rather
// than in the main package so it is a package like any other, tested from
// outside through Run alone.
package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/mycophonic/primordium/filesystem/dirs"

	"github.com/forkcloser/taciturn/internal/keystore"
	"github.com/forkcloser/taciturn/internal/launchd"
)

// The application's name, for the directories primordium resolves.
const appName = "taciturn"

// The exit codes: 0 done, 1 refused or failed, 2 a usage error.
const (
	exitOK    = 0
	exitError = 1
	exitUsage = 2
)

// errFormat is the uniform "taciturn: <error>" stderr line.
const errFormat = "taciturn: %v\n"

const (
	storeDirName   = "keys"
	socketFileName = "agent.sock"
	auditFileName  = "audit.log"
	privateDirMode = fs.FileMode(0o700)
)

var (
	errUsage = errors.New("usage")
	errHome  = errors.New("no home directory")
)

// locations are where everything lives, resolved once per run from the
// user's home and overridable by flags.
type locations struct {
	home   string
	data   string
	store  string
	socket string
	logs   string
	audit  string
}

// resolve names the default locations without creating any: the
// application's data directory as primordium's dirs would name it on
// macOS, and the LaunchAgent's log directory. A command creates, private,
// what it uses (docs/design.md, "Keys" and "The socket and the process").
func resolve() (locations, error) {
	home := dirs.HomeDir()
	if home == "" {
		return locations{}, errHome
	}

	data := filepath.Join(home, "Library", "Application Support", appName)
	paths := launchd.DefaultPaths(home)

	return locations{
		home:   home,
		data:   data,
		store:  filepath.Join(data, storeDirName),
		socket: filepath.Join(data, socketFileName),
		logs:   paths.Logs,
		audit:  filepath.Join(paths.Logs, auditFileName),
	}, nil
}

// ensurePrivateDir creates a directory, and its parents, private.
func ensurePrivateDir(path string) error {
	if err := os.MkdirAll(path, privateDirMode); err != nil {
		return fmt.Errorf("creating %s: %w", path, err)
	}

	return nil
}

// Run is the taciturn command: args are the arguments after the program
// name, version the build-time stamp, and the result is the process exit
// code.
func Run(version string, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stderr)

		return exitUsage
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var err error

	switch args[0] {
	case "agent":
		err = runAgent(ctx, args[1:], stderr)
	case "install":
		err = runInstall(ctx, args[1:], stdout)
	case "uninstall":
		err = runUninstall(ctx, args[1:], stdout)
	case "status":
		err = runStatus(ctx, args[1:], stdout)
	case "doctor":
		return runDoctor(ctx, args[1:], stdout, stderr)
	case "log":
		err = runLog(ctx, args[1:], stdout)
	case "key":
		err = runKey(args[1:], stdout, stderr)
	case "version", "-v", "--version":
		_, _ = fmt.Fprintln(stdout, "taciturn "+version)

		return exitOK
	case "-h", "--help", "help":
		usage(stdout)

		return exitOK
	default:
		_, _ = fmt.Fprintf(stderr, "taciturn: unknown command %q\n\n", args[0])
		usage(stderr)

		return exitUsage
	}

	return report(err, stderr)
}

// report turns a command's error into the exit code and the stderr line.
func report(err error, stderr io.Writer) int {
	switch {
	case err == nil:
		return exitOK
	case errors.Is(err, errUsage), errors.Is(err, flag.ErrHelp):
		return exitUsage
	default:
		_, _ = fmt.Fprintf(stderr, errFormat, err)

		return exitError
	}
}

func usage(w io.Writer) {
	_, _ = fmt.Fprint(w, `taciturn: an ssh-agent for keys in the Secure Enclave

  taciturn agent                       serve the socket in the foreground (what the LaunchAgent runs)
  taciturn install | uninstall         the user LaunchAgent, `+launchd.Label+`
  taciturn status                      the LaunchAgent and the socket
  taciturn doctor                      the enclave, the store, every key, the agent: one report
  taciturn log [-follow] [-json] [-key NAME]
                                       the audit log

  taciturn key create NAME -use locked|unlocked [-peers any]
  taciturn key list [-format console|json|ssh]
  taciturn key show NAME
  taciturn key allow NAME -user USER -host HOST -known-hosts FILE
  taciturn key disallow NAME -host HOST
  taciturn key sshsig NAME -namespace NS [-remove]
  taciturn key delete NAME -yes
  taciturn key rotate NAME             a successor, served beside NAME@<date>
  taciturn key retire NAME             no longer served; the files stay
  taciturn key signers NAME -principal EMAIL
                                       the allowed-signers line, with its validity window

Every command takes -store DIR and, where it matters, -socket PATH.
`)
}

// flagSet is a flag set that reports usage errors through errUsage and
// prints its defaults to the writer given.
func flagSet(name string, w io.Writer) *flag.FlagSet {
	set := flag.NewFlagSet(name, flag.ContinueOnError)
	set.SetOutput(w)

	return set
}

// storeFlag adds the -store flag with the resolved default.
func storeFlag(set *flag.FlagSet, loc locations) *string {
	return set.String("store", loc.store, "the key store directory")
}

// openStore opens the store at the flag's path.
func openStore(path string) (*keystore.Store, error) {
	store, err := keystore.Open(path)
	if err != nil {
		return nil, fmt.Errorf("key store: %w", err)
	}

	return store, nil
}

// parse parses the flags and maps a parse failure to a usage error; the
// flag package has already printed the message.
func parse(set *flag.FlagSet, args []string) error {
	if err := set.Parse(args); err != nil {
		return fmt.Errorf("%w: %w", errUsage, err)
	}

	return nil
}
