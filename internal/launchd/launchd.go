package launchd

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/mycophonic/primordium/filesystem"
)

// Label is the LaunchAgent's name in launchd.
const Label = "org.forkcloser.taciturn"

var (
	// ErrInvalid is a path the package refuses.
	ErrInvalid = errors.New("invalid launchd configuration")
	// ErrLaunchctl is a launchctl command that failed; the message carries
	// its output.
	ErrLaunchctl = errors.New("launchctl failed")
)

const (
	plistMode    fs.FileMode = 0o644
	dirMode      fs.FileMode = 0o755
	logsMode     fs.FileMode = 0o700
	commandLimit             = 30 * time.Second
)

// Paths is where the LaunchAgent's files live for a user.
type Paths struct {
	// Plist is the property list launchd loads.
	Plist string
	// Logs is the directory the agent's standard streams go to.
	Logs string
}

// DefaultPaths are the conventional locations under a home directory.
func DefaultPaths(home string) Paths {
	return Paths{
		Plist: filepath.Join(home, "Library", "LaunchAgents", Label+".plist"),
		Logs:  filepath.Join(home, "Library", "Logs", Label),
	}
}

// Plist renders the property list: the executable run with "agent", at
// load, kept alive, its streams in the logs directory. Every path is
// XML-escaped.
func Plist(executable, logs string) []byte {
	var out bytes.Buffer

	out.WriteString(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>` + Label + `</string>
	<key>ProgramArguments</key>
	<array>
		<string>` + escape(executable) + `</string>
		<string>agent</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<true/>
	<key>StandardOutPath</key>
	<string>` + escape(filepath.Join(logs, "stdout.log")) + `</string>
	<key>StandardErrorPath</key>
	<string>` + escape(filepath.Join(logs, "stderr.log")) + `</string>
</dict>
</plist>
`)

	return out.Bytes()
}

func escape(s string) string {
	var out bytes.Buffer

	_ = xml.EscapeText(&out, []byte(s))

	return out.String()
}

// Install writes the property list for the executable and loads it,
// replacing a loaded agent of the same label.
func Install(ctx context.Context, paths Paths, executable string) error {
	if !filepath.IsAbs(executable) {
		return fmt.Errorf("executable %q is not absolute: %w", executable, ErrInvalid)
	}

	if err := os.MkdirAll(filepath.Dir(paths.Plist), dirMode); err != nil {
		return fmt.Errorf("creating %s: %w", filepath.Dir(paths.Plist), err)
	}

	if err := os.MkdirAll(paths.Logs, logsMode); err != nil {
		return fmt.Errorf("creating %s: %w", paths.Logs, err)
	}

	// A loaded agent is booted out first, so the new property list is what
	// starts; nothing loaded is not an error.
	_ = launchctl(ctx, "bootout", target())

	if err := filesystem.WriteFile(paths.Plist, Plist(executable, paths.Logs), plistMode); err != nil {
		return fmt.Errorf("writing %s: %w", paths.Plist, err)
	}

	return launchctl(ctx, "bootstrap", domain(), paths.Plist)
}

// Uninstall unloads the agent and removes its property list. Nothing
// loaded and no property list is not an error.
func Uninstall(ctx context.Context, paths Paths) error {
	_ = launchctl(ctx, "bootout", target())

	if err := os.Remove(paths.Plist); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("removing %s: %w", paths.Plist, err)
	}

	return nil
}

// Status is what launchd says about the agent.
type Status struct {
	// Loaded says launchd knows the label.
	Loaded bool
	// Running says a process is up, and PID which.
	Running bool
	PID     int
	// Program is the executable launchd runs, as the property list named it.
	Program string
}

// ReadStatus asks launchd about the agent.
func ReadStatus(ctx context.Context) (Status, error) {
	out, err := output(ctx, "print", target())
	if err != nil {
		if strings.Contains(err.Error(), "Could not find service") {
			return Status{}, nil
		}

		return Status{}, err
	}

	return ParseStatus(out), nil
}

// ParseStatus reads launchctl print's output for the fields the status
// reports: a loaded service, whether it is running, its pid and program.
// Only the service's own lines count, one tab in: the blocks nested under
// it (endpoints, event triggers, the spawn constraints) carry their own
// "state = active" lines, which once read as a service that was not
// running while launchd had it running under a pid.
func ParseStatus(text string) Status {
	status := Status{Loaded: true}

	for line := range strings.SplitSeq(text, "\n") {
		if !strings.HasPrefix(line, "\t") || strings.HasPrefix(line, "\t\t") {
			continue
		}

		key, value, found := strings.Cut(strings.TrimSpace(line), "=")
		if !found {
			continue
		}

		key, value = strings.TrimSpace(key), strings.TrimSpace(value)

		switch key {
		case "state":
			status.Running = value == "running"
		case "pid":
			status.PID, _ = strconv.Atoi(value)
		case "program":
			status.Program = value
		}
	}

	return status
}

func domain() string {
	return "gui/" + strconv.Itoa(os.Getuid())
}

func target() string {
	return domain() + "/" + Label
}

func launchctl(ctx context.Context, args ...string) error {
	_, err := output(ctx, args...)

	return err
}

func output(ctx context.Context, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, commandLimit)
	defer cancel()

	// #nosec G204 -- launchctl by absolute path, arguments from this package only
	out, err := exec.CommandContext(ctx, "/bin/launchctl", args...).
		CombinedOutput()
	if err != nil {
		return "", fmt.Errorf(
			"launchctl %s: %s: %w",
			strings.Join(args, " "),
			strings.TrimSpace(string(out)),
			ErrLaunchctl,
		)
	}

	return string(out), nil
}
