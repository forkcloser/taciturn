// The contract of package launchd's pure parts: the property list names
// this binary by the path given, runs "agent", starts at load, is kept
// alive, logs under the logs directory, and escapes every path; the status
// parser reads launchctl print's "key = value" lines.
package launchd_test

import (
	"bytes"
	"encoding/xml"
	"strings"
	"testing"

	"github.com/forkcloser/taciturn/internal/launchd"
)

func TestPlist(t *testing.T) {
	t.Parallel()

	plist := launchd.Plist("/opt/taciturn/bin/taciturn", "/Users/me/Library/Logs/"+launchd.Label)

	for _, want := range []string{
		"<string>" + launchd.Label + "</string>",
		"<string>/opt/taciturn/bin/taciturn</string>",
		"<string>agent</string>",
		"<key>RunAtLoad</key>\n\t<true/>",
		"<key>KeepAlive</key>\n\t<true/>",
		"<string>/Users/me/Library/Logs/" + launchd.Label + "/stdout.log</string>",
		"<string>/Users/me/Library/Logs/" + launchd.Label + "/stderr.log</string>",
	} {
		if !bytes.Contains(plist, []byte(want)) {
			t.Fatalf("plist lacks %q:\n%s", want, plist)
		}
	}

	if err := xml.Unmarshal(plist, new(struct{})); err != nil {
		t.Fatalf("plist is not XML: %v", err)
	}
}

func TestPlistEscapesPaths(t *testing.T) {
	t.Parallel()

	plist := string(launchd.Plist("/tmp/a&b<c>/taciturn", "/tmp/\"logs\""))

	if strings.Contains(plist, "a&b<c>") || !strings.Contains(plist, "a&amp;b&lt;c&gt;") {
		t.Fatalf("executable path not escaped:\n%s", plist)
	}

	if err := xml.Unmarshal([]byte(plist), new(struct{})); err != nil {
		t.Fatalf("plist is not XML: %v", err)
	}
}

func TestDefaultPaths(t *testing.T) {
	t.Parallel()

	paths := launchd.DefaultPaths("/Users/me")

	if paths.Plist != "/Users/me/Library/LaunchAgents/"+launchd.Label+".plist" {
		t.Fatal(paths.Plist)
	}

	if paths.Logs != "/Users/me/Library/Logs/"+launchd.Label {
		t.Fatal(paths.Logs)
	}
}

func TestParseStatus(t *testing.T) {
	t.Parallel()

	running := launchd.ParseStatus(`gui/501/org.forkcloser.taciturn = {
	active count = 1
	path = /Users/me/Library/LaunchAgents/org.forkcloser.taciturn.plist
	state = running

	program = /opt/taciturn/bin/taciturn
	arguments = {
		/opt/taciturn/bin/taciturn
		agent
	}
	pid = 4242
}`)

	if !running.Loaded || !running.Running || running.PID != 4242 || running.Program != "/opt/taciturn/bin/taciturn" {
		t.Fatalf("%+v", running)
	}

	waiting := launchd.ParseStatus("gui/501/org.forkcloser.taciturn = {\n\tstate = waiting\n}")
	if !waiting.Loaded || waiting.Running || waiting.PID != 0 {
		t.Fatalf("%+v", waiting)
	}

	empty := launchd.ParseStatus("")
	if !empty.Loaded || empty.Running || empty.Program != "" {
		t.Fatalf("%+v", empty)
	}
}
