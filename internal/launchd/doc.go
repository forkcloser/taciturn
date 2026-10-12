// Package launchd runs the agent as a user LaunchAgent: it writes the
// property list that names this binary by its real path, loads it into
// the user's launchd domain, reads its state, and unloads it.
//
// launchd starts the agent with HOME and the system PATH only, so the
// property list names the executable by its resolved path, never through
// a tool manager's proxy; after an upgrade to another package directory,
// Install again (the lesson of forkcloser/openssh's agent). The agent is
// started at load and kept alive: a crash is a restart.
//
// The pure parts, the property list and the reading of launchctl's
// output, are tested; Install, Uninstall and Status run launchctl on this
// machine and are verified by using them.
package launchd
