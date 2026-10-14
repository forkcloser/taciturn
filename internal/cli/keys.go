package cli

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/mycophonic/primordium/filesystem/dirs"
	"github.com/mycophonic/primordium/format"

	"github.com/forkcloser/taciturn/internal/enclave"
	"github.com/forkcloser/taciturn/internal/keystore"
	"github.com/forkcloser/taciturn/internal/peer"
	"github.com/forkcloser/taciturn/internal/policy"
	"github.com/forkcloser/taciturn/internal/protocol"
)

var (
	errName           = errors.New("a key name is required")
	errClass          = errors.New("-use must be locked or unlocked")
	errConfirm        = errors.New("deletion needs -yes")
	errRetired        = errors.New("key is retired")
	errArgument       = errors.New("missing argument")
	errPeerFlags      = errors.New("-add and -remove are exclusive")
	errPeerEntry      = errors.New("invalid peer entry")
	errSignatureCheck = errors.New("the key's signature does not verify against its public key")
)

// The access classes as the command line names them.
const (
	useLocked   = "locked"
	useUnlocked = "unlocked"
)

// The peers a new key allows by default: forkcloser/openssh's ssh and
// ssh-keygen by path under every aqua root this machine runs tools from,
// and, until the fork is the sessions' client, Apple's (docs/design.md,
// decision 3). The fork's package directory is one version component
// (vX.Y.Z or vX.Y.Z.N), the archive, the archive's directory, then bin.
const (
	forkPackages   = "pkgs/github_release/github.com/forkcloser/openssh/*/*/*/bin/"
	appleSSH       = `anchor apple and identifier "com.apple.ssh"`
	appleSSHKeygen = `anchor apple and identifier "com.apple.ssh-keygen"`
	humanAquaRoot  = ".local/share/aquaproj-aqua"
	agentAquaRoot  = ".local/share/limen-agent/aqua"
	dateLayout     = "20060102"
	rotatedNameSep = "@"
	formatSSH      = "ssh"
)

// aquaRoots are the roots the fork may run from: the human's and the
// sessions' (limen-install-agent's, under its agent root), whichever this
// process was started under first, so that the environment that creates a
// key does not decide which client may use it.
func aquaRoots() []string {
	home := dirs.HomeDir()
	roots := []string{filepath.Join(home, humanAquaRoot), filepath.Join(home, agentAquaRoot)}

	if root := os.Getenv("AQUA_ROOT_DIR"); root != "" && !slices.Contains(roots, root) {
		roots = append([]string{root}, roots...)
	}

	return roots
}

func defaultPeers() []string {
	var peers []string

	for _, root := range aquaRoots() {
		peers = append(
			peers,
			policy.PeerPathPrefix+filepath.Join(root, forkPackages, "ssh"),
			policy.PeerPathPrefix+filepath.Join(root, forkPackages, "ssh-keygen"),
		)
	}

	return append(peers, appleSSH, appleSSHKeygen)
}

func runKey(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		usage(stderr)

		return errUsage
	}

	loc, err := resolve()
	if err != nil {
		return err
	}

	switch args[0] {
	case "create":
		return keyCreate(loc, args[1:], stdout, stderr)
	case "list":
		return keyList(loc, args[1:], stdout, stderr)
	case "show":
		return keyShow(loc, args[1:], stdout, stderr)
	case "allow":
		return keyAllow(loc, args[1:], stdout, stderr)
	case "disallow":
		return keyDisallow(loc, args[1:], stdout, stderr)
	case "peers":
		return keyPeers(loc, args[1:], stdout, stderr)
	case "sshsig":
		return keySSHSig(loc, args[1:], stdout, stderr)
	case "delete":
		return keyDelete(loc, args[1:], stdout, stderr)
	case "import":
		return keyImport(loc, args[1:], stdout, stderr)
	case "rotate":
		return keyRotate(loc, args[1:], stdout, stderr)
	case "retire":
		return keyRetire(loc, args[1:], stdout, stderr)
	case "signers":
		return keySigners(loc, args[1:], stdout, stderr)
	default:
		_, _ = fmt.Fprintf(stderr, "taciturn: unknown key command %q\n\n", args[0])
		usage(stderr)

		return errUsage
	}
}

// nameAndFlags splits "NAME -flag ..." into the name and the flags.
func nameAndFlags(args []string) (name string, flags []string, err error) {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return "", nil, errName
	}

	return args[0], args[1:], nil
}

// storeError wraps what the key store said, at the command boundary.
func storeError(err error) error {
	return fmt.Errorf("key store: %w", err)
}

func keyCreate(loc locations, args []string, stdout, stderr io.Writer) error {
	name, rest, err := nameAndFlags(args)
	if err != nil {
		return err
	}

	set := flagSet("key create", stderr)
	storePath := storeFlag(set, loc)
	use := set.String(
		"use",
		"",
		"locked: signs while the screen is locked, until reboot; unlocked: only while the session is unlocked",
	)
	peers := set.String(
		"peers",
		"",
		"who may ask, comma-separated: any, path=GLOB, or a code requirement; default: our ssh and Apple's",
	)

	if err = parse(set, rest); err != nil {
		return err
	}

	class, enclaveClass, err := classOf(*use)
	if err != nil {
		return err
	}

	if err = keystore.ValidateName(name); err != nil {
		return storeError(err)
	}

	allowed := defaultPeers()
	if *peers != "" {
		allowed = strings.Split(*peers, ",")
	}

	for _, entry := range allowed {
		if err = validPeer(entry); err != nil {
			return err
		}
	}

	store, err := openStore(*storePath)
	if err != nil {
		return err
	}

	record, err := createKey(store, name, class, enclaveClass, policy.Policy{Peers: allowed})
	if err != nil {
		return err
	}

	_, _ = fmt.Fprintf(
		stdout,
		"created %s %s (%s)\n%s\n",
		record.Name,
		record.Fingerprint,
		class,
		authorizedKey(record),
	)

	return nil
}

// createKey makes a key in the enclave, stores it in the keychain under its
// fingerprint, and writes its record; a record the store refuses takes the
// keychain item down with it, so nothing half exists.
func createKey(
	store *keystore.Store,
	name string,
	class keystore.Class,
	enclaveClass enclave.Class,
	pol policy.Policy,
) (keystore.Record, error) {
	record, key, err := generate(name, class, enclaveClass, pol)
	if err != nil {
		return keystore.Record{}, err
	}

	defer key.Close()

	if err = key.Store(record.Fingerprint); err != nil {
		return keystore.Record{}, fmt.Errorf("keychain: %w", err)
	}

	if err = store.Create(record); err != nil {
		if undo := enclave.Delete(record.Fingerprint); undo != nil {
			return keystore.Record{}, fmt.Errorf(
				"%w; and the key stays in the keychain as %s: %w",
				storeError(err),
				record.Fingerprint,
				undo,
			)
		}

		return keystore.Record{}, storeError(err)
	}

	return record, nil
}

func classOf(use string) (keystore.Class, enclave.Class, error) {
	switch use {
	case useLocked:
		return keystore.ClassAfterFirstUnlock, enclave.ClassAfterFirstUnlock, nil
	case useUnlocked:
		return keystore.ClassWhenUnlocked, enclave.ClassWhenUnlocked, nil
	default:
		return "", 0, errClass
	}
}

func enclaveClassOf(class keystore.Class) enclave.Class {
	if class == keystore.ClassWhenUnlocked {
		return enclave.ClassWhenUnlocked
	}

	return enclave.ClassAfterFirstUnlock
}

// generate makes a key in the enclave and the record for it; the key comes
// back open, the caller's to store and close.
func generate(
	name string,
	class keystore.Class,
	enclaveClass enclave.Class,
	pol policy.Policy,
) (keystore.Record, *enclave.Key, error) {
	key, err := enclave.Generate(enclaveClass)
	if err != nil {
		return keystore.Record{}, nil, fmt.Errorf("enclave: %w", err)
	}

	public, err := protocol.ECDSAP256PublicKey(key.Public())
	if err != nil {
		key.Close()

		return keystore.Record{}, nil, fmt.Errorf("public key: %w", err)
	}

	record := keystore.Record{
		Fingerprint: protocol.Fingerprint(public),
		Name:        name,
		PublicKey:   public,
		Class:       class,
		Created:     time.Now().UTC(),
		Policy:      pol,
	}

	return record, key, nil
}

// proveKey signs a test message with the key and verifies the signature
// against the public key the record carries: the check `key import` runs
// before it lets a blob go, and doctor runs on every key.
func proveKey(key *enclave.Key, record keystore.Record) error {
	message := []byte("taciturn key check " + record.Fingerprint)

	sigR, sigS, err := key.Sign(message)
	if err != nil {
		return fmt.Errorf("signing: %w", err)
	}

	point, err := protocol.ECDSAP256PublicKeyPoint(record.PublicKey)
	if err != nil {
		return fmt.Errorf("stored public key: %w", err)
	}

	public, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), point)
	if err != nil {
		return fmt.Errorf("stored public key: %w", err)
	}

	digest := sha256.Sum256(message)
	if !ecdsa.Verify(public, digest[:], sigR, sigS) {
		return errSignatureCheck
	}

	return nil
}

// keyImport moves every v0.1 key whose blob is still in the store into the
// keychain, proves each by a signature, and deletes the blob only then
// (docs/design.md, decision 15).
func keyImport(loc locations, args []string, stdout, stderr io.Writer) error {
	set := flagSet("key import", stderr)
	storePath := storeFlag(set, loc)

	if err := parse(set, args); err != nil {
		return err
	}

	store, err := openStore(*storePath)
	if err != nil {
		return err
	}

	pending, err := store.LegacyBlobs()
	if err != nil {
		return storeError(err)
	}

	if len(pending) == 0 {
		_, _ = fmt.Fprintln(stdout, "nothing to import: every key is in the keychain")

		return nil
	}

	for _, fingerprint := range pending {
		if err := importKey(store, fingerprint); err != nil {
			return fmt.Errorf("%s: %w", fingerprint, err)
		}

		_, _ = fmt.Fprintf(stdout, "imported %s into the keychain; its blob file is gone\n", fingerprint)
	}

	return nil
}

func importKey(store *keystore.Store, fingerprint string) error {
	record, err := store.Get(fingerprint)
	if err != nil {
		return storeError(err)
	}

	blob, err := store.LegacyBlob(fingerprint)
	if err != nil {
		return storeError(err)
	}

	point, err := protocol.ECDSAP256PublicKeyPoint(record.PublicKey)
	if err != nil {
		return fmt.Errorf("stored public key: %w", err)
	}

	key, err := enclave.Import(blob, point, fingerprint)
	if errors.Is(err, enclave.ErrExists) {
		// An earlier import stored it and did not get to remove the blob:
		// the keychain's copy is checked like a fresh one.
		key, err = enclave.Load(fingerprint, point)
	}

	if err != nil {
		return fmt.Errorf("keychain: %w", err)
	}

	defer key.Close()

	if err = proveKey(key, record); err != nil {
		return fmt.Errorf("the keychain key does not sign, the blob stays: %w", err)
	}

	if err = store.RemoveLegacyBlob(fingerprint); err != nil {
		return storeError(err)
	}

	return nil
}

// authorizedKey is the public key as GitHub and authorized_keys take it.
func authorizedKey(record keystore.Record) string {
	return protocol.AlgorithmECDSAP256 + " " + base64.StdEncoding.EncodeToString(record.PublicKey) + " " + record.Name
}

func keyList(loc locations, args []string, stdout, stderr io.Writer) error {
	set := flagSet("key list", stderr)
	storePath := storeFlag(set, loc)
	kind := set.String("format", string(format.KindConsole), "console, json or ssh")

	if err := parse(set, args); err != nil {
		return err
	}

	store, err := openStore(*storePath)
	if err != nil {
		return err
	}

	records, err := store.List()
	if err != nil {
		return storeError(err)
	}

	if *kind == formatSSH {
		for _, record := range records {
			if record.Retired == nil {
				_, _ = fmt.Fprintln(stdout, authorizedKey(record))
			}
		}

		return nil
	}

	data := make([]*format.Data, 0, len(records))
	for _, record := range records {
		data = append(data, describeRecord(record))
	}

	return printData(*kind, data, stdout)
}

func printData(kind string, data []*format.Data, stdout io.Writer) error {
	formatter, err := format.New(format.Kind(kind))
	if err != nil {
		return fmt.Errorf("format: %w", err)
	}

	if err := formatter.PrintAll(data, stdout); err != nil {
		return fmt.Errorf("output: %w", err)
	}

	return nil
}

func describeRecord(record keystore.Record) *format.Data {
	meta := map[string]any{
		"fingerprint": record.Fingerprint,
		"class":       string(record.Class),
		"created":     record.Created.Format(time.RFC3339),
		"public":      authorizedKey(record),
		"namespaces":  record.Policy.Namespaces,
		"peers":       record.Policy.Peers,
	}

	destinations := make([]string, 0, len(record.Policy.Destinations))
	for _, destination := range record.Policy.Destinations {
		destinations = append(
			destinations,
			fmt.Sprintf("%s@%s (%d host keys)", destination.User, destination.Host, len(destination.HostKeys)),
		)
	}

	meta["destinations"] = destinations

	if record.Retired != nil {
		meta["retired"] = record.Retired.Format(time.RFC3339)
	}

	if record.Predecessor != "" {
		meta["predecessor"] = record.Predecessor
	}

	if record.Successor != "" {
		meta["successor"] = record.Successor
	}

	return &format.Data{Object: record.Name, Meta: meta}
}

func keyShow(loc locations, args []string, stdout, stderr io.Writer) error {
	name, rest, err := nameAndFlags(args)
	if err != nil {
		return err
	}

	set := flagSet("key show", stderr)
	storePath := storeFlag(set, loc)
	kind := set.String("format", string(format.KindConsole), "console or json")

	if err = parse(set, rest); err != nil {
		return err
	}

	store, err := openStore(*storePath)
	if err != nil {
		return err
	}

	record, err := store.Lookup(name)
	if err != nil {
		return storeError(err)
	}

	return printData(*kind, []*format.Data{describeRecord(record)}, stdout)
}

// update applies a change to a key's record and writes it back.
func update(store *keystore.Store, name string, change func(*keystore.Record) error) (keystore.Record, error) {
	record, err := store.Lookup(name)
	if err != nil {
		return keystore.Record{}, storeError(err)
	}

	if err = change(&record); err != nil {
		return keystore.Record{}, err
	}

	if err = store.Update(record); err != nil {
		return keystore.Record{}, storeError(err)
	}

	return record, nil
}

func keyAllow(loc locations, args []string, stdout, stderr io.Writer) error {
	name, rest, err := nameAndFlags(args)
	if err != nil {
		return err
	}

	set := flagSet("key allow", stderr)
	storePath := storeFlag(set, loc)
	user := set.String("user", "", "the user to authenticate as")
	host := set.String("host", "", "the host, as known_hosts names it")
	knownHosts := set.String("known-hosts", "", "the known_hosts file holding the host's keys")

	if err = parse(set, rest); err != nil {
		return err
	}

	if *user == "" || *host == "" || *knownHosts == "" {
		return fmt.Errorf("%w: -user, -host and -known-hosts", errArgument)
	}

	hostKeys, err := hostKeysFrom(*knownHosts, *host)
	if err != nil {
		return err
	}

	store, err := openStore(*storePath)
	if err != nil {
		return err
	}

	record, err := update(store, name, func(record *keystore.Record) error {
		record.Policy.Destinations = append(
			withoutDestination(record.Policy.Destinations, *host, *user),
			policy.Destination{
				User:     *user,
				Host:     *host,
				HostKeys: hostKeys,
			},
		)

		return nil
	})
	if err != nil {
		return err
	}

	_, _ = fmt.Fprintf(
		stdout,
		"%s may authenticate to %s as %s (%d host keys)\n",
		record.Name,
		*host,
		*user,
		len(hostKeys),
	)

	return nil
}

func withoutDestination(destinations []policy.Destination, host, user string) []policy.Destination {
	return slices.DeleteFunc(slices.Clone(destinations), func(destination policy.Destination) bool {
		return destination.Host == host && (user == "" || destination.User == user)
	})
}

func keyDisallow(loc locations, args []string, stdout, stderr io.Writer) error {
	name, rest, err := nameAndFlags(args)
	if err != nil {
		return err
	}

	set := flagSet("key disallow", stderr)
	storePath := storeFlag(set, loc)
	host := set.String("host", "", "the host to remove every destination of")

	if err = parse(set, rest); err != nil {
		return err
	}

	if *host == "" {
		return fmt.Errorf("%w: -host", errArgument)
	}

	store, err := openStore(*storePath)
	if err != nil {
		return err
	}

	record, err := update(store, name, func(record *keystore.Record) error {
		record.Policy.Destinations = withoutDestination(record.Policy.Destinations, *host, "")

		return nil
	})
	if err != nil {
		return err
	}

	_, _ = fmt.Fprintf(stdout, "%s no longer authenticates to %s\n", record.Name, *host)

	return nil
}

// validPeer checks a peer entry the way the agent will read it: "any", a
// path glob the matcher accepts, or a code requirement the framework
// parses. The agent treats what it cannot read as unsatisfied, so an entry
// refused here would have refused every request instead.
func validPeer(entry string) error {
	switch {
	case entry == policy.PeerAny:
		return nil
	case strings.HasPrefix(entry, policy.PeerPathPrefix):
		pattern := strings.TrimPrefix(entry, policy.PeerPathPrefix)
		if !filepath.IsAbs(pattern) {
			return fmt.Errorf("%w: %q: the path is not absolute", errPeerEntry, entry)
		}

		if _, err := filepath.Match(pattern, ""); err != nil {
			return fmt.Errorf("%w: %q: %w", errPeerEntry, entry, err)
		}

		return nil
	case entry == "":
		return fmt.Errorf("%w: empty", errPeerEntry)
	default:
		if err := peer.ValidRequirement(entry); err != nil {
			return fmt.Errorf("%w: %w", errPeerEntry, err)
		}

		return nil
	}
}

// keyPeers edits who may ask a key to sign: one entry added or removed per
// call, the list printed after.
func keyPeers(loc locations, args []string, stdout, stderr io.Writer) error {
	name, rest, err := nameAndFlags(args)
	if err != nil {
		return err
	}

	set := flagSet("key peers", stderr)
	storePath := storeFlag(set, loc)
	add := set.String("add", "", "an entry to allow: any, path=GLOB, or a code requirement")
	remove := set.String("remove", "", "an entry to take away, as show prints it")

	if err = parse(set, rest); err != nil {
		return err
	}

	if *add != "" && *remove != "" {
		return errPeerFlags
	}

	if *add != "" {
		if err = validPeer(*add); err != nil {
			return err
		}
	}

	store, err := openStore(*storePath)
	if err != nil {
		return err
	}

	record, err := update(store, name, func(record *keystore.Record) error {
		if *remove != "" {
			record.Policy.Peers = slices.DeleteFunc(
				slices.Clone(record.Policy.Peers),
				func(entry string) bool { return entry == *remove },
			)
		}

		if *add != "" && !slices.Contains(record.Policy.Peers, *add) {
			record.Policy.Peers = append(slices.Clone(record.Policy.Peers), *add)
		}

		return nil
	})
	if err != nil {
		return err
	}

	_, _ = fmt.Fprintf(stdout, "%s may be asked by %d peers:\n", record.Name, len(record.Policy.Peers))

	for _, entry := range record.Policy.Peers {
		_, _ = fmt.Fprintf(stdout, "  %s\n", entry)
	}

	return nil
}

func keySSHSig(loc locations, args []string, stdout, stderr io.Writer) error {
	name, rest, err := nameAndFlags(args)
	if err != nil {
		return err
	}

	set := flagSet("key sshsig", stderr)
	storePath := storeFlag(set, loc)
	namespace := set.String("namespace", "", "the SSHSIG namespace (git for commits and tags)")
	remove := set.Bool("remove", false, "take the namespace away instead")

	if err = parse(set, rest); err != nil {
		return err
	}

	if *namespace == "" {
		return fmt.Errorf("%w: -namespace", errArgument)
	}

	store, err := openStore(*storePath)
	if err != nil {
		return err
	}

	record, err := update(store, name, func(record *keystore.Record) error {
		namespaces := slices.DeleteFunc(
			slices.Clone(record.Policy.Namespaces),
			func(entry string) bool { return entry == *namespace },
		)
		if !*remove {
			namespaces = append(namespaces, *namespace)
		}

		record.Policy.Namespaces = namespaces

		return nil
	})
	if err != nil {
		return err
	}

	_, _ = fmt.Fprintf(stdout, "%s signs in: %s\n", record.Name, strings.Join(record.Policy.Namespaces, " "))

	return nil
}

func keyDelete(loc locations, args []string, stdout, stderr io.Writer) error {
	name, rest, err := nameAndFlags(args)
	if err != nil {
		return err
	}

	set := flagSet("key delete", stderr)
	storePath := storeFlag(set, loc)
	yes := set.Bool("yes", false, "confirm: the key is gone for good")

	if err = parse(set, rest); err != nil {
		return err
	}

	if !*yes {
		return errConfirm
	}

	store, err := openStore(*storePath)
	if err != nil {
		return err
	}

	record, err := store.Lookup(name)
	if err != nil {
		return storeError(err)
	}

	// The keychain item goes first: a record without its item is a key
	// doctor reports, an item without its record is a key nothing names.
	switch err = enclave.Delete(record.Fingerprint); {
	case err == nil:
	case errors.Is(err, enclave.ErrNotFound):
		_, _ = fmt.Fprintf(stderr, "taciturn: %s was not in the keychain\n", record.Fingerprint)
	case errors.Is(err, enclave.ErrUnavailable):
		_, _ = fmt.Fprintf(stderr, "taciturn: the keychain item of %s stays: %v\n", record.Fingerprint, err)
	default:
		return fmt.Errorf("keychain: %w", err)
	}

	if err = store.Delete(record.Fingerprint); err != nil {
		return storeError(err)
	}

	_, _ = fmt.Fprintf(
		stdout,
		"deleted %s %s; remove it from GitHub too, as an authentication key and as a signing key\n",
		record.Name,
		record.Fingerprint,
	)

	return nil
}

// keyRotate makes NAME's successor with the same class and policy, renames
// the current key NAME@<date>, links the two, and serves both until the old
// one is retired.
func keyRotate(loc locations, args []string, stdout, stderr io.Writer) error {
	name, rest, err := nameAndFlags(args)
	if err != nil {
		return err
	}

	set := flagSet("key rotate", stderr)
	storePath := storeFlag(set, loc)

	if err = parse(set, rest); err != nil {
		return err
	}

	store, err := openStore(*storePath)
	if err != nil {
		return err
	}

	current, err := store.Lookup(name)
	if err != nil {
		return storeError(err)
	}

	if current.Retired != nil {
		return fmt.Errorf("%s: %w", name, errRetired)
	}

	successor, key, err := generate(name, current.Class, enclaveClassOf(current.Class), current.Policy)
	if err != nil {
		return err
	}

	defer key.Close()

	successor.Predecessor = current.Fingerprint

	if err = key.Store(successor.Fingerprint); err != nil {
		return fmt.Errorf("keychain: %w", err)
	}

	// The successor takes the name, so the current key gives it up first;
	// a store that then refuses the successor gets the current key back as
	// it was and the successor leaves the keychain, so a failed rotation
	// leaves nothing renamed and nothing dangling.
	before := current
	current.Name = name + rotatedNameSep + successor.Created.Format(dateLayout)
	current.Successor = successor.Fingerprint

	if err = store.Update(current); err != nil {
		_ = enclave.Delete(successor.Fingerprint)

		return storeError(err)
	}

	if err = store.Create(successor); err != nil {
		_ = enclave.Delete(successor.Fingerprint)

		if restore := store.Update(before); restore != nil {
			return fmt.Errorf("%w; and %s stays renamed %s: %w", storeError(err), name, current.Name, restore)
		}

		return storeError(err)
	}

	_, _ = fmt.Fprintf(stdout, "rotated: %s is now %s %s; %s is %s, still served\n%s\n",
		name, successor.Fingerprint, successor.Class, current.Name, current.Fingerprint, authorizedKey(successor))
	_, _ = fmt.Fprintf(
		stdout,
		"register the new key on GitHub (authentication and signing), then: taciturn key signers %s -principal EMAIL\n",
		name,
	)

	return nil
}

func keyRetire(loc locations, args []string, stdout, stderr io.Writer) error {
	name, rest, err := nameAndFlags(args)
	if err != nil {
		return err
	}

	set := flagSet("key retire", stderr)
	storePath := storeFlag(set, loc)

	if err = parse(set, rest); err != nil {
		return err
	}

	store, err := openStore(*storePath)
	if err != nil {
		return err
	}

	record, err := update(store, name, func(record *keystore.Record) error {
		if record.Retired != nil {
			return fmt.Errorf("%s: %w", record.Name, errRetired)
		}

		now := time.Now().UTC()
		record.Retired = &now

		return nil
	})
	if err != nil {
		return err
	}

	_, _ = fmt.Fprintf(
		stdout,
		"retired %s %s: no longer served; the files stay until deleted; remove it from GitHub\n",
		record.Name,
		record.Fingerprint,
	)

	return nil
}

func keySigners(loc locations, args []string, stdout, stderr io.Writer) error {
	name, rest, err := nameAndFlags(args)
	if err != nil {
		return err
	}

	set := flagSet("key signers", stderr)
	storePath := storeFlag(set, loc)
	principal := set.String("principal", "", "the principal the signatures are verified for (the committer's email)")

	if err = parse(set, rest); err != nil {
		return err
	}

	if *principal == "" {
		return fmt.Errorf("%w: -principal", errArgument)
	}

	store, err := openStore(*storePath)
	if err != nil {
		return err
	}

	record, err := store.Lookup(name)
	if err != nil {
		return storeError(err)
	}

	_, _ = fmt.Fprintln(stdout, allowedSigner(*principal, record))

	return nil
}
