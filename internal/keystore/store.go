package keystore

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/mycophonic/primordium/filesystem"
	"github.com/mycophonic/primordium/filesystem/flock"
)

const (
	dirMode  fs.FileMode = 0o700
	fileMode fs.FileMode = 0o600
	// othersMask is every permission bit but the owner's.
	othersMask fs.FileMode = 0o077

	blobSuffix   = ".blob"
	recordSuffix = ".json"
	lockName     = ".lock"

	// maxRecordFile bounds what a record file may be before it is read: a
	// record is a few hundred bytes of JSON.
	maxRecordFile = 64 * 1024
)

// Store is a key store on disk.
type Store struct {
	dir string
}

// Open opens the store at dir, creating the directory private when it does
// not exist. A directory that exists with permissions for anyone but the
// owner is ErrInsecure; a path that is not a directory is ErrInvalid.
func Open(dir string) (*Store, error) {
	info, err := os.Stat(dir)

	switch {
	case errors.Is(err, fs.ErrNotExist):
		if err = os.MkdirAll(dir, dirMode); err != nil {
			return nil, fmt.Errorf("creating key store: %w", err)
		}

		if info, err = os.Stat(dir); err != nil {
			return nil, fmt.Errorf("key store: %w", err)
		}
	case err != nil:
		return nil, fmt.Errorf("key store: %w", err)
	case !info.IsDir():
		return nil, fmt.Errorf("key store %s is not a directory: %w", dir, ErrInvalid)
	}

	if info.Mode().Perm()&othersMask != 0 {
		return nil, fmt.Errorf("key store %s has mode %o: %w", dir, info.Mode().Perm(), ErrInsecure)
	}

	// The lock file must exist for the advisory lock to be taken on it.
	lock, err := os.OpenFile(
		filepath.Join(dir, lockName),
		os.O_RDONLY|os.O_CREATE,
		fileMode,
	) // #nosec G304 -- the store's own directory, a fixed name
	if err != nil {
		return nil, fmt.Errorf("key store lock file: %w", err)
	}

	if err = lock.Close(); err != nil {
		return nil, fmt.Errorf("key store lock file: %w", err)
	}

	return &Store{dir: dir}, nil
}

// Dir is the store's directory.
func (s *Store) Dir() string {
	return s.dir
}

// Create adds a key's record; the key itself is the keychain's. A key with
// this fingerprint or a record with this name already present is
// ErrExists; nothing is written then.
func (s *Store) Create(record Record) error {
	if err := record.validate(); err != nil {
		return err
	}

	return s.locked(func() error {
		records, err := s.readAll()
		if err != nil {
			return err
		}

		for _, existing := range records {
			if existing.Fingerprint == record.Fingerprint {
				return fmt.Errorf("key %s: %w", record.Fingerprint, ErrExists)
			}

			if existing.Name == record.Name {
				return fmt.Errorf("name %q: %w", record.Name, ErrExists)
			}
		}

		if _, err := os.Stat(s.recordPath(record.Fingerprint)); err == nil {
			return fmt.Errorf("record of %s: %w", record.Fingerprint, ErrExists)
		}

		return s.writeRecord(record)
	})
}

// Edit changes one key's record, named by its name or its fingerprint. The
// record is read, handed to change and written back under the store's lock,
// so of two edits at once neither is lost. change may alter anything but
// the key: a record that comes back with another fingerprint or public key
// is ErrInvalid. A name another key holds is ErrExists, a key not in the
// store ErrNotFound; an error from change is returned as it is. Nothing is
// written unless all of it holds. The record as written is returned.
func (s *Store) Edit(nameOrFingerprint string, change func(*Record) error) (Record, error) {
	byFingerprint := strings.HasPrefix(nameOrFingerprint, fingerprintPrefix)

	check := ValidateName
	if byFingerprint {
		check = ValidateFingerprint
	}

	if err := check(nameOrFingerprint); err != nil {
		return Record{}, err
	}

	var edited Record

	err := s.locked(func() error {
		var err error

		edited, err = s.editLocked(nameOrFingerprint, byFingerprint, change)

		return err
	})
	if err != nil {
		return Record{}, err
	}

	return edited, nil
}

// Rotate hands a key's name to its successor, both records written under
// the store's lock. current is the key as the caller looked it up: the
// store's record of it must still carry that name and that successor, or
// the key was rotated or renamed since and the rotation is ErrExists, so of
// two rotations at once one is refused and writes nothing. The key takes
// the name renamed and the successor's fingerprint; the successor's record
// is written with the name the key gave up, the key as its predecessor and
// the key's policy as the store holds it now, so an edit made since the
// lookup is the successor's too. A retired key is ErrInvalid, a name or a
// key already in the store ErrExists, a key not in the store ErrNotFound;
// nothing is written unless all of it holds. Should the successor's record
// fail to be written, the key's is put back as it was. The two records as
// written are returned, the key's first.
func (s *Store) Rotate(current Record, renamed string, successor Record) (rotated, written Record, err error) {
	if err = ValidateFingerprint(current.Fingerprint); err != nil {
		return Record{}, Record{}, err
	}

	if err = ValidateName(renamed); err != nil {
		return Record{}, Record{}, err
	}

	err = s.locked(func() error {
		var failed error

		rotated, written, failed = s.rotateLocked(current, renamed, successor)

		return failed
	})
	if err != nil {
		return Record{}, Record{}, err
	}

	return rotated, written, nil
}

// Delete removes a key's record, and the v0.1 blob file beside it when one
// is still there. A key not in the store is ErrNotFound.
func (s *Store) Delete(fingerprint string) error {
	if err := ValidateFingerprint(fingerprint); err != nil {
		return err
	}

	return s.locked(func() error {
		if _, err := s.read(fingerprint); err != nil {
			return err
		}

		if err := os.Remove(s.blobPath(fingerprint)); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("removing blob: %w", err)
		}

		if err := os.Remove(s.recordPath(fingerprint)); err != nil {
			return fmt.Errorf("removing record: %w", err)
		}

		return nil
	})
}

// Get returns a key's record.
func (s *Store) Get(fingerprint string) (Record, error) {
	if err := ValidateFingerprint(fingerprint); err != nil {
		return Record{}, err
	}

	return s.read(fingerprint)
}

// Lookup returns the record named by a name or a fingerprint.
func (s *Store) Lookup(nameOrFingerprint string) (Record, error) {
	if strings.HasPrefix(nameOrFingerprint, fingerprintPrefix) {
		return s.Get(nameOrFingerprint)
	}

	if err := ValidateName(nameOrFingerprint); err != nil {
		return Record{}, err
	}

	records, err := s.readAll()
	if err != nil {
		return Record{}, err
	}

	for _, record := range records {
		if record.Name == nameOrFingerprint {
			return record, nil
		}
	}

	return Record{}, fmt.Errorf("name %q: %w", nameOrFingerprint, ErrNotFound)
}

// LegacyBlob returns the v0.1 wrapped blob of a key whose blob file is
// still in the store, for `key import`; a key with no blob file is
// ErrNotFound. An oversize file is ErrInvalid.
func (s *Store) LegacyBlob(fingerprint string) ([]byte, error) {
	if err := ValidateFingerprint(fingerprint); err != nil {
		return nil, err
	}

	if _, err := s.read(fingerprint); err != nil {
		return nil, err
	}

	blob, err := readPrivate(s.blobPath(fingerprint))
	if err != nil {
		return nil, err
	}

	if len(blob) == 0 || len(blob) > MaxBlob {
		return nil, fmt.Errorf("blob of %d bytes: %w", len(blob), ErrInvalid)
	}

	return blob, nil
}

// RemoveLegacyBlob deletes a key's v0.1 blob file once the key is in the
// keychain. A key with no blob file is ErrNotFound.
func (s *Store) RemoveLegacyBlob(fingerprint string) error {
	if err := ValidateFingerprint(fingerprint); err != nil {
		return err
	}

	return s.locked(func() error {
		if _, err := s.read(fingerprint); err != nil {
			return err
		}

		if err := os.Remove(s.blobPath(fingerprint)); err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return fmt.Errorf("blob of %s: %w", fingerprint, ErrNotFound)
			}

			return fmt.Errorf("removing blob: %w", err)
		}

		return nil
	})
}

// LegacyBlobs lists the fingerprints of the keys whose v0.1 blob file is
// still in the store: the keys `key import` has yet to move.
func (s *Store) LegacyBlobs() ([]string, error) {
	records, err := s.readAll()
	if err != nil {
		return nil, err
	}

	var pending []string

	for _, record := range records {
		if _, err := os.Stat(s.blobPath(record.Fingerprint)); err == nil {
			pending = append(pending, record.Fingerprint)
		}
	}

	return pending, nil
}

// List returns every record, oldest first, names breaking ties.
func (s *Store) List() ([]Record, error) {
	return s.readAll()
}

func (s *Store) blobPath(fingerprint string) string {
	return filepath.Join(s.dir, fileID(fingerprint)+blobSuffix)
}

func (s *Store) recordPath(fingerprint string) string {
	return filepath.Join(s.dir, fileID(fingerprint)+recordSuffix)
}

// locked runs fn holding the store's write lock. What fn returns comes
// back as it is; only a failure of the lock is reported as one.
func (s *Store) locked(fn func() error) error {
	var result error

	err := flock.WithLock(filepath.Join(s.dir, lockName), func() error {
		result = fn()

		return nil
	})

	if result != nil {
		return result
	}

	if err != nil {
		return fmt.Errorf("key store lock: %w", err)
	}

	return nil
}

// editLocked is Edit's read, change and write; the caller holds the lock.
func (s *Store) editLocked(handle string, byFingerprint bool, change func(*Record) error) (Record, error) {
	records, err := s.readAll()
	if err != nil {
		return Record{}, err
	}

	current, found := named(records, handle, byFingerprint)
	if !found {
		return Record{}, fmt.Errorf("key %s: %w", handle, ErrNotFound)
	}

	edited := current

	if err := change(&edited); err != nil {
		return Record{}, err
	}

	if edited.Fingerprint != current.Fingerprint {
		return Record{}, fmt.Errorf("an edit cannot change the key %s: %w", current.Fingerprint, ErrInvalid)
	}

	if err := edited.validate(); err != nil {
		return Record{}, err
	}

	for _, existing := range records {
		if existing.Fingerprint != current.Fingerprint && existing.Name == edited.Name {
			return Record{}, fmt.Errorf("name %q: %w", edited.Name, ErrExists)
		}
	}

	if err := s.writeRecord(edited); err != nil {
		return Record{}, err
	}

	return edited, nil
}

// rotateLocked is Rotate's read, checks and two writes; the caller holds
// the lock.
func (s *Store) rotateLocked(looked Record, renamed string, successor Record) (rotated, written Record, err error) {
	records, err := s.readAll()
	if err != nil {
		return Record{}, Record{}, err
	}

	held, err := rotatable(records, looked, renamed)
	if err != nil {
		return Record{}, Record{}, err
	}

	successor.Name = held.Name
	successor.Policy = held.Policy
	successor.Predecessor = held.Fingerprint

	if err = successor.validate(); err != nil {
		return Record{}, Record{}, err
	}

	if _, found := named(records, successor.Fingerprint, true); found {
		return Record{}, Record{}, fmt.Errorf("key %s: %w", successor.Fingerprint, ErrExists)
	}

	rotated = held
	rotated.Name = renamed
	rotated.Successor = successor.Fingerprint

	if err = s.writeRecord(rotated); err != nil {
		return Record{}, Record{}, err
	}

	if err = s.writeRecord(successor); err != nil {
		if restore := s.writeRecord(held); restore != nil {
			return Record{}, Record{}, fmt.Errorf(
				"%w; and key %s stays renamed %s: %w", err, held.Fingerprint, renamed, restore,
			)
		}

		return Record{}, Record{}, err
	}

	return rotated, successor, nil
}

// rotatable is the key a rotation is about, as the store holds it: still as
// the caller looked it up, not retired, and its new name free.
func rotatable(records []Record, looked Record, renamed string) (Record, error) {
	held, found := named(records, looked.Fingerprint, true)
	if !found {
		return Record{}, fmt.Errorf("key %s: %w", looked.Fingerprint, ErrNotFound)
	}

	if held.Name != looked.Name || held.Successor != looked.Successor {
		return Record{}, fmt.Errorf(
			"key %s was rotated or renamed since it was looked up: %w", held.Fingerprint, ErrExists,
		)
	}

	if held.Retired != nil {
		return Record{}, fmt.Errorf("key %s is retired: %w", held.Name, ErrInvalid)
	}

	if other, taken := named(records, renamed, false); taken && other.Fingerprint != held.Fingerprint {
		return Record{}, fmt.Errorf("name %q: %w", renamed, ErrExists)
	}

	return held, nil
}

// named is the record a name, or a fingerprint, names among records.
func named(records []Record, handle string, byFingerprint bool) (Record, bool) {
	for _, record := range records {
		if (byFingerprint && record.Fingerprint == handle) || (!byFingerprint && record.Name == handle) {
			return record, true
		}
	}

	return Record{}, false
}

// readAll reads every record and checks that a v0.1 blob file, where one
// remains, has its record.
func (s *Store) readAll() ([]Record, error) {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, fmt.Errorf("reading key store: %w", err)
	}

	var records []Record

	for _, entry := range entries {
		name := entry.Name()

		switch {
		case strings.HasSuffix(name, recordSuffix):
			record, err := s.readNamed(name)
			if err != nil {
				return nil, err
			}

			records = append(records, record)
		case strings.HasSuffix(name, blobSuffix):
			if err := s.checkRecordExists(name); err != nil {
				return nil, err
			}
		}
	}

	sort.Slice(records, func(i, j int) bool {
		if !records[i].Created.Equal(records[j].Created) {
			return records[i].Created.Before(records[j].Created)
		}

		return records[i].Name < records[j].Name
	})

	return records, nil
}

// readNamed reads a record file found in the directory and checks that it
// holds the key its name says.
func (s *Store) readNamed(name string) (Record, error) {
	record, err := readRecordFile(filepath.Join(s.dir, name))
	if err != nil {
		return Record{}, err
	}

	if fileID(record.Fingerprint)+recordSuffix != name {
		return Record{}, fmt.Errorf("record %s holds key %s: %w", name, record.Fingerprint, ErrCorrupt)
	}

	return record, nil
}

// checkRecordExists says a blob file found in the directory has its record.
func (s *Store) checkRecordExists(blobName string) error {
	recordName := strings.TrimSuffix(blobName, blobSuffix) + recordSuffix
	if _, err := os.Stat(filepath.Join(s.dir, recordName)); err != nil {
		return fmt.Errorf("blob %s without its record: %w", blobName, ErrCorrupt)
	}

	return nil
}

func (s *Store) read(fingerprint string) (Record, error) {
	record, err := readRecordFile(s.recordPath(fingerprint))
	if err != nil {
		return Record{}, err
	}

	if record.Fingerprint != fingerprint {
		return Record{}, fmt.Errorf("record of %s holds key %s: %w", fingerprint, record.Fingerprint, ErrCorrupt)
	}

	return record, nil
}

func (s *Store) writeRecord(record Record) error {
	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding record: %w", err)
	}

	if err := filesystem.WriteFile(s.recordPath(record.Fingerprint), append(data, '\n'), fileMode); err != nil {
		return fmt.Errorf("writing record: %w", err)
	}

	return nil
}

func readRecordFile(path string) (Record, error) {
	data, err := readPrivate(path)
	if err != nil {
		return Record{}, err
	}

	var record Record
	if err := json.Unmarshal(data, &record); err != nil {
		return Record{}, fmt.Errorf("decoding %s: %w", filepath.Base(path), ErrCorrupt)
	}

	if err := record.validate(); err != nil {
		return Record{}, fmt.Errorf("%s: %w: %w", filepath.Base(path), ErrCorrupt, err)
	}

	return record, nil
}

// readPrivate reads a file that must be the owner's alone: one readable by
// others is ErrInsecure, one missing is ErrNotFound, one over the record
// bound is ErrCorrupt.
func readPrivate(path string) ([]byte, error) {
	file, err := os.Open(path) // #nosec G304 -- the store's own directory joined with a validated fingerprint
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("%s: %w", filepath.Base(path), ErrNotFound)
		}

		return nil, fmt.Errorf("opening %s: %w", filepath.Base(path), err)
	}

	data, err := readChecked(file)
	if err != nil {
		_ = file.Close()

		return nil, fmt.Errorf("%s: %w", filepath.Base(path), err)
	}

	if err := file.Close(); err != nil {
		return nil, fmt.Errorf("closing %s: %w", filepath.Base(path), err)
	}

	return data, nil
}

func readChecked(file *os.File) ([]byte, error) {
	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat: %w", err)
	}

	if info.Mode().Perm()&othersMask != 0 {
		return nil, fmt.Errorf("mode %o: %w", info.Mode().Perm(), ErrInsecure)
	}

	if info.Size() > maxRecordFile {
		return nil, fmt.Errorf("%d bytes: %w", info.Size(), ErrCorrupt)
	}

	data := make([]byte, info.Size())
	if _, err := io.ReadFull(file, data); err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}

	return data, nil
}
