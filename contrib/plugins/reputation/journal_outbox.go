package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

const maximumJournalRecordBytes = 256 * 1024

type journalOutbox struct {
	directory  string
	maxBytes   int64
	maxRecords int
}

type outboxRecord struct {
	Key   string
	Value []byte
}

// openJournalOutbox binds a bounded persistent directory shared by replacement processes.
func openJournalOutbox(directory string, maxRecords int, maxBytes int64) (*journalOutbox, error) {
	if !filepath.IsAbs(directory) || maxRecords < 1 || maxRecords > 100000 || maxBytes < 1 {
		return nil, errConfiguration
	}

	if err := os.MkdirAll(directory, 0700); err != nil {
		return nil, errStateUnavailable
	}

	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errStateUnavailable
	}

	return &journalOutbox{directory: directory, maxRecords: maxRecords, maxBytes: maxBytes}, nil
}

// withLock serializes capacity accounting and recovery across replicas on a lock-capable persistent filesystem.
func (b *journalOutbox) withLock(ctx context.Context, action func() error) error {
	fd, err := unix.Open(filepath.Join(b.directory, ".lock"), unix.O_CREAT|unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return errStateUnavailable
	}

	defer func() { _ = unix.Close(fd) }()

	for {
		if err := ctx.Err(); err != nil {
			return err
		}

		err = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			defer func() { _ = unix.Flock(fd, unix.LOCK_UN) }()
			return action()
		}

		if !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EAGAIN) {
			return errStateUnavailable
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(20 * time.Millisecond):
		}
	}
}

// recordName keeps even opaque event identifiers out of directory listings.
func recordName(key string) string {
	digest := sha256.Sum256([]byte(key))
	return hex.EncodeToString(digest[:]) + ".record"
}

// put acknowledges only a synced immutable record and directory entry; retries cannot replace its content.
func (b *journalOutbox) put(ctx context.Context, key string, value []byte) error {
	if len(key) < 1 || len(key) > 128 || len(value) < 1 || len(value) > maximumJournalRecordBytes {
		return errManifestPlan
	}

	encoded, err := json.Marshal(outboxRecord{Key: key, Value: value})
	if err != nil {
		return errManifestPlan
	}

	return b.withLock(ctx, func() error { return b.putLocked(key, value, encoded) })
}

// putLocked compares exact retries before reserving persistent capacity under the outbox lock.
func (b *journalOutbox) putLocked(key string, value, encoded []byte) error {
	name := recordName(key)

	existing, err := b.readRecord(name)
	if err == nil {
		if existing.Key != key || !bytes.Equal(existing.Value, value) {
			return errEventConflict
		}

		return b.syncDirectory()
	}

	if !errors.Is(err, os.ErrNotExist) {
		return errStateUnavailable
	}

	entries, size, err := b.inventory()
	if err != nil {
		return err
	}

	if len(entries) >= b.maxRecords || int64(len(encoded)) > b.maxBytes-size {
		return errQuotaExceeded
	}

	return b.writeRecord(name, encoded)
}

// inventory rejects unexpected objects and counts actual bytes while holding the interprocess lock.
func (b *journalOutbox) inventory() ([]string, int64, error) {
	entries, err := os.ReadDir(b.directory)
	if err != nil {
		return nil, 0, errStateUnavailable
	}

	var (
		size    int64
		records []string
	)

	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() {
			return nil, 0, errStateUnavailable
		}

		if entry.Name() == ".lock" {
			continue
		}

		if strings.HasPrefix(entry.Name(), ".pending-") {
			if err := os.Remove(filepath.Join(b.directory, entry.Name())); err != nil {
				return nil, 0, errStateUnavailable
			}

			continue
		}

		if !strings.HasSuffix(entry.Name(), ".record") || info.Size() > 2*maximumJournalRecordBytes {
			return nil, 0, errStateUnavailable
		}

		records = append(records, entry.Name())
		size += info.Size()
	}

	return records, size, nil
}

// writeRecord publishes a fully synced temporary file with an atomic rename under the outbox lock.
func (b *journalOutbox) writeRecord(name string, encoded []byte) error {
	file, err := os.CreateTemp(b.directory, ".pending-")
	if err != nil {
		return errStateUnavailable
	}

	defer func() { _ = os.Remove(file.Name()) }()
	defer func() { _ = file.Close() }()

	if _, err := file.Write(encoded); err != nil {
		return errStateUnavailable
	}

	if err := file.Sync(); err != nil {
		return errStateUnavailable
	}

	if err := file.Close(); err != nil {
		return errStateUnavailable
	}

	if err := os.Rename(file.Name(), filepath.Join(b.directory, name)); err != nil {
		return errStateUnavailable
	}

	return b.syncDirectory()
}

// syncDirectory makes successful creation and deletion receipts durable across process replacement.
func (b *journalOutbox) syncDirectory() error {
	directory, err := os.Open(b.directory)
	if err != nil {
		return errStateUnavailable
	}

	defer func() { _ = directory.Close() }()

	return directory.Sync()
}

// readRecord bounds decoding and rejects symlinks, mismatched keys and malformed recovery records.
func (b *journalOutbox) readRecord(name string) (outboxRecord, error) {
	fd, err := unix.Open(filepath.Join(b.directory, name), unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return outboxRecord{}, err
	}

	file := os.NewFile(uintptr(fd), name)
	defer func() { _ = file.Close() }()

	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > 2*maximumJournalRecordBytes {
		return outboxRecord{}, errStateUnavailable
	}

	decoder := json.NewDecoder(io.LimitReader(file, 2*maximumJournalRecordBytes+1))
	decoder.DisallowUnknownFields()

	var record outboxRecord
	if err := decoder.Decode(&record); err != nil || recordName(record.Key) != name || len(record.Key) > 128 || len(record.Key) == 0 || len(record.Value) == 0 || len(record.Value) > maximumJournalRecordBytes {
		return outboxRecord{}, errStateUnavailable
	}

	if decoder.Decode(new(any)) != io.EOF {
		return outboxRecord{}, errStateUnavailable
	}

	return record, nil
}

// drain removes each record only after the downstream sink confirms durable acceptance.
func (b *journalOutbox) drain(ctx context.Context, deliver func(context.Context, string, []byte) error) error {
	return b.withLock(ctx, func() error {
		records, _, err := b.inventory()
		if err != nil {
			return err
		}

		for _, name := range records {
			if err := ctx.Err(); err != nil {
				return err
			}

			record, err := b.readRecord(name)
			if err != nil {
				return err
			}

			if err := deliver(ctx, record.Key, record.Value); err != nil {
				return err
			}

			if err := os.Remove(filepath.Join(b.directory, name)); err != nil {
				return errStateUnavailable
			}

			if err := b.syncDirectory(); err != nil {
				return err
			}
		}

		return nil
	})
}
