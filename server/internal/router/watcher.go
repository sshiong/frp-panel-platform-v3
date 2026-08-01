package router

import (
	"context"
	"errors"
	"os"
	"time"
)

// Watcher is the Router-side file/IPC adapter. Control writes a complete
// signed snapshot atomically; the watcher reloads it without touching SQLite
// and keeps the previous in-memory table when the new file is invalid.
type Watcher struct {
	Runtime      *Runtime
	SnapshotPath string
	Interval     time.Duration
	OnError      func(error)
}

func (w *Watcher) Run(ctx context.Context) error {
	if w == nil || w.Runtime == nil || w.SnapshotPath == "" {
		return errors.New("router watcher is not configured")
	}
	interval := w.Interval
	if interval <= 0 {
		interval = 250 * time.Millisecond
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	var fingerprint fileFingerprint
	for {
		fingerprint = w.reloadIfChanged(fingerprint)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

type fileFingerprint struct {
	modified time.Time
	size     int64
	present  bool
}

func (w *Watcher) reloadIfChanged(previous fileFingerprint) fileFingerprint {
	info, err := os.Stat(w.SnapshotPath)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) && w.OnError != nil {
			w.OnError(err)
		}
		return fileFingerprint{}
	}
	current := fileFingerprint{modified: info.ModTime(), size: info.Size(), present: true}
	if current == previous {
		return previous
	}
	if err := w.Runtime.LoadFile(w.SnapshotPath); err != nil {
		// A bad snapshot must not displace last-good. The next atomic write has
		// a new fingerprint and will be tried again.
		if w.OnError != nil {
			w.OnError(err)
		}
	}
	return current
}
