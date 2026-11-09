package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
)

const blobDir = "blobs"

// blobPath derives the on-disk name. The ids are hashed so that nothing a
// client supplies ever reaches the filesystem, and the separator keeps
// ("ab","c") and ("a","bc") from sharing a file; '/' cannot occur in a valid id.
func blobPath(dir, vaultID, blobID string) string {
	sum := sha256.Sum256([]byte(vaultID + "/" + blobID))
	return filepath.Join(dir, blobDir, hex.EncodeToString(sum[:]))
}

func (s *Store) blobPath(vaultID, blobID string) string { return blobPath(s.dir, vaultID, blobID) }

// PutBlob stores or replaces an attachment. The bytes reach their final name by
// rename, so a reader or a crash never sees a partial file.
func (s *Store) PutBlob(vaultID, blobID string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Join(s.dir, blobDir), "tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	_, err = tmp.Write(data)
	if err == nil {
		err = tmp.Sync()
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.state.Load().Vaults[vaultID]; !ok {
		return ErrNotFound
	}
	size := int64(len(data))
	var p pending
	err = s.txn(func(tx *sql.Tx) error {
		var old int64
		err := tx.QueryRow(`SELECT size FROM blobs WHERE vault_id = ? AND blob_id = ?`, vaultID, blobID).Scan(&old)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		p.delta = size - old
		if s.used+p.delta > s.quota {
			return ErrQuota
		}
		_, err = tx.Exec(`INSERT INTO blobs (vault_id, blob_id, size) VALUES (?, ?, ?)
			ON CONFLICT (vault_id, blob_id) DO UPDATE SET size = excluded.size`, vaultID, blobID, size)
		if err != nil {
			return err
		}
		return os.Rename(tmp.Name(), s.blobPath(vaultID, blobID))
	})
	if err != nil {
		return err
	}
	s.settle(nil, &p)
	return nil
}

// OpenBlob opens an attachment for reading and returns its size.
func (s *Store) OpenBlob(ctx context.Context, vaultID, blobID string) (*os.File, int64, error) {
	var size int64
	err := s.r.QueryRowContext(ctx, `SELECT size FROM blobs WHERE vault_id = ? AND blob_id = ?`, vaultID, blobID).Scan(&size)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, 0, ErrNotFound
	}
	if err != nil {
		return nil, 0, err
	}
	f, err := os.Open(s.blobPath(vaultID, blobID))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, 0, ErrNotFound
	}
	if err != nil {
		return nil, 0, err
	}
	return f, size, nil
}

// DeleteBlob removes an attachment.
func (s *Store) DeleteBlob(vaultID, blobID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var p pending
	err := s.txn(func(tx *sql.Tx) error {
		var size int64
		err := tx.QueryRow(`SELECT size FROM blobs WHERE vault_id = ? AND blob_id = ?`, vaultID, blobID).Scan(&size)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		p.delta = -size
		p.files = []string{s.blobPath(vaultID, blobID)}
		_, err = tx.Exec(`DELETE FROM blobs WHERE vault_id = ? AND blob_id = ?`, vaultID, blobID)
		return err
	})
	if err != nil {
		return err
	}
	s.settle(nil, &p)
	return nil
}

// removeTempBlobFiles deletes partial uploads left by a crash. Files with no
// row are deliberately kept: after restoring an older database they may still
// be wanted, and a leftover file costs nothing but disk.
func (s *Store) removeTempBlobFiles() error {
	files, err := filepath.Glob(filepath.Join(s.dir, blobDir, "tmp-*"))
	if err != nil {
		return err
	}
	for _, f := range files {
		os.Remove(f)
	}
	return nil
}
