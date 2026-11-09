// Package store persists the ledger and the opaque ciphertext around it in
// SQLite plus a blob directory. One writer connection and one mutex serialize
// every write; reads go through a separate query-only pool under WAL.
package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"

	_ "modernc.org/sqlite"

	"mixia/server/internal/ledger"
)

// Sentinel errors, mapped to wire error codes by the api package.
var (
	ErrNotFound    = errors.New("not found")
	ErrBadRequest  = errors.New("bad request")
	ErrStaleGen    = errors.New("stale generation")
	ErrGone        = errors.New("already bootstrapped")
	ErrQuota       = errors.New("storage quota exceeded")
	ErrPairUsed    = errors.New("pair already used")
	ErrPairExpired = errors.New("pair expired")
	ErrPairLimit   = errors.New("too many open pairs")
)

// StaleSnapshotError means a rotate's snapshot was built from a log that has
// moved on since. Head is the vault's current head.
type StaleSnapshotError struct{ Head int64 }

func (e *StaleSnapshotError) Error() string {
	return fmt.Sprintf("snapshot is stale, vault head is %d", e.Head)
}

const dbFile = "mixia.db"

const schema = `
CREATE TABLE IF NOT EXISTS ledger (
	seq  INTEGER PRIMARY KEY,
	body BLOB NOT NULL,
	sig  BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS vaults (
	vault_id TEXT PRIMARY KEY,
	gen      INTEGER NOT NULL,
	head     INTEGER NOT NULL
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS changes (
	vault_id TEXT NOT NULL,
	seq      INTEGER NOT NULL,
	id       TEXT NOT NULL,
	device   TEXT NOT NULL,
	gen      INTEGER NOT NULL,
	data     BLOB NOT NULL,
	PRIMARY KEY (vault_id, seq),
	UNIQUE (vault_id, id)
);
CREATE TABLE IF NOT EXISTS keys (
	vault_id  TEXT NOT NULL,
	device_id TEXT NOT NULL,
	gen       INTEGER NOT NULL,
	wrapped   BLOB NOT NULL,
	PRIMARY KEY (vault_id, device_id, gen)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS keys_by_device ON keys (device_id);
CREATE TABLE IF NOT EXISTS blobs (
	vault_id TEXT NOT NULL,
	blob_id  TEXT NOT NULL,
	size     INTEGER NOT NULL,
	PRIMARY KEY (vault_id, blob_id)
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS pairs (
	pair_id    TEXT PRIMARY KEY,
	token_hash BLOB NOT NULL,
	expires_at INTEGER NOT NULL,
	offer      BLOB NOT NULL,
	request    BLOB,
	grant_msg  BLOB,
	fails      INTEGER NOT NULL DEFAULT 0
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS audit (
	id     INTEGER PRIMARY KEY AUTOINCREMENT,
	ts     INTEGER NOT NULL,
	device TEXT NOT NULL,
	action TEXT NOT NULL,
	detail TEXT NOT NULL
);
`

// Store is the persistence layer. All exported methods are safe for concurrent
// use.
type Store struct {
	dir   string
	quota int64
	w     *sql.DB
	r     *sql.DB

	mu    sync.Mutex // serializes writers; guards used
	used  int64      // bytes of change payloads plus blob files
	state atomic.Pointer[ledger.State]
}

// sqliteDSN builds a file: URI. It is percent-encoded so that non-ASCII paths
// and characters such as '?' in the data directory cannot alter the DSN.
func sqliteDSN(path string, params ...string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	p := filepath.ToSlash(abs)
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	u := url.URL{Scheme: "file", Path: p}
	return u.String() + "?" + strings.Join(params, "&"), nil
}

// Open opens or creates the store in dir. It replays the ledger and refuses to
// return if the stored data does not verify.
func Open(dir string, quota int64) (*Store, error) {
	if err := os.MkdirAll(filepath.Join(dir, blobDir), 0o700); err != nil {
		return nil, err
	}
	path := filepath.Join(dir, dbFile)
	// SQLite gives the -wal and -shm files the mode of the main database.
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	f.Close()

	s := &Store{dir: dir, quota: quota}
	if err := s.open(path); err != nil {
		s.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) open(path string) error {
	ctx := context.Background()
	wdsn, err := sqliteDSN(path,
		"_pragma=busy_timeout(10000)", "_pragma=journal_mode(WAL)",
		"_pragma=synchronous(FULL)", "_txlock=immediate")
	if err != nil {
		return err
	}
	if s.w, err = sql.Open("sqlite", wdsn); err != nil {
		return err
	}
	s.w.SetMaxOpenConns(1)
	s.w.SetConnMaxLifetime(0)
	s.w.SetConnMaxIdleTime(0)
	if _, err := s.w.ExecContext(ctx, schema); err != nil {
		return fmt.Errorf("create schema: %w", err)
	}

	rdsn, err := sqliteDSN(path, "_pragma=busy_timeout(10000)", "_pragma=query_only(1)")
	if err != nil {
		return err
	}
	if s.r, err = sql.Open("sqlite", rdsn); err != nil {
		return err
	}
	s.r.SetMaxOpenConns(8)

	st, err := replay(ctx, s.w)
	if err != nil {
		return err
	}
	if err := checkVaultTable(ctx, s.w, st); err != nil {
		return err
	}
	s.state.Store(st)

	var changeBytes, blobBytes int64
	if err := s.w.QueryRowContext(ctx, `SELECT COALESCE(SUM(LENGTH(data)),0) FROM changes`).Scan(&changeBytes); err != nil {
		return err
	}
	if err := s.w.QueryRowContext(ctx, `SELECT COALESCE(SUM(size),0) FROM blobs`).Scan(&blobBytes); err != nil {
		return err
	}
	s.used = changeBytes + blobBytes
	return s.removeTempBlobFiles()
}

// Close releases the database handles. The writer closes last so that SQLite
// can checkpoint the WAL.
func (s *Store) Close() error {
	var errs []error
	if s.r != nil {
		errs = append(errs, s.r.Close())
	}
	if s.w != nil {
		errs = append(errs, s.w.Close())
	}
	return errors.Join(errs...)
}

// State returns the current immutable ledger state.
func (s *Store) State() *ledger.State { return s.state.Load() }

type querier interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

func readLedger(ctx context.Context, q querier, from int64) ([]ledger.Wire, error) {
	rows, err := q.QueryContext(ctx, `SELECT body, sig FROM ledger WHERE seq >= ? ORDER BY seq`, from)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ledger.Wire{}
	for rows.Next() {
		var w ledger.Wire
		if err := rows.Scan((*[]byte)(&w.Body), (*[]byte)(&w.Sig)); err != nil {
			return nil, err
		}
		out = append(out, w)
	}
	return out, rows.Err()
}

func replay(ctx context.Context, q querier) (*ledger.State, error) {
	entries, err := readLedger(ctx, q, 0)
	if err != nil {
		return nil, fmt.Errorf("read ledger: %w", err)
	}
	st, err := ledger.Replay(entries)
	if err != nil {
		return nil, fmt.Errorf("ledger verification failed: %w", err)
	}
	return st, nil
}

// checkVaultTable confirms the vaults table agrees with the replayed ledger.
func checkVaultTable(ctx context.Context, q querier, st *ledger.State) error {
	rows, err := q.QueryContext(ctx, `SELECT vault_id, gen FROM vaults`)
	if err != nil {
		return err
	}
	defer rows.Close()
	seen := 0
	for rows.Next() {
		var id string
		var gen int64
		if err := rows.Scan(&id, &gen); err != nil {
			return err
		}
		v, ok := st.Vaults[id]
		if !ok || v.Gen != gen {
			return errors.New("vaults table disagrees with ledger")
		}
		seen++
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if seen != len(st.Vaults) {
		return errors.New("vaults table disagrees with ledger")
	}
	return nil
}

// txn runs fn in a write transaction; the caller holds s.mu. It deliberately
// ignores the request context: once started, a transaction should finish even
// if the client goes away.
func (s *Store) txn(fn func(tx *sql.Tx) error) error {
	tx, err := s.w.BeginTx(context.Background(), nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit()
}

// pending collects what must happen only after a transaction has committed.
type pending struct {
	delta int64    // change in s.used
	files []string // blob files to unlink
}

func (s *Store) settle(next *ledger.State, p *pending) {
	if next != nil {
		s.state.Store(next)
	}
	s.used += p.delta
	for _, f := range p.files {
		os.Remove(f)
	}
}

// applyEntries advances next through entries and returns their effects.
// vault_rotate and root_rotate are refused here: each is only valid together
// with the key replacement that its own endpoint performs atomically.
func applyEntries(next *ledger.State, entries []*ledger.Entry) ([]ledger.Effect, error) {
	effects := make([]ledger.Effect, 0, len(entries))
	for _, e := range entries {
		if e.Type == ledger.TypeVaultRotate || e.Type == ledger.TypeRootRotate {
			return nil, ledger.Invalid("this entry type has its own endpoint")
		}
		eff, err := next.Apply(e)
		if err != nil {
			return nil, err
		}
		effects = append(effects, eff)
	}
	return effects, nil
}

func insertEntry(tx *sql.Tx, e *ledger.Entry) error {
	_, err := tx.Exec(`INSERT INTO ledger (seq, body, sig) VALUES (?, ?, ?)`, e.Seq, e.Body, e.Sig)
	return err
}

func (s *Store) writeEntries(tx *sql.Tx, entries []*ledger.Entry, effects []ledger.Effect, actor string, now int64, p *pending) error {
	for i, e := range entries {
		if err := insertEntry(tx, e); err != nil {
			return err
		}
		if err := s.applyEffect(tx, effects[i], p); err != nil {
			return err
		}
		if err := audit(tx, now, actor, effects[i].Action, effects[i].Detail); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) applyEffect(tx *sql.Tx, eff ledger.Effect, p *pending) error {
	if eff.AddedVault != "" {
		if _, err := tx.Exec(`INSERT INTO vaults (vault_id, gen, head) VALUES (?, 1, 0)`, eff.AddedVault); err != nil {
			return err
		}
	}
	if eff.RevokedDevice != "" {
		if _, err := tx.Exec(`DELETE FROM keys WHERE device_id = ?`, eff.RevokedDevice); err != nil {
			return err
		}
	}
	for _, v := range eff.NarrowedVaults {
		if _, err := tx.Exec(`DELETE FROM keys WHERE vault_id = ? AND device_id = ?`, v, eff.NarrowedDevice); err != nil {
			return err
		}
	}
	if eff.DeletedVault != "" {
		return s.dropVault(tx, eff.DeletedVault, p)
	}
	return nil
}

func (s *Store) dropVault(tx *sql.Tx, id string, p *pending) error {
	var changeBytes int64
	if err := tx.QueryRow(`SELECT COALESCE(SUM(LENGTH(data)),0) FROM changes WHERE vault_id = ?`, id).Scan(&changeBytes); err != nil {
		return err
	}
	rows, err := tx.Query(`SELECT blob_id, size FROM blobs WHERE vault_id = ?`, id)
	if err != nil {
		return err
	}
	defer rows.Close()
	p.delta -= changeBytes
	for rows.Next() {
		var blobID string
		var size int64
		if err := rows.Scan(&blobID, &size); err != nil {
			return err
		}
		p.delta -= size
		p.files = append(p.files, s.blobPath(id, blobID))
	}
	if err := rows.Err(); err != nil {
		return err
	}
	rows.Close()
	for _, q := range []string{
		`DELETE FROM changes WHERE vault_id = ?`,
		`DELETE FROM keys WHERE vault_id = ?`,
		`DELETE FROM blobs WHERE vault_id = ?`,
		`DELETE FROM vaults WHERE vault_id = ?`,
	} {
		if _, err := tx.Exec(q, id); err != nil {
			return err
		}
	}
	return nil
}

// Key is a wrapped vault key addressed to a device or to "recovery".
type Key struct {
	VaultID  string     `json:"vaultId"`
	DeviceID string     `json:"deviceId"`
	Gen      int64      `json:"gen"`
	Wrapped  ledger.B64 `json:"wrapped"`
}

func checkKey(st *ledger.State, k Key) error {
	if len(k.Wrapped) == 0 {
		return ErrBadRequest
	}
	if k.DeviceID == ledger.Recovery {
		return nil
	}
	if _, ok := st.ActiveDevice(k.DeviceID); !ok {
		return ErrBadRequest
	}
	return nil
}

func writeKeys(tx *sql.Tx, keys []Key) error {
	for _, k := range keys {
		_, err := tx.Exec(`INSERT INTO keys (vault_id, device_id, gen, wrapped) VALUES (?, ?, ?, ?)
			ON CONFLICT (vault_id, device_id, gen) DO UPDATE SET wrapped = excluded.wrapped`,
			k.VaultID, k.DeviceID, k.Gen, []byte(k.Wrapped))
		if err != nil {
			return err
		}
	}
	return nil
}

// Bootstrap atomically writes the initial ledger and its key wraps. It succeeds
// at most once per database: the presence of genesis is the permanent marker.
func (s *Store) Bootstrap(entries []*ledger.Entry, keys []Key, now int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cur := s.state.Load()
	if cur.Bootstrapped() {
		return ErrGone
	}
	next := cur.Clone()
	effects, err := applyEntries(next, entries)
	if err != nil {
		return err
	}
	for _, k := range keys {
		v, ok := next.Vaults[k.VaultID]
		if !ok || k.Gen != v.Gen {
			return ErrBadRequest
		}
		if err := checkKey(next, k); err != nil {
			return err
		}
	}
	var p pending
	err = s.txn(func(tx *sql.Tx) error {
		if err := s.writeEntries(tx, entries, effects, ledger.Root, now, &p); err != nil {
			return err
		}
		if err := writeKeys(tx, keys); err != nil {
			return err
		}
		return audit(tx, now, ledger.Root, "bootstrap", fmt.Sprintf("entries=%d keys=%d", len(entries), len(keys)))
	})
	if err != nil {
		return err
	}
	s.settle(next, &p)
	return nil
}

// AppendLedger validates entries in order and appends them atomically. It
// returns the new head.
func (s *Store) AppendLedger(entries []*ledger.Entry, actor string, now int64) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cur := s.state.Load()
	next := cur.Clone()
	effects, err := applyEntries(next, entries)
	if err != nil {
		var ce *ledger.ConflictError
		if errors.As(err, &ce) {
			// Report the committed head, not the batch's working head.
			ce.Head = cur.Head
		}
		return 0, err
	}
	if len(entries) == 0 {
		return cur.Head, nil
	}
	var p pending
	err = s.txn(func(tx *sql.Tx) error {
		return s.writeEntries(tx, entries, effects, actor, now, &p)
	})
	if err != nil {
		return 0, err
	}
	s.settle(next, &p)
	return next.Head, nil
}

// Ledger returns entries with seq >= from and the current head.
func (s *Store) Ledger(ctx context.Context, from int64) ([]ledger.Wire, int64, error) {
	tx, err := s.r.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, 0, err
	}
	defer tx.Rollback()
	entries, err := readLedger(ctx, tx, from)
	if err != nil {
		return nil, 0, err
	}
	var head int64
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(seq), -1) FROM ledger`).Scan(&head); err != nil {
		return nil, 0, err
	}
	return entries, head, nil
}

// Change is a stored change as seen by clients.
type Change struct {
	Seq    int64      `json:"seq"`
	ID     string     `json:"id"`
	Device string     `json:"device"`
	Gen    int64      `json:"gen"`
	Blob   ledger.B64 `json:"blob"`
}

// NewChange is a change submitted by a client.
type NewChange struct {
	ID   string     `json:"id"`
	Gen  int64      `json:"gen"`
	Blob ledger.B64 `json:"blob"`
}

// Accepted reports the seq assigned to a submitted change id.
type Accepted struct {
	ID  string `json:"id"`
	Seq int64  `json:"seq"`
}

func checkNewChange(c NewChange) error {
	if !ledger.ValidID(c.ID) || len(c.Blob) == 0 {
		return ErrBadRequest
	}
	return nil
}

func insertChange(tx *sql.Tx, vaultID string, seq int64, device string, c NewChange) error {
	_, err := tx.Exec(`INSERT INTO changes (vault_id, seq, id, device, gen, data) VALUES (?, ?, ?, ?, ?, ?)`,
		vaultID, seq, c.ID, device, c.Gen, []byte(c.Blob))
	return err
}

// PutChanges appends changes, assigning consecutive seqs. Ids already present
// in the vault are not rewritten; their original seq is returned. The batch is
// all-or-nothing.
func (s *Store) PutChanges(vaultID, device string, changes []NewChange) ([]Accepted, int64, error) {
	for _, c := range changes {
		if err := checkNewChange(c); err != nil {
			return nil, 0, err
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.state.Load().Vaults[vaultID]
	if !ok {
		return nil, 0, ErrNotFound
	}
	for _, c := range changes {
		if c.Gen != v.Gen {
			return nil, 0, ErrStaleGen
		}
	}
	accepted := make([]Accepted, 0, len(changes))
	var head int64
	var p pending
	err := s.txn(func(tx *sql.Tx) error {
		if err := tx.QueryRow(`SELECT head FROM vaults WHERE vault_id = ?`, vaultID).Scan(&head); err != nil {
			return err
		}
		for _, c := range changes {
			var seq int64
			err := tx.QueryRow(`SELECT seq FROM changes WHERE vault_id = ? AND id = ?`, vaultID, c.ID).Scan(&seq)
			if err == nil {
				accepted = append(accepted, Accepted{ID: c.ID, Seq: seq})
				continue
			}
			if !errors.Is(err, sql.ErrNoRows) {
				return err
			}
			p.delta += int64(len(c.Blob))
			if s.used+p.delta > s.quota {
				return ErrQuota
			}
			head++
			if err := insertChange(tx, vaultID, head, device, c); err != nil {
				return err
			}
			accepted = append(accepted, Accepted{ID: c.ID, Seq: head})
		}
		_, err := tx.Exec(`UPDATE vaults SET head = ? WHERE vault_id = ?`, head, vaultID)
		return err
	})
	if err != nil {
		return nil, 0, err
	}
	s.settle(nil, &p)
	return accepted, head, nil
}

// ChangePage is one page of a vault's change log.
type ChangePage struct {
	Changes []Change `json:"changes"`
	Head    int64    `json:"head"`
	Base    int64    `json:"base"`
	Gen     int64    `json:"gen"`
}

// Changes returns up to limit changes with seq > max(after, base-1).
func (s *Store) Changes(ctx context.Context, vaultID string, after int64, limit int) (*ChangePage, error) {
	tx, err := s.r.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	page := &ChangePage{Changes: []Change{}}
	err = tx.QueryRowContext(ctx, `SELECT gen, head FROM vaults WHERE vault_id = ?`, vaultID).Scan(&page.Gen, &page.Head)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	var minSeq sql.NullInt64
	if err := tx.QueryRowContext(ctx, `SELECT MIN(seq) FROM changes WHERE vault_id = ?`, vaultID).Scan(&minSeq); err != nil {
		return nil, err
	}
	page.Base = page.Head + 1
	if minSeq.Valid {
		page.Base = minSeq.Int64
	}
	rows, err := tx.QueryContext(ctx, `SELECT seq, id, device, gen, data FROM changes
		WHERE vault_id = ? AND seq > ? ORDER BY seq LIMIT ?`, vaultID, max(after, page.Base-1), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var c Change
		if err := rows.Scan(&c.Seq, &c.ID, &c.Device, &c.Gen, (*[]byte)(&c.Blob)); err != nil {
			return nil, err
		}
		page.Changes = append(page.Changes, c)
	}
	return page, rows.Err()
}

// WrappedKey is a key wrap as returned to its recipient.
type WrappedKey struct {
	Gen     int64      `json:"gen"`
	Wrapped ledger.B64 `json:"wrapped"`
}

// Keys returns the wraps addressed to deviceID in a vault.
func (s *Store) Keys(ctx context.Context, vaultID, deviceID string) ([]WrappedKey, error) {
	rows, err := s.r.QueryContext(ctx, `SELECT gen, wrapped FROM keys WHERE vault_id = ? AND device_id = ? ORDER BY gen`, vaultID, deviceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []WrappedKey{}
	for rows.Next() {
		var k WrappedKey
		if err := rows.Scan(&k.Gen, (*[]byte)(&k.Wrapped)); err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

// PutKeys upserts wraps for the vault's current generation.
func (s *Store) PutKeys(vaultID string, keys []Key, actor string, now int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.state.Load()
	v, ok := st.Vaults[vaultID]
	if !ok {
		return ErrNotFound
	}
	for i := range keys {
		keys[i].VaultID = vaultID
		if keys[i].Gen != v.Gen {
			return ErrStaleGen
		}
		if err := checkKey(st, keys[i]); err != nil {
			return err
		}
	}
	if len(keys) == 0 {
		return nil
	}
	return s.txn(func(tx *sql.Tx) error {
		if err := writeKeys(tx, keys); err != nil {
			return err
		}
		return audit(tx, now, actor, "keys_put", fmt.Sprintf("vault=%s count=%d", vaultID, len(keys)))
	})
}

// snapshotHash computes spec section 6: SHA256 over id (UTF-8) || blob bytes, in order.
func snapshotHash(snapshot []NewChange) string {
	h := sha256.New()
	for _, c := range snapshot {
		h.Write([]byte(c.ID))
		h.Write(c.Blob)
	}
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}

// wrapsComplete reports whether keys cover recovery and every active device with access.
func wrapsComplete(st *ledger.State, vaultID string, keys []Key) bool {
	have := make(map[string]bool, len(keys))
	for _, k := range keys {
		have[k.DeviceID] = true
	}
	if !have[ledger.Recovery] {
		return false
	}
	for _, d := range st.Devices {
		if !d.Revoked && d.HasVault(vaultID) && !have[d.ID] {
			return false
		}
	}
	return true
}

// Rotate performs spec section 6 atomically: it appends the vault_rotate entry,
// discards the old log and every old wrap, and writes the snapshot and new
// wraps. Nothing changes unless all of it succeeds.
func (s *Store) Rotate(vaultID string, e *ledger.Entry, keys []Key, snapshot []NewChange, actor string, now int64) error {
	if e.Type != ledger.TypeVaultRotate || e.VaultID() != vaultID {
		return ledger.Invalid("entry is not a vault_rotate for this vault")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	next := s.state.Load().Clone()
	eff, err := next.Apply(e)
	if err != nil {
		return err
	}
	if e.SnapshotCount() != int64(len(snapshot)) {
		return ErrBadRequest
	}
	gen := next.Vaults[vaultID].Gen
	ids := make(map[string]struct{}, len(snapshot))
	var newBytes int64
	for _, c := range snapshot {
		if err := checkNewChange(c); err != nil {
			return err
		}
		if _, dup := ids[c.ID]; dup || c.Gen != gen {
			return ErrBadRequest
		}
		ids[c.ID] = struct{}{}
		newBytes += int64(len(c.Blob))
	}
	for i := range keys {
		keys[i].VaultID = vaultID
		if keys[i].Gen != gen {
			return ErrBadRequest
		}
		if err := checkKey(next, keys[i]); err != nil {
			return err
		}
	}
	// 旧日志一旦删除就回不来了，所以这里替客户端把最后一道关：
	// 快照必须和已签名的哈希一致，封装必须覆盖全部有权设备和账户恢复。
	if snapshotHash(snapshot) != e.SnapshotHash() || !wrapsComplete(next, vaultID, keys) {
		return ErrBadRequest
	}
	var p pending
	err = s.txn(func(tx *sql.Tx) error {
		var head, oldBytes int64
		if err := tx.QueryRow(`SELECT head FROM vaults WHERE vault_id = ?`, vaultID).Scan(&head); err != nil {
			return err
		}
		// A change accepted after the client took its snapshot is in neither
		// the snapshot nor, once the old log is dropped, anywhere else.
		if e.LogHead() != head {
			return &StaleSnapshotError{Head: head}
		}
		if err := tx.QueryRow(`SELECT COALESCE(SUM(LENGTH(data)),0) FROM changes WHERE vault_id = ?`, vaultID).Scan(&oldBytes); err != nil {
			return err
		}
		p.delta = newBytes - oldBytes
		if s.used+p.delta > s.quota {
			return ErrQuota
		}
		if err := insertEntry(tx, e); err != nil {
			return err
		}
		if _, err := tx.Exec(`DELETE FROM changes WHERE vault_id = ?`, vaultID); err != nil {
			return err
		}
		if _, err := tx.Exec(`DELETE FROM keys WHERE vault_id = ?`, vaultID); err != nil {
			return err
		}
		if err := writeKeys(tx, keys); err != nil {
			return err
		}
		for _, c := range snapshot {
			head++
			if err := insertChange(tx, vaultID, head, actor, c); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(`UPDATE vaults SET gen = ?, head = ? WHERE vault_id = ?`, gen, head, vaultID); err != nil {
			return err
		}
		return audit(tx, now, actor, eff.Action, eff.Detail)
	})
	if err != nil {
		return err
	}
	s.settle(next, &p)
	return nil
}

// RootRotate appends a root_rotate entry and replaces every recovery wrap in
// one transaction. The new recovery key has to open every vault from the moment
// the old root stops being valid, so keys must hold exactly one wrap for the
// current generation of each vault.
func (s *Store) RootRotate(e *ledger.Entry, keys []Key, now int64) error {
	if e.Type != ledger.TypeRootRotate {
		return ledger.Invalid("entry is not a root_rotate")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	next := s.state.Load().Clone()
	eff, err := next.Apply(e)
	if err != nil {
		return err
	}
	seen := make(map[string]struct{}, len(keys))
	for i := range keys {
		k := &keys[i]
		v, ok := next.Vaults[k.VaultID]
		_, dup := seen[k.VaultID]
		if !ok || dup || k.Gen != v.Gen || len(k.Wrapped) == 0 || (k.DeviceID != "" && k.DeviceID != ledger.Recovery) {
			return ErrBadRequest
		}
		seen[k.VaultID] = struct{}{}
		k.DeviceID = ledger.Recovery
	}
	if len(seen) != len(next.Vaults) {
		return ErrBadRequest
	}
	var p pending
	err = s.txn(func(tx *sql.Tx) error {
		if err := insertEntry(tx, e); err != nil {
			return err
		}
		if _, err := tx.Exec(`DELETE FROM keys WHERE device_id = ?`, ledger.Recovery); err != nil {
			return err
		}
		if err := writeKeys(tx, keys); err != nil {
			return err
		}
		return audit(tx, now, ledger.Root, eff.Action, fmt.Sprintf("vaults=%d", len(keys)))
	})
	if err != nil {
		return err
	}
	s.settle(next, &p)
	return nil
}
