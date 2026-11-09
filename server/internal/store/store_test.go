package store

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"mixia/server/internal/ledger"
)

func openTest(t *testing.T) (*Store, string) {
	t.Helper()
	dir := t.TempDir()
	s, err := Open(dir, 1<<30)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s, dir
}

// signed builds an entry signed by the seeded root.
type signed func(seq int64, prev, typ string, data map[string]any) *ledger.Entry

// seed writes a genesis entry and one vault. It returns the root's entry builder
// and the last entry written.
func seed(t *testing.T, s *Store) (signed, *ledger.Entry) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	mk := func(seq int64, prev, typ string, data map[string]any) *ledger.Entry {
		body, err := json.Marshal(map[string]any{"v": 1, "seq": seq, "prev": prev, "ts": 1, "signer": "root", "type": typ, "data": data})
		if err != nil {
			t.Fatal(err)
		}
		sig := ed25519.Sign(priv, append([]byte("mixia/ledger/v1\n"), body...))
		e, err := ledger.Parse(ledger.Wire{Body: body, Sig: sig})
		if err != nil {
			t.Fatal(err)
		}
		return e
	}
	genesis := mk(0, "", ledger.TypeGenesis, map[string]any{
		"ownerId": "o", "rootPub": ledger.EncodeB64(pub), "recoveryBoxPub": ledger.EncodeB64(make([]byte, 32)),
	})
	vault := mk(1, ledger.EncodeB64(genesis.Hash()), ledger.TypeVaultAdd, map[string]any{"vaultId": "v", "gen": 1, "keyCommit": ledger.EncodeB64(make([]byte, 32))})
	if err := s.Bootstrap([]*ledger.Entry{genesis, vault}, nil, 1); err != nil {
		t.Fatal(err)
	}
	return mk, vault
}

// No normal path leaves a recovery wrap for an old generation behind, but one
// that did would still open with the retired recovery code.
func TestRootRotateRemovesEveryRecoveryRow(t *testing.T) {
	s, _ := openTest(t)
	mk, last := seed(t, s)
	if _, err := s.w.Exec(`INSERT INTO keys (vault_id, device_id, gen, wrapped) VALUES ('v', 'recovery', 0, x'00')`); err != nil {
		t.Fatal(err)
	}
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	e := mk(2, ledger.EncodeB64(last.Hash()), ledger.TypeRootRotate, map[string]any{
		"rootPub": ledger.EncodeB64(pub), "recoveryBoxPub": ledger.EncodeB64(make([]byte, 32)),
	})
	if err := s.RootRotate(e, []Key{{VaultID: "v", Gen: 1, Wrapped: []byte("wrap")}}, 1); err != nil {
		t.Fatal(err)
	}
	keys, err := s.Keys(context.Background(), "v", ledger.Recovery)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 || keys[0].Gen != 1 || string(keys[0].Wrapped) != "wrap" {
		t.Fatalf("recovery rows = %+v", keys)
	}
}

func TestAuditKeepsNewest5000(t *testing.T) {
	s, _ := openTest(t)
	const total = auditKeep + 25
	s.mu.Lock()
	err := s.txn(func(tx *sql.Tx) error {
		for i := 1; i <= total; i++ {
			if err := audit(tx, int64(i), "d", "a", ""); err != nil {
				return err
			}
		}
		return nil
	})
	s.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	var count, oldest int64
	if err := s.r.QueryRow(`SELECT COUNT(*), MIN(ts) FROM audit`).Scan(&count, &oldest); err != nil {
		t.Fatal(err)
	}
	if count != auditKeep || oldest != total-auditKeep+1 {
		t.Fatalf("count=%d oldest=%d", count, oldest)
	}
	events, err := s.Audit(context.Background(), 1)
	if err != nil || len(events) != 1 || events[0].Ts != total {
		t.Fatalf("newest = %v, %v", events, err)
	}
}

func TestBackupWhileOpenAndVerify(t *testing.T) {
	s, dir := openTest(t)
	seed(t, s)
	if _, _, err := s.PutChanges("v", "dev", []NewChange{{ID: "a", Gen: 1, Blob: []byte("x")}}); err != nil {
		t.Fatal(err)
	}

	// Writers keep going during the backup.
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			if _, _, err := s.PutChanges("v", "dev", []NewChange{{ID: fmt.Sprintf("c%d", i), Gen: 1, Blob: []byte("x")}}); err != nil {
				t.Error(err)
				return
			}
		}
	}()
	dest := filepath.Join(t.TempDir(), "backup 密匣.db")
	err := Backup(dir, dest)
	close(stop)
	wg.Wait()
	if err != nil {
		t.Fatal(err)
	}

	if err := Backup(dir, dest); err == nil {
		t.Fatal("backup overwrote an existing file")
	}

	// The copy is a working store.
	restored := t.TempDir()
	data, err := os.ReadFile(dest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(restored, dbFile), data, 0o600); err != nil {
		t.Fatal(err)
	}
	sum, err := Verify(restored)
	if err != nil {
		t.Fatal(err)
	}
	if sum.Head != 1 || sum.Vaults != 1 || sum.Changes < 1 {
		t.Fatalf("summary = %+v", sum)
	}
	r, err := Open(restored, 1<<30)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if r.State().Head != 1 {
		t.Fatalf("restored head = %d", r.State().Head)
	}
}

func TestVerifyAfterCleanShutdown(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir, 1<<30)
	if err != nil {
		t.Fatal(err)
	}
	seed(t, s)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	// No -wal or -shm exists now; read-only mode must still work.
	sum, err := Verify(dir)
	if err != nil {
		t.Fatal(err)
	}
	if sum.Entries != 2 || sum.GenesisHash == "" {
		t.Fatalf("summary = %+v", sum)
	}
	if err := Backup(dir, filepath.Join(t.TempDir(), "b.db")); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyEmptyAndMissing(t *testing.T) {
	if _, err := Verify(t.TempDir()); err == nil {
		t.Fatal("verify passed a directory with no database")
	}
	dir := t.TempDir()
	s, err := Open(dir, 1<<30)
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	sum, err := Verify(dir)
	if err != nil {
		t.Fatal(err)
	}
	if sum.Entries != 0 || sum.Head != -1 {
		t.Fatalf("summary = %+v", sum)
	}
}

func TestVerifyDetectsMissingBlobFile(t *testing.T) {
	s, dir := openTest(t)
	seed(t, s)
	if err := s.PutBlob("v", "b", []byte("data")); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(s.blobPath("v", "b")); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(dir); err == nil {
		t.Fatal("verify missed a deleted blob file")
	}
}

func TestOpenRemovesOnlyTempBlobFiles(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir, 1<<30)
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	tmp := filepath.Join(dir, blobDir, "tmp-123")
	orphan := filepath.Join(dir, blobDir, "abcdef")
	for _, f := range []string{tmp, orphan} {
		if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	s, err = Open(dir, 1<<30)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := os.Stat(tmp); !os.IsNotExist(err) {
		t.Fatal("temp file survived Open")
	}
	if _, err := os.Stat(orphan); err != nil {
		t.Fatal("Open deleted a file it could not account for")
	}
}
