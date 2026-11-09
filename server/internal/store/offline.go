package store

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"

	"mixia/server/internal/ledger"
)

// openReadOnly opens the database without any write access. It is what backup
// and verify use, so both can run beside a live server.
func openReadOnly(dir string) (*sql.DB, error) {
	path := filepath.Join(dir, dbFile)
	if _, err := os.Stat(path); err != nil {
		return nil, err
	}
	dsn, err := sqliteDSN(path, "mode=ro", "_pragma=busy_timeout(10000)")
	if err != nil {
		return nil, err
	}
	return sql.Open("sqlite", dsn)
}

// Backup writes a consistent copy of the database to dest with VACUUM INTO.
// Blob files are not part of it; see README.
func Backup(dir, dest string) error {
	if _, err := os.Stat(dest); err == nil {
		return fmt.Errorf("destination already exists")
	}
	db, err := openReadOnly(dir)
	if err != nil {
		return err
	}
	defer db.Close()
	_, err = db.Exec(`VACUUM INTO ?`, dest)
	return err
}

// Summary describes a store without exposing any content.
type Summary struct {
	Entries        int
	Head           int64
	GenesisHash    string
	HeadHash       string
	DevicesActive  int
	DevicesRevoked int
	Admins         int
	Vaults         int
	Changes        int64
	ChangeBytes    int64
	Keys           int64
	Blobs          int64
	BlobBytes      int64
	OpenPairs      int64
	AuditEvents    int64
}

// Verify replays the ledger and cross-checks the tables and blob files against
// it, without writing anything.
func Verify(dir string) (*Summary, error) {
	db, err := openReadOnly(dir)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	ctx := context.Background()
	st, err := replay(ctx, db)
	if err != nil {
		return nil, err
	}
	if err := checkVaultTable(ctx, db, st); err != nil {
		return nil, err
	}
	sum := &Summary{
		Entries:     int(st.Head + 1),
		Head:        st.Head,
		GenesisHash: ledger.EncodeB64(st.GenesisHash),
		HeadHash:    ledger.EncodeB64(st.HeadHash),
		Vaults:      len(st.Vaults),
	}
	for _, d := range st.Devices {
		switch {
		case d.Revoked:
			sum.DevicesRevoked++
		case d.Role == ledger.RoleAdmin:
			sum.DevicesActive++
			sum.Admins++
		default:
			sum.DevicesActive++
		}
	}
	counts := []struct {
		q    string
		dest []any
	}{
		{`SELECT COUNT(*), COALESCE(SUM(LENGTH(data)),0) FROM changes`, []any{&sum.Changes, &sum.ChangeBytes}},
		{`SELECT COUNT(*) FROM keys`, []any{&sum.Keys}},
		{`SELECT COUNT(*), COALESCE(SUM(size),0) FROM blobs`, []any{&sum.Blobs, &sum.BlobBytes}},
		{`SELECT COUNT(*) FROM pairs`, []any{&sum.OpenPairs}},
		{`SELECT COUNT(*) FROM audit`, []any{&sum.AuditEvents}},
	}
	for _, c := range counts {
		if err := db.QueryRowContext(ctx, c.q).Scan(c.dest...); err != nil {
			return nil, err
		}
	}
	if err := checkChangeGens(ctx, db, st); err != nil {
		return nil, err
	}
	if err := checkBlobFiles(ctx, db, dir); err != nil {
		return nil, err
	}
	return sum, nil
}

// checkChangeGens confirms no vault retains a change from another generation.
func checkChangeGens(ctx context.Context, db *sql.DB, st *ledger.State) error {
	rows, err := db.QueryContext(ctx, `SELECT DISTINCT vault_id, gen FROM changes`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		var gen int64
		if err := rows.Scan(&id, &gen); err != nil {
			return err
		}
		if v, ok := st.Vaults[id]; !ok || v.Gen != gen {
			return fmt.Errorf("changes table holds rows outside the current generation")
		}
	}
	return rows.Err()
}

func checkBlobFiles(ctx context.Context, db *sql.DB, dir string) error {
	rows, err := db.QueryContext(ctx, `SELECT vault_id, blob_id, size FROM blobs`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var v, b string
		var size int64
		if err := rows.Scan(&v, &b, &size); err != nil {
			return err
		}
		fi, err := os.Stat(blobPath(dir, v, b))
		if err != nil || fi.Size() != size {
			return fmt.Errorf("blob file missing or wrong size")
		}
	}
	return rows.Err()
}
