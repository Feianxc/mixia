package store

import (
	"context"
	"database/sql"
)

const auditKeep = 5000

// Event is one audit record. Detail holds ids only, never content.
type Event struct {
	Ts     int64  `json:"ts"`
	Device string `json:"device"`
	Action string `json:"action"`
	Detail string `json:"detail"`
}

// audit records an event inside the caller's transaction and trims the table.
// AUTOINCREMENT ids never repeat, so the cut is a plain range delete.
func audit(tx *sql.Tx, ts int64, device, action, detail string) error {
	res, err := tx.Exec(`INSERT INTO audit (ts, device, action, detail) VALUES (?, ?, ?, ?)`, ts, device, action, detail)
	if err != nil {
		return err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return err
	}
	_, err = tx.Exec(`DELETE FROM audit WHERE id <= ?`, id-auditKeep)
	return err
}

// Audit returns the newest events first.
func (s *Store) Audit(ctx context.Context, limit int) ([]Event, error) {
	rows, err := s.r.QueryContext(ctx, `SELECT ts, device, action, detail FROM audit ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Event{}
	for rows.Next() {
		var e Event
		if err := rows.Scan(&e.Ts, &e.Device, &e.Action, &e.Detail); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
