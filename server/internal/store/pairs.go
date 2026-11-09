package store

import (
	"context"
	"database/sql"
	"errors"

	"mixia/server/internal/ledger"
)

const (
	maxOpenPairs = 3
	maxPairFails = 5

	// Wire values of a pairing's status field.
	PairOpen      = "open"
	PairRequested = "requested"
	PairGranted   = "granted"
)

// Pair is a pairing session. Offer, Request and Grant are opaque to the server.
type Pair struct {
	ID        string
	TokenHash []byte
	ExpiresAt int64
	Offer     ledger.B64
	Request   ledger.B64 // nil until the new device has posted
	Grant     ledger.B64 // nil until an admin has granted
}

// Status returns the wire status.
func (p *Pair) Status() string {
	switch {
	case p.Grant != nil:
		return PairGranted
	case p.Request != nil:
		return PairRequested
	}
	return PairOpen
}

type rowScanner interface {
	Scan(dest ...any) error
}

const pairColumns = `pair_id, token_hash, expires_at, offer, request, grant_msg`

func scanPair(row rowScanner) (*Pair, error) {
	var p Pair
	err := row.Scan(&p.ID, &p.TokenHash, &p.ExpiresAt, (*[]byte)(&p.Offer), (*[]byte)(&p.Request), (*[]byte)(&p.Grant))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &p, nil
}

// Pair returns a live pairing. A pairing past its expiry that has not been
// purged yet reports ErrPairExpired.
func (s *Store) Pair(ctx context.Context, id string, now int64) (*Pair, error) {
	p, err := scanPair(s.r.QueryRowContext(ctx, `SELECT `+pairColumns+` FROM pairs WHERE pair_id = ?`, id))
	if err != nil {
		return nil, err
	}
	if p.ExpiresAt <= now {
		return nil, ErrPairExpired
	}
	return p, nil
}

func livePair(tx *sql.Tx, id string, now int64) (*Pair, error) {
	p, err := scanPair(tx.QueryRow(`SELECT `+pairColumns+` FROM pairs WHERE pair_id = ?`, id))
	if err != nil {
		return nil, err
	}
	if p.ExpiresAt <= now {
		return nil, ErrPairExpired
	}
	return p, nil
}

// CreatePair opens a pairing. Pairings that are neither expired nor granted
// count against the limit of three.
func (s *Store) CreatePair(p *Pair, actor string, now int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.txn(func(tx *sql.Tx) error {
		if _, err := tx.Exec(`DELETE FROM pairs WHERE expires_at <= ?`, now); err != nil {
			return err
		}
		var open int
		if err := tx.QueryRow(`SELECT COUNT(*) FROM pairs WHERE grant_msg IS NULL`).Scan(&open); err != nil {
			return err
		}
		if open >= maxOpenPairs {
			return ErrPairLimit
		}
		var exists int
		if err := tx.QueryRow(`SELECT COUNT(*) FROM pairs WHERE pair_id = ?`, p.ID).Scan(&exists); err != nil {
			return err
		}
		if exists > 0 {
			return ErrPairUsed
		}
		_, err := tx.Exec(`INSERT INTO pairs (pair_id, token_hash, expires_at, offer) VALUES (?, ?, ?, ?)`,
			p.ID, p.TokenHash, p.ExpiresAt, []byte(p.Offer))
		if err != nil {
			return err
		}
		return audit(tx, now, actor, "pair_open", "pair="+p.ID)
	})
}

// PairFail records a wrong token and destroys the pairing at the fifth.
func (s *Store) PairFail(id string, now int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.txn(func(tx *sql.Tx) error {
		var fails int
		err := tx.QueryRow(`UPDATE pairs SET fails = fails + 1 WHERE pair_id = ? RETURNING fails`, id).Scan(&fails)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		if fails < maxPairFails {
			return nil
		}
		if _, err := tx.Exec(`DELETE FROM pairs WHERE pair_id = ?`, id); err != nil {
			return err
		}
		return audit(tx, now, "pair", "pair_destroyed", "pair="+id)
	})
}

// PairRequest stores the new device's request. It can happen only once.
func (s *Store) PairRequest(id string, request []byte, now int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.txn(func(tx *sql.Tx) error {
		p, err := livePair(tx, id, now)
		if err != nil {
			return err
		}
		if p.Request != nil {
			return ErrPairUsed
		}
		if _, err := tx.Exec(`UPDATE pairs SET request = ? WHERE pair_id = ?`, request, id); err != nil {
			return err
		}
		return audit(tx, now, "pair", "pair_request", "pair="+id)
	})
}

// PairGrant stores the admin's grant. It requires a pending request and can
// happen only once.
func (s *Store) PairGrant(id string, grant []byte, actor string, now int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.txn(func(tx *sql.Tx) error {
		p, err := livePair(tx, id, now)
		if err != nil {
			return err
		}
		if p.Grant != nil {
			return ErrPairUsed
		}
		if p.Request == nil {
			return ErrBadRequest
		}
		if _, err := tx.Exec(`UPDATE pairs SET grant_msg = ? WHERE pair_id = ?`, grant, id); err != nil {
			return err
		}
		return audit(tx, now, actor, "pair_grant", "pair="+id)
	})
}

// DeletePair destroys a pairing.
func (s *Store) DeletePair(id, actor string, now int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.txn(func(tx *sql.Tx) error {
		res, err := tx.Exec(`DELETE FROM pairs WHERE pair_id = ?`, id)
		if err != nil {
			return err
		}
		if n, err := res.RowsAffected(); err != nil {
			return err
		} else if n == 0 {
			return ErrNotFound
		}
		return audit(tx, now, actor, "pair_delete", "pair="+id)
	})
}

// PurgeExpiredPairs removes pairings past their expiry.
func (s *Store) PurgeExpiredPairs(now int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.txn(func(tx *sql.Tx) error {
		_, err := tx.Exec(`DELETE FROM pairs WHERE expires_at <= ?`, now)
		return err
	})
}
