package api

import (
	"crypto/sha256"
	"crypto/subtle"
	"net/http"
	"time"

	"mixia/server/internal/ledger"
	"mixia/server/internal/store"
)

const (
	pairTTL = 15 * time.Minute
	// pairSkew tolerates a client that computes expiresAt as "now + 15 min" on
	// a clock slightly ahead of ours. The stored expiry is still capped at TTL.
	pairSkew = 30 * time.Second

	hdrPairToken = "X-Mx-Pair-Token"
)

func pairParam(w http.ResponseWriter, r *http.Request) (string, bool) {
	id := r.PathValue("id")
	if !ledger.ValidID(id) {
		writeError(w, http.StatusBadRequest, codeBadRequest)
		return "", false
	}
	return id, true
}

// tokenPair loads a pairing for a caller authenticating with the pair token.
// Wrong tokens count toward destroying the pairing and toward the IP limit.
func (s *Server) tokenPair(w http.ResponseWriter, r *http.Request) (*store.Pair, bool) {
	id, ok := pairParam(w, r)
	if !ok {
		return nil, false
	}
	now := s.nowMs()
	p, err := s.store.Pair(r.Context(), id, now)
	if err != nil {
		writeFailure(w, err)
		return nil, false
	}
	// A malformed token decodes to nothing and simply fails the comparison.
	raw, _ := ledger.DecodeB64(r.Header.Get(hdrPairToken))
	sum := sha256.Sum256(raw)
	if subtle.ConstantTimeCompare(sum[:], p.TokenHash) != 1 {
		s.limiter.take(s.clientIP(r), s.now())
		if err := s.store.PairFail(id, now); err != nil {
			writeFailure(w, err)
			return nil, false
		}
		writeError(w, http.StatusUnauthorized, codeUnauthorized)
		return nil, false
	}
	return p, true
}

// nullable renders an optional opaque field: a b64 string, or null if absent.
func nullable(b ledger.B64) any {
	if b == nil {
		return nil
	}
	return b
}

func (s *Server) postPair(w http.ResponseWriter, _ *http.Request, p *principal) {
	if !p.isAdmin() {
		writeError(w, http.StatusForbidden, codeForbidden)
		return
	}
	var req struct {
		PairID    string     `json:"pairId"`
		TokenHash ledger.B64 `json:"tokenHash"`
		ExpiresAt int64      `json:"expiresAt"`
		Offer     ledger.B64 `json:"offer"`
	}
	if !decodeJSON(w, p.body, &req) {
		return
	}
	now := s.now()
	nowMs := now.UnixMilli()
	latest := now.Add(pairTTL).UnixMilli()
	if !ledger.ValidID(req.PairID) || len(req.TokenHash) != sha256.Size || len(req.Offer) == 0 ||
		req.ExpiresAt <= nowMs || req.ExpiresAt > latest+pairSkew.Milliseconds() {
		writeError(w, http.StatusBadRequest, codeBadRequest)
		return
	}
	pair := &store.Pair{
		ID:        req.PairID,
		TokenHash: req.TokenHash,
		ExpiresAt: min(req.ExpiresAt, latest),
		Offer:     req.Offer,
	}
	if err := s.store.CreatePair(pair, p.name, nowMs); err != nil {
		writeFailure(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) getPair(w http.ResponseWriter, r *http.Request) {
	p, ok := s.tokenPair(w, r)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"offer":  p.Offer,
		"status": p.Status(),
		"grant":  nullable(p.Grant),
	})
}

func (s *Server) postPairRequest(w http.ResponseWriter, r *http.Request) {
	p, ok := s.tokenPair(w, r)
	if !ok {
		return
	}
	body, ok := readBody(w, r, maxAnonBody)
	if !ok {
		return
	}
	var req struct {
		Request ledger.B64 `json:"request"`
	}
	if !decodeJSON(w, body, &req) {
		return
	}
	if len(req.Request) == 0 {
		writeError(w, http.StatusBadRequest, codeBadRequest)
		return
	}
	if err := s.store.PairRequest(p.ID, req.Request, s.nowMs()); err != nil {
		writeFailure(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) getPairAdmin(w http.ResponseWriter, r *http.Request, a *principal) {
	if !a.isAdmin() {
		writeError(w, http.StatusForbidden, codeForbidden)
		return
	}
	id, ok := pairParam(w, r)
	if !ok {
		return
	}
	p, err := s.store.Pair(r.Context(), id, s.nowMs())
	if err != nil {
		writeFailure(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": p.Status(), "request": nullable(p.Request)})
}

func (s *Server) postPairGrant(w http.ResponseWriter, r *http.Request, a *principal) {
	if !a.isAdmin() {
		writeError(w, http.StatusForbidden, codeForbidden)
		return
	}
	id, ok := pairParam(w, r)
	if !ok {
		return
	}
	var req struct {
		Grant ledger.B64 `json:"grant"`
	}
	if !decodeJSON(w, a.body, &req) {
		return
	}
	if len(req.Grant) == 0 {
		writeError(w, http.StatusBadRequest, codeBadRequest)
		return
	}
	if err := s.store.PairGrant(id, req.Grant, a.name, s.nowMs()); err != nil {
		writeFailure(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) deletePair(w http.ResponseWriter, r *http.Request, a *principal) {
	if !a.isAdmin() {
		writeError(w, http.StatusForbidden, codeForbidden)
		return
	}
	id, ok := pairParam(w, r)
	if !ok {
		return
	}
	if err := s.store.DeletePair(id, a.name, s.nowMs()); err != nil {
		writeFailure(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
