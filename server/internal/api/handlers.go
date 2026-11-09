package api

import (
	"crypto/sha256"
	"crypto/subtle"
	"io"
	"net/http"
	"strconv"

	"mixia/server/internal/ledger"
	"mixia/server/internal/store"
)

const (
	defaultChangeLimit = 500
	maxChangeLimit     = 1000
	defaultAuditLimit  = 100
	maxAuditLimit      = 1000
)

func (s *Server) getInfo(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"proto":        1,
		"time":         s.nowMs(),
		"bootstrapped": s.store.State().Bootstrapped(),
	})
}

func parseEntries(wires []ledger.Wire) ([]*ledger.Entry, error) {
	entries := make([]*ledger.Entry, 0, len(wires))
	for _, wire := range wires {
		e, err := ledger.Parse(wire)
		if err != nil {
			return nil, err
		}
		entries = append(entries, e)
	}
	return entries, nil
}

func (s *Server) postBootstrap(w http.ResponseWriter, r *http.Request) {
	if s.store.State().Bootstrapped() {
		writeError(w, http.StatusGone, codeGone)
		return
	}
	if s.cfg.BootstrapTokenHash == nil {
		writeError(w, http.StatusForbidden, codeForbidden)
		return
	}
	body, ok := readBody(w, r, maxAnonBody)
	if !ok {
		return
	}
	var req struct {
		Token   string        `json:"token"`
		Entries []ledger.Wire `json:"entries"`
		Keys    []store.Key   `json:"keys"`
	}
	if !decodeJSON(w, body, &req) {
		return
	}
	sum := sha256.Sum256([]byte(req.Token))
	if subtle.ConstantTimeCompare(sum[:], s.cfg.BootstrapTokenHash) != 1 {
		writeError(w, http.StatusUnauthorized, codeUnauthorized)
		return
	}
	entries, err := parseEntries(req.Entries)
	if err != nil {
		writeFailure(w, err)
		return
	}
	if len(entries) == 0 || entries[0].Type != ledger.TypeGenesis {
		writeError(w, http.StatusBadRequest, codeLedgerInvalid)
		return
	}
	if err := s.store.Bootstrap(entries, req.Keys, s.nowMs()); err != nil {
		if ledger.IsConflict(err) {
			// There is no head to race with here; a bad seq is just invalid.
			writeError(w, http.StatusBadRequest, codeLedgerInvalid)
			return
		}
		writeFailure(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "head": s.store.State().Head})
}

// queryInt reads a non-negative integer parameter. On failure it has already
// written the response.
func queryInt(w http.ResponseWriter, r *http.Request, name string, def int64) (int64, bool) {
	raw := r.URL.Query().Get(name)
	if raw == "" {
		return def, true
	}
	v, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || v < 0 {
		writeError(w, http.StatusBadRequest, codeBadRequest)
		return 0, false
	}
	return v, true
}

// queryLimit reads a positive limit and caps it at most.
func queryLimit(w http.ResponseWriter, r *http.Request, def, most int) (int, bool) {
	v, ok := queryInt(w, r, "limit", int64(def))
	if !ok {
		return 0, false
	}
	if v == 0 {
		writeError(w, http.StatusBadRequest, codeBadRequest)
		return 0, false
	}
	return int(min(v, int64(most))), true
}

func (s *Server) getLedger(w http.ResponseWriter, r *http.Request, _ *principal) {
	from, ok := queryInt(w, r, "from", 0)
	if !ok {
		return
	}
	entries, head, err := s.store.Ledger(r.Context(), from)
	if err != nil {
		writeFailure(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"entries": entries, "head": head})
}

func (s *Server) postLedger(w http.ResponseWriter, _ *http.Request, p *principal) {
	if !p.isAdmin() {
		writeError(w, http.StatusForbidden, codeForbidden)
		return
	}
	var req struct {
		Entries []ledger.Wire `json:"entries"`
	}
	if !decodeJSON(w, p.body, &req) {
		return
	}
	entries, err := parseEntries(req.Entries)
	if err != nil {
		writeFailure(w, err)
		return
	}
	head, err := s.store.AppendLedger(entries, p.name, s.nowMs())
	if err != nil {
		writeFailure(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"head": head})
}

// postRootRotate replaces the root key and every recovery wrap atomically. Only
// the current root may do this, not an admin device.
func (s *Server) postRootRotate(w http.ResponseWriter, _ *http.Request, p *principal) {
	if !p.root {
		writeError(w, http.StatusForbidden, codeForbidden)
		return
	}
	var req struct {
		Entry *ledger.Wire `json:"entry"`
		Keys  []store.Key  `json:"keys"`
	}
	if !decodeJSON(w, p.body, &req) {
		return
	}
	if req.Entry == nil {
		writeError(w, http.StatusBadRequest, codeBadRequest)
		return
	}
	entry, err := ledger.Parse(*req.Entry)
	if err != nil {
		writeFailure(w, err)
		return
	}
	if err := s.store.RootRotate(entry, req.Keys, s.nowMs()); err != nil {
		writeFailure(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "head": entry.Seq})
}

// vaultParam returns a syntactically valid {id}. On failure it has already
// written the response.
func vaultParam(w http.ResponseWriter, r *http.Request) (string, bool) {
	id := r.PathValue("id")
	if !ledger.ValidID(id) {
		writeError(w, http.StatusBadRequest, codeBadRequest)
		return "", false
	}
	return id, true
}

// accessibleVault applies `acc`. The scope check comes first so that a device
// outside a vault learns nothing beyond 403.
func (s *Server) accessibleVault(w http.ResponseWriter, r *http.Request, p *principal) (string, bool) {
	id, ok := vaultParam(w, r)
	if !ok {
		return "", false
	}
	if !p.canAccess(id) {
		writeError(w, http.StatusForbidden, codeForbidden)
		return "", false
	}
	if _, exists := s.store.State().Vaults[id]; !exists {
		writeError(w, http.StatusNotFound, codeNotFound)
		return "", false
	}
	return id, true
}

// administeredVault applies `adm` plus `acc`: an admin outside the vault's
// scope is refused like any other device.
func (s *Server) administeredVault(w http.ResponseWriter, r *http.Request, p *principal) (string, bool) {
	if !p.isAdmin() {
		writeError(w, http.StatusForbidden, codeForbidden)
		return "", false
	}
	return s.accessibleVault(w, r, p)
}

func (s *Server) getChanges(w http.ResponseWriter, r *http.Request, p *principal) {
	id, ok := s.accessibleVault(w, r, p)
	if !ok {
		return
	}
	after, ok := queryInt(w, r, "after", 0)
	if !ok {
		return
	}
	limit, ok := queryLimit(w, r, defaultChangeLimit, maxChangeLimit)
	if !ok {
		return
	}
	page, err := s.store.Changes(r.Context(), id, after, limit)
	if err != nil {
		writeFailure(w, err)
		return
	}
	writeJSON(w, http.StatusOK, page)
}

func (s *Server) postChanges(w http.ResponseWriter, r *http.Request, p *principal) {
	id, ok := s.accessibleVault(w, r, p)
	if !ok {
		return
	}
	var req struct {
		Changes []store.NewChange `json:"changes"`
	}
	if !decodeJSON(w, p.body, &req) {
		return
	}
	accepted, head, err := s.store.PutChanges(id, p.name, req.Changes)
	if err != nil {
		writeFailure(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"accepted": accepted, "head": head})
}

func (s *Server) getKeys(w http.ResponseWriter, r *http.Request, p *principal) {
	id, ok := s.accessibleVault(w, r, p)
	if !ok {
		return
	}
	owner := p.name
	if p.root {
		owner = ledger.Recovery
	}
	keys, err := s.store.Keys(r.Context(), id, owner)
	if err != nil {
		writeFailure(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"keys": keys})
}

func (s *Server) putKeys(w http.ResponseWriter, r *http.Request, p *principal) {
	id, ok := s.administeredVault(w, r, p)
	if !ok {
		return
	}
	var req struct {
		Keys []store.Key `json:"keys"`
	}
	if !decodeJSON(w, p.body, &req) {
		return
	}
	if err := s.store.PutKeys(id, req.Keys, p.name, s.nowMs()); err != nil {
		writeFailure(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) postRotate(w http.ResponseWriter, r *http.Request, p *principal) {
	id, ok := s.administeredVault(w, r, p)
	if !ok {
		return
	}
	var req struct {
		Entry   *ledger.Wire      `json:"entry"`
		Keys    []store.Key       `json:"keys"`
		Changes []store.NewChange `json:"changes"`
	}
	if !decodeJSON(w, p.body, &req) {
		return
	}
	if req.Entry == nil {
		writeError(w, http.StatusBadRequest, codeBadRequest)
		return
	}
	entry, err := ledger.Parse(*req.Entry)
	if err != nil {
		writeFailure(w, err)
		return
	}
	if err := s.store.Rotate(id, entry, req.Keys, req.Changes, p.name, s.nowMs()); err != nil {
		writeFailure(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "ledgerHead": entry.Seq})
}

// blobParams applies `acc` and validates {blobId}.
func (s *Server) blobParams(w http.ResponseWriter, r *http.Request, p *principal) (vaultID, blobID string, ok bool) {
	vaultID, ok = s.accessibleVault(w, r, p)
	if !ok {
		return "", "", false
	}
	blobID = r.PathValue("blobId")
	if !ledger.ValidID(blobID) {
		writeError(w, http.StatusBadRequest, codeBadRequest)
		return "", "", false
	}
	return vaultID, blobID, true
}

func (s *Server) putBlob(w http.ResponseWriter, r *http.Request, p *principal) {
	vaultID, blobID, ok := s.blobParams(w, r, p)
	if !ok {
		return
	}
	if err := s.store.PutBlob(vaultID, blobID, p.body); err != nil {
		writeFailure(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) getBlob(w http.ResponseWriter, r *http.Request, p *principal) {
	vaultID, blobID, ok := s.blobParams(w, r, p)
	if !ok {
		return
	}
	f, size, err := s.store.OpenBlob(r.Context(), vaultID, blobID)
	if err != nil {
		writeFailure(w, err)
		return
	}
	defer f.Close()
	h := w.Header()
	h.Set("Content-Type", "application/octet-stream")
	h.Set("Content-Length", strconv.FormatInt(size, 10))
	w.WriteHeader(http.StatusOK)
	io.Copy(w, f)
}

func (s *Server) deleteBlob(w http.ResponseWriter, r *http.Request, p *principal) {
	vaultID, blobID, ok := s.blobParams(w, r, p)
	if !ok {
		return
	}
	if err := s.store.DeleteBlob(vaultID, blobID); err != nil {
		writeFailure(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) getAudit(w http.ResponseWriter, r *http.Request, p *principal) {
	if !p.isAdmin() {
		writeError(w, http.StatusForbidden, codeForbidden)
		return
	}
	limit, ok := queryLimit(w, r, defaultAuditLimit, maxAuditLimit)
	if !ok {
		return
	}
	events, err := s.store.Audit(r.Context(), limit)
	if err != nil {
		writeFailure(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"events": events})
}
