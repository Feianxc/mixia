// Package api is the HTTP surface of spec section 7. The server is untrusted by
// design: it verifies who is asking and what the ledger allows, and treats
// every payload as opaque.
package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"path"
	"strings"
	"time"

	"mixia/server/internal/ledger"
	"mixia/server/internal/store"
)

const (
	maxAnonBody   = 64 << 10
	maxJSONBody   = 8 << 20
	maxRotateBody = 96 << 20
	maxBlobBody   = 50 << 20

	defaultRateRPS   = 5
	defaultRateBurst = 30

	janitorInterval = time.Minute
)

// Wire error codes.
const (
	codeBadRequest     = "bad_request"
	codeUnauthorized   = "unauthorized"
	codeForbidden      = "forbidden"
	codeNotFound       = "not_found"
	codeLedgerConflict = "ledger_conflict"
	codeLedgerInvalid  = "ledger_invalid"
	codeStaleGen       = "stale_gen"
	codeStaleSnapshot  = "stale_snapshot"
	codeGone           = "gone"
	codeTooLarge       = "too_large"
	codeRateLimited    = "rate_limited"
	codeQuotaExceeded  = "quota_exceeded"
	codePairUsed       = "pair_used"
	codePairExpired    = "pair_expired"
	codeInternal       = "internal"
)

// Config configures a Server.
type Config struct {
	Store *store.Store

	// BootstrapTokenHash is SHA256(token). Nil disables bootstrap.
	BootstrapTokenHash []byte

	// TrustCF makes the rate limiter key on CF-Connecting-IP.
	TrustCF bool

	// RateRPS and RateBurst size the per-IP token bucket. Zero means default.
	RateRPS   float64
	RateBurst float64

	// Now overrides the clock in tests.
	Now func() time.Time

	// Log receives one line per request. Nil discards.
	Log *log.Logger
}

// Server handles the API.
type Server struct {
	cfg     Config
	store   *store.Store
	mux     *http.ServeMux
	now     func() time.Time
	startMs int64
	limiter *limiter
	nonces  *nonceCache
	log     *log.Logger
}

// New builds a Server. The start time it records is the floor for request
// timestamps: the nonce cache is empty at this moment, so older requests could
// otherwise be replayed.
func New(cfg Config) *Server {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.RateRPS == 0 {
		cfg.RateRPS = defaultRateRPS
	}
	if cfg.RateBurst == 0 {
		cfg.RateBurst = defaultRateBurst
	}
	if cfg.Log == nil {
		cfg.Log = log.New(io.Discard, "", 0)
	}
	s := &Server{
		cfg:     cfg,
		store:   cfg.Store,
		now:     cfg.Now,
		startMs: cfg.Now().UnixMilli(),
		limiter: newLimiter(cfg.RateRPS, cfg.RateBurst),
		nonces:  newNonceCache(),
		log:     cfg.Log,
	}
	s.mux = s.routes()
	return s
}

func (s *Server) nowMs() int64 { return s.now().UnixMilli() }

func (s *Server) routes() *http.ServeMux {
	m := http.NewServeMux()
	dev := authOpts{limit: maxJSONBody}
	devOrRoot := authOpts{limit: maxJSONBody, allowRoot: true}

	m.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	})
	m.Handle("GET /v1/info", s.limited(s.getInfo))
	m.Handle("POST /v1/bootstrap", s.limited(s.postBootstrap))

	m.Handle("GET /v1/ledger", s.authed(devOrRoot, s.getLedger))
	m.Handle("POST /v1/ledger", s.authed(devOrRoot, s.postLedger))
	m.Handle("POST /v1/root/rotate", s.authed(devOrRoot, s.postRootRotate))

	m.Handle("POST /v1/pair", s.authed(dev, s.postPair))
	m.Handle("GET /v1/pair/{id}", s.limited(s.getPair))
	m.Handle("POST /v1/pair/{id}/request", s.limited(s.postPairRequest))
	m.Handle("GET /v1/pair/{id}/admin", s.authed(dev, s.getPairAdmin))
	m.Handle("POST /v1/pair/{id}/grant", s.authed(dev, s.postPairGrant))
	m.Handle("DELETE /v1/pair/{id}", s.authed(dev, s.deletePair))

	m.Handle("GET /v1/vaults/{id}/changes", s.authed(devOrRoot, s.getChanges))
	m.Handle("POST /v1/vaults/{id}/changes", s.authed(dev, s.postChanges))
	m.Handle("GET /v1/vaults/{id}/keys", s.authed(devOrRoot, s.getKeys))
	m.Handle("PUT /v1/vaults/{id}/keys", s.authed(devOrRoot, s.putKeys))
	m.Handle("POST /v1/vaults/{id}/rotate", s.authed(authOpts{limit: maxRotateBody, allowRoot: true}, s.postRotate))

	blob := authOpts{limit: maxBlobBody}
	m.Handle("PUT /v1/vaults/{id}/blobs/{blobId}", s.authed(blob, s.putBlob))
	m.Handle("GET /v1/vaults/{id}/blobs/{blobId}", s.authed(dev, s.getBlob))
	m.Handle("DELETE /v1/vaults/{id}/blobs/{blobId}", s.authed(dev, s.deleteBlob))

	m.Handle("GET /v1/audit", s.authed(dev, s.getAudit))

	// A catch-all also turns the mux's plain-text 405s into JSON 404s.
	m.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		writeError(w, http.StatusNotFound, codeNotFound)
	})
	return m
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.ResponseWriter.Write(b)
}

func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// isCanonicalPath mirrors the mux's cleanPath. Unclean paths are answered here
// because the mux would otherwise serve them an HTML redirect.
func isCanonicalPath(p string) bool {
	if !strings.HasPrefix(p, "/") {
		return false
	}
	c := path.Clean(p)
	if strings.HasSuffix(p, "/") && c != "/" {
		c += "/"
	}
	return c == p
}

// routeName is the matched pattern without its method. Only this template is
// logged, never the concrete path, which can carry vault and pair ids.
func routeName(r *http.Request) string {
	if r.Pattern == "" {
		return "-"
	}
	if _, route, ok := strings.Cut(r.Pattern, " "); ok {
		return route
	}
	return r.Pattern
}

// ServeHTTP applies the headers, logging and panic containment shared by every
// response, then dispatches.
func (s *Server) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	start := time.Now()
	h := rw.Header()
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Cache-Control", "no-store")
	w := &statusWriter{ResponseWriter: rw}
	defer func() {
		if v := recover(); v != nil {
			if v == http.ErrAbortHandler {
				panic(v)
			}
			if w.status == 0 {
				writeError(w, http.StatusInternalServerError, codeInternal)
			}
		}
		s.log.Printf("%s %s %d %dms", r.Method, routeName(r), w.status, time.Since(start).Milliseconds())
	}()
	if !isCanonicalPath(r.URL.EscapedPath()) {
		writeError(w, http.StatusNotFound, codeNotFound)
		return
	}
	s.mux.ServeHTTP(w, r)
}

// RunJanitor drops expired pairings, nonces and idle rate buckets until ctx ends.
func (s *Server) RunJanitor(ctx context.Context) {
	t := time.NewTicker(janitorInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.janitorPass()
		}
	}
}

func (s *Server) janitorPass() {
	now := s.now()
	s.nonces.sweep(now.UnixMilli())
	s.limiter.sweep(now)
	if err := s.store.PurgeExpiredPairs(now.UnixMilli()); err != nil {
		s.log.Printf("janitor: pair purge failed")
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	b, err := json.Marshal(v)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	w.Write(b)
}

func writeError(w http.ResponseWriter, status int, code string) {
	writeJSON(w, status, map[string]string{"error": code})
}

// writeFailure maps store and ledger errors to the wire.
func writeFailure(w http.ResponseWriter, err error) {
	var conflict *ledger.ConflictError
	var inv *ledger.InvalidError
	var stale *store.StaleSnapshotError
	switch {
	case errors.As(err, &conflict):
		writeJSON(w, http.StatusConflict, map[string]any{"error": codeLedgerConflict, "head": conflict.Head})
	case errors.As(err, &stale):
		writeJSON(w, http.StatusConflict, map[string]any{"error": codeStaleSnapshot, "head": stale.Head})
	case errors.As(err, &inv):
		writeError(w, http.StatusBadRequest, codeLedgerInvalid)
	case errors.Is(err, store.ErrBadRequest):
		writeError(w, http.StatusBadRequest, codeBadRequest)
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, codeNotFound)
	case errors.Is(err, store.ErrStaleGen):
		writeError(w, http.StatusConflict, codeStaleGen)
	case errors.Is(err, store.ErrGone):
		writeError(w, http.StatusGone, codeGone)
	case errors.Is(err, store.ErrQuota):
		writeError(w, http.StatusRequestEntityTooLarge, codeQuotaExceeded)
	case errors.Is(err, store.ErrPairUsed):
		writeError(w, http.StatusConflict, codePairUsed)
	case errors.Is(err, store.ErrPairExpired):
		writeError(w, http.StatusGone, codePairExpired)
	case errors.Is(err, store.ErrPairLimit):
		writeError(w, http.StatusTooManyRequests, codeRateLimited)
	default:
		writeError(w, http.StatusInternalServerError, codeInternal)
	}
}

// readBody reads the whole request body under limit. On failure it has already
// written the response. A declared length is allocated in one piece: growing
// the buffer as it fills would hold two copies of a large body at the peak. The
// callers make that safe, being either authenticated or capped at maxAnonBody.
func readBody(w http.ResponseWriter, r *http.Request, limit int64) ([]byte, bool) {
	if r.ContentLength > limit {
		writeError(w, http.StatusRequestEntityTooLarge, codeTooLarge)
		return nil, false
	}
	src := http.MaxBytesReader(w, r.Body, limit)
	var body []byte
	var err error
	if r.ContentLength > 0 {
		body = make([]byte, r.ContentLength)
		_, err = io.ReadFull(src, body)
	} else {
		body, err = io.ReadAll(src)
	}
	if err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			writeError(w, http.StatusRequestEntityTooLarge, codeTooLarge)
		} else {
			writeError(w, http.StatusBadRequest, codeBadRequest)
		}
		return nil, false
	}
	return body, true
}

func decodeJSON(w http.ResponseWriter, body []byte, v any) bool {
	if err := json.Unmarshal(body, v); err != nil {
		writeError(w, http.StatusBadRequest, codeBadRequest)
		return false
	}
	return true
}
