package api

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"mixia/server/internal/ledger"
)

const (
	clockWindowMs  = 300_000
	startGraceMs   = 5_000
	nonceRetainMs  = 600_000
	nonceSize      = 16
	signatureBytes = 64

	hdrDevice = "X-Mx-Device"
	hdrTs     = "X-Mx-Ts"
	hdrNonce  = "X-Mx-Nonce"
	hdrSig    = "X-Mx-Sig"
	hdrBody   = "X-Mx-Body"
)

type authOpts struct {
	allowRoot bool
	limit     int64
}

// principal is an authenticated caller and the body it signed.
type principal struct {
	name string // deviceId, or "root"
	root bool
	dev  ledger.Device
	body []byte
}

// isAdmin implements `adm` and, on routes that allow root, `adm/root`.
func (p *principal) isAdmin() bool { return p.root || p.dev.Role == ledger.RoleAdmin }

// canAccess implements `acc` and, on routes that allow root, `acc/root`.
func (p *principal) canAccess(vaultID string) bool { return p.root || p.dev.HasVault(vaultID) }

type authedHandler func(http.ResponseWriter, *http.Request, *principal)

// validBodyHash reports whether v is lowercase hex SHA-256. The signature covers
// this exact text, so accepting a second spelling would gain nothing.
func validBodyHash(v string) bool {
	if len(v) != 2*sha256.Size {
		return false
	}
	for i := 0; i < len(v); i++ {
		if c := v[i]; (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// authed wraps a handler with spec section 3. The signature covers the body's
// hash from X-Mx-Body rather than the body itself, so the caller is proven
// before any of the body is read: nobody can make the server buffer a large
// body without holding a key.
func (s *Server) authed(opts authOpts, h authedHandler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := s.clientIP(r)
		now := s.now()
		if s.limiter.exhausted(ip, now) {
			writeError(w, http.StatusTooManyRequests, codeRateLimited)
			return
		}
		reject := func() {
			s.limiter.take(ip, now)
			writeError(w, http.StatusUnauthorized, codeUnauthorized)
		}

		name := r.Header.Get(hdrDevice)
		tsHdr := r.Header.Get(hdrTs)
		nonce := r.Header.Get(hdrNonce)
		bodyHash := r.Header.Get(hdrBody)
		sig, sigErr := ledger.DecodeB64(r.Header.Get(hdrSig))
		if name == "" || sigErr != nil || len(sig) != signatureBytes || !validBodyHash(bodyHash) {
			reject()
			return
		}
		ts, err := strconv.ParseInt(tsHdr, 10, 64)
		if err != nil {
			reject()
			return
		}
		nowMs := now.UnixMilli()
		if ts < nowMs-clockWindowMs || ts > nowMs+clockWindowMs || ts < s.startMs-startGraceMs {
			reject()
			return
		}
		if raw, err := ledger.DecodeB64(nonce); err != nil || len(raw) != nonceSize {
			reject()
			return
		}

		st := s.store.State()
		p := &principal{name: name, root: name == ledger.Root}
		if p.root {
			if !opts.allowRoot {
				writeError(w, http.StatusForbidden, codeForbidden)
				return
			}
			if !st.Bootstrapped() {
				reject()
				return
			}
		} else {
			d, ok := st.ActiveDevice(name)
			if !ok {
				reject()
				return
			}
			p.dev = d
		}

		msg := "MIXIA-REQ-1\n" + r.Method + "\n" + r.URL.RequestURI() + "\n" + tsHdr + "\n" + nonce + "\n" + bodyHash
		var valid bool
		if p.root {
			valid = ledger.StrictVerify(st.RootPub, []byte(msg), sig)
		} else {
			valid = verifyP256(p.dev.AuthPub, msg, sig)
		}
		// The nonce is spent only by a valid signature, otherwise anyone who
		// saw a nonce could burn it; and before the body is read, otherwise a
		// captured request could be replayed to buffer the body many times.
		if !valid || !s.nonces.add(nonce, nowMs) {
			reject()
			return
		}

		body, ok := readBody(w, r, opts.limit)
		if !ok {
			return
		}
		digest := sha256.Sum256(body)
		if hex.EncodeToString(digest[:]) != bodyHash {
			reject()
			return
		}
		p.body = body
		h(w, r, p)
	})
}

func verifyP256(pub *ecdsa.PublicKey, msg string, sig []byte) bool {
	digest := sha256.Sum256([]byte(msg))
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	return ecdsa.Verify(pub, digest[:], r, s)
}

// limited applies the per-IP bucket to an anonymous route.
func (s *Server) limited(h http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.limiter.take(s.clientIP(r), s.now()) {
			writeError(w, http.StatusTooManyRequests, codeRateLimited)
			return
		}
		h(w, r)
	})
}

func (s *Server) clientIP(r *http.Request) string {
	if s.cfg.TrustCF {
		if ip := strings.TrimSpace(r.Header.Get("CF-Connecting-IP")); ip != "" {
			if addr, err := netip.ParseAddr(ip); err == nil {
				return addr.String()
			}
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// nonceCache remembers nonces for ten minutes, which outlives the widest span
// in which a timestamp can stay acceptable (+-300 s).
type nonceCache struct {
	mu   sync.Mutex
	seen map[string]int64 // nonce -> expiry, unix ms
}

func newNonceCache() *nonceCache { return &nonceCache{seen: map[string]int64{}} }

// add records a nonce and reports whether it was new.
func (c *nonceCache) add(nonce string, nowMs int64) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if exp, ok := c.seen[nonce]; ok && exp >= nowMs {
		return false
	}
	c.seen[nonce] = nowMs + nonceRetainMs
	return true
}

func (c *nonceCache) sweep(nowMs int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for n, exp := range c.seen {
		if exp < nowMs {
			delete(c.seen, n)
		}
	}
}

// limiter is a per-IP token bucket.
type limiter struct {
	mu      sync.Mutex
	rate    float64
	burst   float64
	buckets map[string]*bucket
}

type bucket struct {
	tokens float64
	last   time.Time
}

func newLimiter(rate, burst float64) *limiter {
	return &limiter{rate: rate, burst: burst, buckets: map[string]*bucket{}}
}

// refill returns the bucket for ip topped up to now. The caller holds l.mu.
func (l *limiter) refill(ip string, now time.Time) *bucket {
	b, ok := l.buckets[ip]
	if !ok {
		b = &bucket{tokens: l.burst, last: now}
		l.buckets[ip] = b
		return b
	}
	if elapsed := now.Sub(b.last).Seconds(); elapsed > 0 {
		b.tokens = min(l.burst, b.tokens+elapsed*l.rate)
		b.last = now
	}
	return b
}

// take spends a token and reports whether one was available.
func (l *limiter) take(ip string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	b := l.refill(ip, now)
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// exhausted reports whether ip has no token left, without spending one. Signed
// requests only pay on failure, so a healthy device never drains its bucket.
func (l *limiter) exhausted(ip string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.refill(ip, now).tokens < 1
}

// sweep forgets full buckets; a missing bucket behaves the same as a full one.
func (l *limiter) sweep(now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for ip := range l.buckets {
		if l.refill(ip, now).tokens >= l.burst {
			delete(l.buckets, ip)
		}
	}
}
