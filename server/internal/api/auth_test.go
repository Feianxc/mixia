package api

import (
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"mixia/server/internal/edtest"
	"mixia/server/internal/ledger"
)

func TestSignedRequestAccepted(t *testing.T) {
	h := newHarness(t)
	admin := h.bootstrap()

	// Query strings are part of the signed string.
	h.call(admin.signer(), "GET", "/v1/ledger?from=1", nil).ok(t)
	h.call(h.rootSigner(), "GET", "/v1/ledger?from=1", nil).ok(t)
}

func TestTamperedRequestsRejected(t *testing.T) {
	h := newHarness(t)
	admin := h.bootstrap()
	other := newDevice(t)
	body := mustJSON(map[string]any{"changes": []any{}})
	uri := changesURI(vault1)

	cases := []struct {
		name string
		mut  mutate
	}{
		{"wrong signature", func(r *sent) {
			r.sig = enc(p256Sign(other.auth, signedString(r.method, r.uri, r.ts, r.nonce, r.bodyHash)))
		}},
		{"altered body", func(r *sent) { r.body = mustJSON(map[string]any{"changes": []any{change("x", 1)}}) }},
		{"altered body and hash", func(r *sent) {
			r.body = mustJSON(map[string]any{"changes": []any{change("x", 1)}})
			r.bodyHash = bodyDigest(r.body)
		}},
		{"altered hash", func(r *sent) { r.bodyHash = bodyDigest([]byte("other")) }},
		{"missing body hash", func(r *sent) { r.skip[hdrBody] = true }},
		{"altered path", func(r *sent) { r.uri = changesURI("v2") }},
		{"altered query", func(r *sent) { r.uri = uri + "?x=1" }},
		{"altered method", func(r *sent) { r.method = "GET" }},
		{"altered ts", func(r *sent) { r.ts = strconv.FormatInt(time.Now().UnixMilli()+1, 10) }},
		{"altered nonce", func(r *sent) { r.nonce = enc(randBytes(16)) }},
		{"short signature", func(r *sent) { r.sig = enc(randBytes(63)) }},
		{"bad base64 signature", func(r *sent) { r.sig = "!!!" }},
		{"non-numeric ts", func(r *sent) { r.ts = "soon" }},
		{"short nonce", func(r *sent) { r.nonce = enc(randBytes(15)) }},
		{"missing device", func(r *sent) { r.skip[hdrDevice] = true }},
		{"missing ts", func(r *sent) { r.skip[hdrTs] = true }},
		{"missing nonce", func(r *sent) { r.skip[hdrNonce] = true }},
		{"missing signature", func(r *sent) { r.skip[hdrSig] = true }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h.call(admin.signer(), "POST", uri, body, c.mut).want(t, http.StatusUnauthorized, codeUnauthorized)
		})
	}
}

func TestClockWindow(t *testing.T) {
	h := newHarness(t)
	admin := h.bootstrap()
	// Move past the start-time floor so that only the +-300 s rule is in play.
	h.clock.advance(time.Hour)
	now := h.clock.now().UnixMilli()

	h.signedAt(admin.signer(), "GET", "/v1/ledger", nil, now-301_000, enc(randBytes(16))).
		want(t, http.StatusUnauthorized, codeUnauthorized)
	h.signedAt(admin.signer(), "GET", "/v1/ledger", nil, now+301_000, enc(randBytes(16))).
		want(t, http.StatusUnauthorized, codeUnauthorized)
	h.signedAt(admin.signer(), "GET", "/v1/ledger", nil, now-290_000, enc(randBytes(16))).ok(t)
	h.signedAt(admin.signer(), "GET", "/v1/ledger", nil, now+290_000, enc(randBytes(16))).ok(t)
}

func TestTimestampFloorAtServerStart(t *testing.T) {
	h := newHarness(t)
	admin := h.bootstrap()
	h.restart()
	start := h.srv.startMs

	// Well inside the clock window, but older than the server allows.
	h.signedAt(admin.signer(), "GET", "/v1/ledger", nil, start-6_000, enc(randBytes(16))).
		want(t, http.StatusUnauthorized, codeUnauthorized)
	h.signedAt(admin.signer(), "GET", "/v1/ledger", nil, start-4_000, enc(randBytes(16))).ok(t)
}

func TestNonceReplayRejected(t *testing.T) {
	h := newHarness(t)
	admin := h.bootstrap()
	ts := h.clock.now().UnixMilli()
	nonce := enc(randBytes(16))

	h.signedAt(admin.signer(), "GET", "/v1/ledger", nil, ts, nonce).ok(t)
	h.signedAt(admin.signer(), "GET", "/v1/ledger", nil, ts, nonce).want(t, http.StatusUnauthorized, codeUnauthorized)
	// A nonce is global, not per route.
	h.signedAt(admin.signer(), "GET", "/v1/ledger?from=0", nil, ts, nonce).want(t, http.StatusUnauthorized, codeUnauthorized)
}

// Correctly signed, so only the format check itself can refuse these.
func TestNonceFormatEnforcedOnValidSignature(t *testing.T) {
	h := newHarness(t)
	admin := h.bootstrap()
	ts := h.clock.now().UnixMilli()
	for _, nonce := range []string{enc(randBytes(15)), enc(randBytes(17)), "not base64!!!!!!!!!!!!"} {
		h.signedAt(admin.signer(), "GET", "/v1/ledger", nil, ts, nonce).want(t, http.StatusUnauthorized, codeUnauthorized)
	}
}

func TestInvalidSignatureDoesNotBurnNonce(t *testing.T) {
	h := newHarness(t)
	admin := h.bootstrap()
	ts := h.clock.now().UnixMilli()
	nonce := enc(randBytes(16))

	h.signedAt(newDeviceClaiming(t, admin.id), "GET", "/v1/ledger", nil, ts, nonce).want(t, http.StatusUnauthorized, codeUnauthorized)
	h.signedAt(admin.signer(), "GET", "/v1/ledger", nil, ts, nonce).ok(t)
}

// newDeviceClaiming signs with a fresh key while claiming another device's id.
func newDeviceClaiming(t *testing.T, id string) signer {
	s := newDevice(t).signer()
	s.name = id
	return s
}

func TestNonceCacheExpiry(t *testing.T) {
	c := newNonceCache()
	if !c.add("n", 0) {
		t.Fatal("first add refused")
	}
	if c.add("n", nonceRetainMs) {
		t.Fatal("nonce forgotten too early")
	}
	c.sweep(nonceRetainMs + 1)
	if len(c.seen) != 0 {
		t.Fatal("sweep kept an expired nonce")
	}
}

func TestUnknownAndRevokedDevices(t *testing.T) {
	h := newHarness(t)
	h.bootstrap()

	stranger := newDevice(t)
	h.call(stranger.signer(), "GET", "/v1/ledger", nil).want(t, http.StatusUnauthorized, codeUnauthorized)

	member := h.addDevice(ledger.RoleMember, vault1)
	h.call(member.signer(), "GET", "/v1/ledger", nil).ok(t)
	h.revoke(member)
	h.call(member.signer(), "GET", "/v1/ledger", nil).want(t, http.StatusUnauthorized, codeUnauthorized)
	h.call(member.signer(), "GET", changesURI(vault1), nil).want(t, http.StatusUnauthorized, codeUnauthorized)
}

func TestRootAuth(t *testing.T) {
	h := newHarness(t)
	h.bootstrap()

	_, wrong, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	h.call(rootSigner(wrong), "GET", "/v1/ledger", nil).want(t, http.StatusUnauthorized, codeUnauthorized)

	// Routes the spec does not mark `root` refuse it even with a valid key.
	for _, r := range []struct{ method, uri string }{
		{"POST", "/v1/pair"},
		{"GET", "/v1/audit"},
		{"POST", changesURI(vault1)},
		{"GET", blobURI(vault1, "b")},
	} {
		h.call(h.rootSigner(), r.method, r.uri, nil).want(t, http.StatusForbidden, codeForbidden)
	}
}

func TestRootCannotAuthenticateBeforeGenesis(t *testing.T) {
	h := newHarness(t)
	h.call(h.rootSigner(), "GET", "/v1/ledger", nil).want(t, http.StatusUnauthorized, codeUnauthorized)
}

func TestAdminOnlyRoutesRefuseMembers(t *testing.T) {
	h := newHarness(t)
	h.bootstrap()
	member := h.addDevice(ledger.RoleMember, vault1)

	for _, r := range []struct{ method, uri string }{
		{"POST", "/v1/ledger"},
		{"POST", "/v1/pair"},
		{"GET", "/v1/pair/abc/admin"},
		{"POST", "/v1/pair/abc/grant"},
		{"DELETE", "/v1/pair/abc"},
		{"PUT", keysURI(vault1)},
		{"POST", rotateURI(vault1)},
		{"GET", "/v1/audit"},
	} {
		t.Run(r.method+" "+r.uri, func(t *testing.T) {
			h.call(member.signer(), r.method, r.uri, []byte("{}")).want(t, http.StatusForbidden, codeForbidden)
		})
	}
}

// tripwire is a request body that records whether anything tried to read it.
type tripwire struct{ reads atomic.Int64 }

func (b *tripwire) Read([]byte) (int, error) {
	b.reads.Add(1)
	return 0, io.EOF
}

func (b *tripwire) Close() error { return nil }

// serveTripped runs a request through the handler with a tripwire body claiming
// to be large, and reports the status and how often the body was touched.
func (h *harness) serveTripped(method, uri string, headers map[string]string) (int, int64) {
	h.t.Helper()
	body := &tripwire{}
	req := httptest.NewRequest(method, uri, nil)
	req.Body = body
	req.ContentLength = 90 << 20
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.srv.ServeHTTP(rec, req)
	return rec.Code, body.reads.Load()
}

// The point of X-Mx-Body: nobody without a key can make the server buffer
// anything. Each case here is a request that used to reach the body read.
func TestBodyNotReadUntilSignatureVerified(t *testing.T) {
	h := newHarness(t)
	admin := h.bootstrap()
	revoked := h.addDevice(ledger.RoleMember, vault1)
	h.revoke(revoked)

	uri := rotateURI(vault1)
	ts := strconv.FormatInt(h.clock.now().UnixMilli(), 10)
	hash := bodyDigest([]byte("anything"))
	fresh := func() string { return enc(randBytes(16)) }
	forged := func(name string) map[string]string {
		m := authHeaders(admin.signer(), "POST", uri, ts, fresh(), hash)
		m[hdrDevice] = name
		m[hdrSig] = enc(randBytes(64))
		return m
	}
	expired := authHeaders(admin.signer(), "POST", uri, strconv.FormatInt(h.clock.now().UnixMilli()-400_000, 10), fresh(), hash)
	missingHash := authHeaders(admin.signer(), "POST", uri, ts, fresh(), hash)
	delete(missingHash, hdrBody)

	// Validly signed, so only the format check can stop these.
	upper := authHeaders(admin.signer(), "POST", uri, ts, fresh(), strings.ToUpper(hash))
	short := authHeaders(admin.signer(), "POST", uri, ts, fresh(), hash[:63])
	nonHex := authHeaders(admin.signer(), "POST", uri, ts, fresh(), "g"+hash[1:])

	replayed := authHeaders(admin.signer(), "POST", uri, ts, fresh(), hash)
	if _, reads := h.serveTripped("POST", uri, replayed); reads == 0 {
		t.Fatal("a valid signature should reach the body")
	}

	cases := []struct {
		name    string
		uri     string
		headers map[string]string
		status  int
	}{
		{"anonymous claiming root", uri, forged(ledger.Root), http.StatusUnauthorized},
		{"anonymous claiming a known device", uri, forged(admin.id), http.StatusUnauthorized},
		{"unknown device", uri, forged(newDevice(t).id), http.StatusUnauthorized},
		{"revoked device", uri, authHeaders(revoked.signer(), "POST", uri, ts, fresh(), hash), http.StatusUnauthorized},
		{"expired timestamp", uri, expired, http.StatusUnauthorized},
		{"replayed nonce", uri, replayed, http.StatusUnauthorized},
		{"missing body hash", uri, missingHash, http.StatusUnauthorized},
		{"uppercase body hash", uri, upper, http.StatusUnauthorized},
		{"short body hash", uri, short, http.StatusUnauthorized},
		{"non-hex body hash", uri, nonHex, http.StatusUnauthorized},
		{"no headers at all", uri, nil, http.StatusUnauthorized},
		{"root on a route that refuses it", "/v1/pair", forged(ledger.Root), http.StatusForbidden},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			status, reads := h.serveTripped("POST", c.uri, c.headers)
			if status != c.status {
				t.Fatalf("status = %d, want %d", status, c.status)
			}
			if reads != 0 {
				t.Fatalf("body was read %d times before authentication", reads)
			}
		})
	}
}

func TestBodyMustMatchSignedHash(t *testing.T) {
	h := newHarness(t)
	admin := h.bootstrap()
	ts := strconv.FormatInt(h.clock.now().UnixMilli(), 10)
	uri := changesURI(vault1)
	good := mustJSON(map[string]any{"changes": []any{change("a", 1)}})
	bad := mustJSON(map[string]any{"changes": []any{change("b", 1)}})

	nonce := enc(randBytes(16))
	headers := authHeaders(admin.signer(), "POST", uri, ts, nonce, bodyDigest(good))
	h.raw("POST", uri, bad, headers).want(t, http.StatusUnauthorized, codeUnauthorized)
	res := h.call(admin.signer(), "GET", uri, nil)
	res.ok(t)
	if n := len(res.list(t, "changes")); n != 0 {
		t.Fatalf("a body that did not match its hash stored %d changes", n)
	}

	// The nonce was spent at the signature, before the body was looked at.
	h.raw("POST", uri, good, headers).want(t, http.StatusUnauthorized, codeUnauthorized)

	h.raw("POST", uri, good, authHeaders(admin.signer(), "POST", uri, ts, enc(randBytes(16)), bodyDigest(good))).ok(t)
}

func TestBodyMismatchCountsAsAuthFailure(t *testing.T) {
	h := newHarness(t, withRate(0.001, 2))
	admin := h.bootstrapDirect()
	uri := changesURI(vault1)
	for i := 0; i < 2; i++ {
		ts := strconv.FormatInt(h.clock.now().UnixMilli(), 10)
		headers := authHeaders(admin.signer(), "POST", uri, ts, enc(randBytes(16)), bodyDigest([]byte("x")))
		h.raw("POST", uri, []byte("y"), headers).want(t, http.StatusUnauthorized, codeUnauthorized)
	}
	h.call(admin.signer(), "GET", "/v1/ledger", nil).want(t, http.StatusTooManyRequests, codeRateLimited)
}

func TestEmptyBodyStillNeedsItsHash(t *testing.T) {
	h := newHarness(t)
	admin := h.bootstrap()
	empty := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	ts := strconv.FormatInt(h.clock.now().UnixMilli(), 10)
	h.raw("GET", "/v1/ledger", nil, authHeaders(admin.signer(), "GET", "/v1/ledger", ts, enc(randBytes(16)), empty)).ok(t)
}

// crypto/ed25519 accepts this request; libsodium, and so the client, would not.
func TestRootRequestRefusesSmallOrderR(t *testing.T) {
	h := newHarness(t)
	h.bootstrap()
	forged := signer{name: ledger.Root, sign: func(msg []byte) []byte {
		sig := edtest.IdentityR(h.root, msg)
		if !ed25519.Verify(h.root.Public().(ed25519.PublicKey), msg, sig) {
			t.Fatal("test vector is not accepted by crypto/ed25519, so it proves nothing")
		}
		return sig
	}}
	h.call(forged, "GET", "/v1/ledger", nil).want(t, http.StatusUnauthorized, codeUnauthorized)
}
