package api

import (
	"crypto/sha256"
	"net/http"
	"testing"
	"time"

	"mixia/server/internal/ledger"
)

type pairing struct {
	id    string
	token string // b64
}

func (p pairing) header() map[string]string { return map[string]string{hdrPairToken: p.token} }

func (h *harness) openPair(admin *testDevice, id string) pairing {
	h.t.Helper()
	token := randBytes(32)
	sum := sha256.Sum256(token)
	h.callJSON(admin.signer(), "POST", "/v1/pair", map[string]any{
		"pairId":    id,
		"tokenHash": enc(sum[:]),
		"expiresAt": h.clock.now().Add(10 * time.Minute).UnixMilli(),
		"offer":     enc([]byte("offer-" + id)),
	}).ok(h.t)
	return pairing{id: id, token: enc(token)}
}

func TestPairFullFlow(t *testing.T) {
	h := newHarness(t)
	admin := h.bootstrap()
	s := admin.signer()
	p := h.openPair(admin, "ABC123")

	res := h.raw("GET", "/v1/pair/ABC123", nil, p.header())
	res.ok(t)
	m := res.json(t)
	if m["offer"] != enc([]byte("offer-ABC123")) || m["status"] != "open" || m["grant"] != nil {
		t.Fatalf("pair = %v", m)
	}
	res = h.call(s, "GET", "/v1/pair/ABC123/admin", nil)
	res.ok(t)
	if m := res.json(t); m["status"] != "open" || m["request"] != nil {
		t.Fatalf("admin view = %v", m)
	}

	req := enc([]byte("sealed request"))
	h.raw("POST", "/v1/pair/ABC123/request", mustJSON(map[string]any{"request": req}), p.header()).ok(t)
	res = h.call(s, "GET", "/v1/pair/ABC123/admin", nil)
	res.ok(t)
	if m := res.json(t); m["status"] != "requested" || m["request"] != req {
		t.Fatalf("admin view = %v", m)
	}

	// Approval: the device joins the ledger, then the grant is released.
	d := newDevice(t)
	h.mustAppend(s, func() ledger.Wire {
		return h.deviceEntry(admin, ledger.TypeDeviceAdd, deviceData(d, ledger.RoleMember, vault1))
	})
	h.callJSON(s, "PUT", keysURI(vault1), map[string]any{"keys": []any{wrapKey(d.id, 1)}}).ok(t)
	grant := enc([]byte("sealed grant"))
	h.callJSON(s, "POST", "/v1/pair/ABC123/grant", map[string]any{"grant": grant}).ok(t)

	res = h.raw("GET", "/v1/pair/ABC123", nil, p.header())
	res.ok(t)
	if m := res.json(t); m["status"] != "granted" || m["grant"] != grant {
		t.Fatalf("pair = %v", m)
	}

	// The new device now authenticates with its own key.
	h.call(d.signer(), "GET", "/v1/ledger", nil).ok(t)
	res = h.call(d.signer(), "GET", keysURI(vault1), nil)
	res.ok(t)
	if n := len(res.list(t, "keys")); n != 1 {
		t.Fatalf("new device keys = %d", n)
	}

	h.callJSON(s, "POST", "/v1/pair/ABC123/grant", map[string]any{"grant": grant}).want(t, http.StatusConflict, codePairUsed)
	h.call(s, "DELETE", "/v1/pair/ABC123", nil).ok(t)
	h.raw("GET", "/v1/pair/ABC123", nil, p.header()).want(t, http.StatusNotFound, codeNotFound)
	h.call(s, "DELETE", "/v1/pair/ABC123", nil).want(t, http.StatusNotFound, codeNotFound)
}

func TestPairWrongTokenDestroysAfterFive(t *testing.T) {
	h := newHarness(t)
	admin := h.bootstrap()
	p := h.openPair(admin, "ABC123")
	wrong := map[string]string{hdrPairToken: enc(randBytes(32))}

	for i := 0; i < 4; i++ {
		h.raw("GET", "/v1/pair/ABC123", nil, wrong).want(t, http.StatusUnauthorized, codeUnauthorized)
	}
	h.raw("GET", "/v1/pair/ABC123", nil, p.header()).ok(t) // still alive after four

	// The fifth may come from any route, and a missing token counts too.
	h.raw("POST", "/v1/pair/ABC123/request", []byte(`{"request":"eA"}`), nil).want(t, http.StatusUnauthorized, codeUnauthorized)
	h.raw("GET", "/v1/pair/ABC123", nil, p.header()).want(t, http.StatusNotFound, codeNotFound)
}

func TestPairExpiry(t *testing.T) {
	h := newHarness(t)
	admin := h.bootstrap()
	p := h.openPair(admin, "ABC123")

	h.clock.advance(11 * time.Minute)
	h.raw("GET", "/v1/pair/ABC123", nil, p.header()).want(t, http.StatusGone, codePairExpired)
	h.raw("POST", "/v1/pair/ABC123/request", []byte(`{"request":"eA"}`), p.header()).want(t, http.StatusGone, codePairExpired)
	h.call(admin.signer(), "GET", "/v1/pair/ABC123/admin", nil).want(t, http.StatusGone, codePairExpired)
	h.callJSON(admin.signer(), "POST", "/v1/pair/ABC123/grant", map[string]any{"grant": "eA"}).want(t, http.StatusGone, codePairExpired)

	h.srv.janitorPass()
	h.raw("GET", "/v1/pair/ABC123", nil, p.header()).want(t, http.StatusNotFound, codeNotFound)
}

func TestPairRequestOnlyOnce(t *testing.T) {
	h := newHarness(t)
	admin := h.bootstrap()
	p := h.openPair(admin, "ABC123")
	body := []byte(`{"request":"eA"}`)

	h.raw("POST", "/v1/pair/ABC123/request", body, p.header()).ok(t)
	h.raw("POST", "/v1/pair/ABC123/request", body, p.header()).want(t, http.StatusConflict, codePairUsed)
}

func TestPairGrantNeedsRequest(t *testing.T) {
	h := newHarness(t)
	admin := h.bootstrap()
	h.openPair(admin, "ABC123")
	h.callJSON(admin.signer(), "POST", "/v1/pair/ABC123/grant", map[string]any{"grant": "eA"}).want(t, http.StatusBadRequest, codeBadRequest)
}

func TestPairCreateValidation(t *testing.T) {
	h := newHarness(t)
	admin := h.bootstrap()
	now := h.clock.now()
	base := func(mut func(map[string]any)) map[string]any {
		m := map[string]any{
			"pairId": "ABC123", "tokenHash": enc(randBytes(32)),
			"expiresAt": now.Add(5 * time.Minute).UnixMilli(), "offer": enc([]byte("o")),
		}
		mut(m)
		return m
	}
	cases := map[string]func(map[string]any){
		"ttl over 15 minutes": func(m map[string]any) { m["expiresAt"] = now.Add(16 * time.Minute).UnixMilli() },
		"already expired":     func(m map[string]any) { m["expiresAt"] = now.Add(-time.Second).UnixMilli() },
		"bad pair id":         func(m map[string]any) { m["pairId"] = "../x" },
		"short token hash":    func(m map[string]any) { m["tokenHash"] = enc(randBytes(31)) },
		"empty offer":         func(m map[string]any) { m["offer"] = "" },
	}
	for name, mut := range cases {
		t.Run(name, func(t *testing.T) {
			h.callJSON(admin.signer(), "POST", "/v1/pair", base(mut)).want(t, http.StatusBadRequest, codeBadRequest)
		})
	}
	// Exactly 15 minutes is allowed.
	h.callJSON(admin.signer(), "POST", "/v1/pair", base(func(m map[string]any) {
		m["expiresAt"] = h.clock.now().Add(pairTTL).UnixMilli()
	})).ok(t)
	// The id is taken now.
	h.callJSON(admin.signer(), "POST", "/v1/pair", base(func(map[string]any) {})).want(t, http.StatusConflict, codePairUsed)
}

func TestPairOpenLimit(t *testing.T) {
	h := newHarness(t)
	admin := h.bootstrap()
	s := admin.signer()
	h.openPair(admin, "P1")
	p2 := h.openPair(admin, "P2")
	h.openPair(admin, "P3")

	fourth := map[string]any{
		"pairId": "P4", "tokenHash": enc(randBytes(32)),
		"expiresAt": h.clock.now().Add(time.Minute).UnixMilli(), "offer": enc([]byte("o")),
	}
	h.callJSON(s, "POST", "/v1/pair", fourth).want(t, http.StatusTooManyRequests, codeRateLimited)

	// A granted pairing is finished and frees its slot.
	h.raw("POST", "/v1/pair/P2/request", []byte(`{"request":"eA"}`), p2.header()).ok(t)
	h.callJSON(s, "POST", "/v1/pair/P2/grant", map[string]any{"grant": "eA"}).ok(t)
	h.callJSON(s, "POST", "/v1/pair", fourth).ok(t)
	h.call(s, "DELETE", "/v1/pair/P1", nil).ok(t)

	// So does expiry, without waiting for the janitor.
	h.clock.advance(11 * time.Minute)
	h.openPair(admin, "P5")
	h.openPair(admin, "P6")
	h.openPair(admin, "P7")
}

func TestPairPathValidation(t *testing.T) {
	h := newHarness(t)
	h.bootstrap()
	h.raw("GET", "/v1/pair/%2e%2e", nil, nil).want(t, http.StatusBadRequest, codeBadRequest)
	h.raw("GET", "/v1/pair/unknown", nil, map[string]string{hdrPairToken: enc(randBytes(32))}).want(t, http.StatusNotFound, codeNotFound)
}
