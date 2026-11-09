package api

import (
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"testing"

	"mixia/server/internal/edtest"
	"mixia/server/internal/ledger"
)

const rootRotateURI = "/v1/root/rotate"

func recoveryWrap(vault string, gen int64) map[string]any {
	return map[string]any{"vaultId": vault, "gen": gen, "wrapped": enc(randBytes(80))}
}

// nextRoot builds a root_rotate signed by the current root.
func (h *harness) nextRoot() (ed25519.PrivateKey, ledger.Wire) {
	h.t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		h.t.Fatal(err)
	}
	return priv, h.rootEntry(ledger.TypeRootRotate, map[string]any{"rootPub": enc(pub), "recoveryBoxPub": enc(randBytes(32))})
}

func (h *harness) rotateRoot(keys ...map[string]any) {
	h.t.Helper()
	if keys == nil {
		keys = []map[string]any{}
	}
	priv, entry := h.nextRoot()
	h.callJSON(h.rootSigner(), "POST", rootRotateURI, map[string]any{"entry": entry, "keys": keys}).ok(h.t)
	h.commit(entry)
	h.root = priv
}

func recoveryWraps(t *testing.T, h *harness, vault string) []any {
	t.Helper()
	res := h.call(h.rootSigner(), "GET", keysURI(vault), nil)
	res.ok(t)
	return res.list(t, "keys")
}

func TestRootRotate(t *testing.T) {
	h := newHarness(t)
	admin := h.bootstrap()
	h.addVault("v2")
	old := h.rootSigner()
	wrap1, wrap2 := recoveryWrap(vault1, 1), recoveryWrap("v2", 1)
	priv, entry := h.nextRoot()

	res := h.callJSON(old, "POST", rootRotateURI, map[string]any{"entry": entry, "keys": []any{wrap1, wrap2}})
	res.ok(t)
	h.commit(entry)
	h.root = priv
	if got := res.number(t, "head"); got != h.head {
		t.Fatalf("head = %d, want %d", got, h.head)
	}

	// The old root is finished the moment the transaction commits.
	h.call(old, "GET", "/v1/ledger", nil).want(t, http.StatusUnauthorized, codeUnauthorized)
	for vault, want := range map[string]any{vault1: wrap1["wrapped"], "v2": wrap2["wrapped"]} {
		keys := recoveryWraps(t, h, vault)
		if len(keys) != 1 || keys[0].(map[string]any)["wrapped"] != want {
			t.Fatalf("recovery wraps of %s = %v", vault, keys)
		}
	}

	// Device wraps are not recovery wraps and stay where they are.
	res = h.call(admin.signer(), "GET", keysURI(vault1), nil)
	res.ok(t)
	if n := len(res.list(t, "keys")); n != 1 {
		t.Fatalf("admin keys = %d", n)
	}

	res = h.call(admin.signer(), "GET", "/v1/audit?limit=1", nil)
	res.ok(t)
	e := res.list(t, "events")[0].(map[string]any)
	if e["action"] != ledger.TypeRootRotate || e["device"] != ledger.Root {
		t.Fatalf("audit = %v", e)
	}

	// The entry replays, although the write path refuses it outside this route.
	h.restart()
	h.call(h.rootSigner(), "GET", "/v1/ledger", nil).ok(t)
	if keys := recoveryWraps(t, h, "v2"); keys[0].(map[string]any)["wrapped"] != wrap2["wrapped"] {
		t.Fatalf("recovery wrap lost across restart: %v", keys)
	}
}

func TestRootRotateCoversZeroOneAndManyVaults(t *testing.T) {
	h := newHarness(t)
	h.bootstrap()
	h.rotateRoot(recoveryWrap(vault1, 1)) // one

	h.addVault("v2")
	h.addVault("v3")
	h.rotateRoot(recoveryWrap(vault1, 1), recoveryWrap("v2", 1), recoveryWrap("v3", 1)) // many

	for _, id := range []string{vault1, "v2", "v3"} {
		h.mustAppend(h.rootSigner(), func() ledger.Wire {
			return h.rootEntry(ledger.TypeVaultDelete, map[string]any{"vaultId": id})
		})
	}
	h.rotateRoot() // none
}

func TestRootRotateUsesCurrentGeneration(t *testing.T) {
	h, admin, _ := rotateFixture(t)
	req := h.rotateBody(admin.id, admin.sign, vault1, 2, nil, "s1")
	h.callJSON(admin.signer(), "POST", rotateURI(vault1), req).ok(t)
	h.commit(entryOf(req))

	_, entry := h.nextRoot()
	body := map[string]any{"entry": entry, "keys": []any{recoveryWrap(vault1, 1)}}
	h.callJSON(h.rootSigner(), "POST", rootRotateURI, body).want(t, http.StatusBadRequest, codeBadRequest)

	h.rotateRoot(recoveryWrap(vault1, 2))
	keys := recoveryWraps(t, h, vault1)
	if len(keys) != 1 || keys[0].(map[string]any)["gen"] != float64(2) {
		t.Fatalf("recovery wraps = %v", keys)
	}
}

func TestRootRotateRefused(t *testing.T) {
	h := newHarness(t)
	admin := h.bootstrap()
	h.addVault("v2")
	good := []any{recoveryWrap(vault1, 1), recoveryWrap("v2", 1)}
	_, entry := h.nextRoot()

	// Everything the route could change, to prove a refusal changes none of it.
	state := func() string {
		var b []byte
		for _, r := range []*response{
			h.call(h.rootSigner(), "GET", "/v1/ledger", nil),
			h.call(h.rootSigner(), "GET", keysURI(vault1), nil),
			h.call(h.rootSigner(), "GET", keysURI("v2"), nil),
		} {
			r.ok(t)
			b = append(b, r.body...)
		}
		return string(b)
	}
	before := state()

	smallOrderRoot := h.rootEntry(ledger.TypeRootRotate, map[string]any{
		"rootPub": enc(edtest.Identity().Encode()), "recoveryBoxPub": enc(randBytes(32)),
	})
	_, stranger, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	foreignDevice := recoveryWrap("v2", 1)
	foreignDevice["deviceId"] = admin.id
	emptyWrap := recoveryWrap("v2", 1)
	emptyWrap["wrapped"] = ""
	data := map[string]any{"rootPub": enc(stranger.Public().(ed25519.PublicKey)), "recoveryBoxPub": enc(randBytes(32))}

	cases := []struct {
		name   string
		body   map[string]any
		status int
		code   string
	}{
		{"no keys", map[string]any{"entry": entry, "keys": []any{}}, 400, codeBadRequest},
		{"vault missing", map[string]any{"entry": entry, "keys": good[:1]}, 400, codeBadRequest},
		{"unknown vault", map[string]any{"entry": entry, "keys": append(good[:2:2], recoveryWrap("ghost", 1))}, 400, codeBadRequest},
		{"unknown vault replacing a real one", map[string]any{"entry": entry, "keys": []any{good[0], recoveryWrap("ghost", 1)}}, 400, codeBadRequest},
		{"duplicate vault", map[string]any{"entry": entry, "keys": []any{good[0], good[0]}}, 400, codeBadRequest},
		{"duplicate on top of a full set", map[string]any{"entry": entry, "keys": append(good[:2:2], good[0])}, 400, codeBadRequest},
		{"wrong gen", map[string]any{"entry": entry, "keys": []any{good[0], recoveryWrap("v2", 2)}}, 400, codeBadRequest},
		{"empty wrap", map[string]any{"entry": entry, "keys": []any{good[0], emptyWrap}}, 400, codeBadRequest},
		{"wrap for a device", map[string]any{"entry": entry, "keys": []any{good[0], foreignDevice}}, 400, codeBadRequest},
		{"no entry", map[string]any{"keys": good}, 400, codeBadRequest},
		{"entry is not root_rotate", map[string]any{"entry": h.rootEntry(ledger.TypeVaultAdd, vaultData("x")), "keys": good}, 400, codeLedgerInvalid},
		{"entry signed by a stranger", map[string]any{"entry": makeEntry(h.head+1, h.prev, ledger.Root, stranger, ledger.TypeRootRotate, data), "keys": good}, 400, codeLedgerInvalid},
		{"entry signed by an admin", map[string]any{"entry": h.deviceEntry(admin, ledger.TypeRootRotate, data), "keys": good}, 400, codeLedgerInvalid},
		{"small-order new root", map[string]any{"entry": smallOrderRoot, "keys": good}, 400, codeLedgerInvalid},
		{"seq conflict", map[string]any{"entry": makeEntry(h.head+5, h.prev, ledger.Root, h.root, ledger.TypeRootRotate, data), "keys": good}, 409, codeLedgerConflict},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h.callJSON(h.rootSigner(), "POST", rootRotateURI, c.body).want(t, c.status, c.code)
			if after := state(); after != before {
				t.Fatalf("state changed:\nbefore %s\nafter  %s", before, after)
			}
		})
	}

	// A deviceId of "recovery" says what is already implied.
	explicit := recoveryWrap("v2", 1)
	explicit["deviceId"] = ledger.Recovery
	h.callJSON(h.rootSigner(), "POST", rootRotateURI, map[string]any{"entry": entry, "keys": []any{good[0], explicit}}).ok(t)
}

func TestRootRotateOnlyRoot(t *testing.T) {
	h := newHarness(t)
	admin := h.bootstrap()
	member := h.addDevice(ledger.RoleMember, vault1)
	_, entry := h.nextRoot()
	body := map[string]any{"entry": entry, "keys": []any{recoveryWrap(vault1, 1)}}
	h.callJSON(admin.signer(), "POST", rootRotateURI, body).want(t, http.StatusForbidden, codeForbidden)
	h.callJSON(member.signer(), "POST", rootRotateURI, body).want(t, http.StatusForbidden, codeForbidden)
	h.raw("POST", rootRotateURI, mustJSON(body), nil).want(t, http.StatusUnauthorized, codeUnauthorized)
}

func TestRootRotateNotThroughLedger(t *testing.T) {
	h := newHarness(t)
	h.bootstrap()
	_, entry := h.nextRoot()
	h.postEntries(h.rootSigner(), entry).want(t, http.StatusBadRequest, codeLedgerInvalid)

	fresh := newHarness(t)
	genesis := fresh.rootEntry(ledger.TypeGenesis, genesisData(fresh.root))
	fresh.commit(genesis)
	_, rotate := fresh.nextRoot()
	body := mustJSON(map[string]any{"token": testToken, "entries": []ledger.Wire{genesis, rotate}, "keys": []any{}})
	fresh.raw("POST", "/v1/bootstrap", body, nil).want(t, http.StatusBadRequest, codeLedgerInvalid)
}
