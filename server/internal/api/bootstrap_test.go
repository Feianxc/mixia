package api

import (
	"net/http"
	"testing"

	"mixia/server/internal/ledger"
)

func bootstrapBody(token string, wires []ledger.Wire, keys []map[string]any) []byte {
	if keys == nil {
		keys = []map[string]any{}
	}
	return mustJSON(map[string]any{"token": token, "entries": wires, "keys": keys})
}

func infoBootstrapped(t *testing.T, h *harness) bool {
	t.Helper()
	res := h.raw("GET", "/v1/info", nil, nil)
	res.ok(t)
	return res.json(t)["bootstrapped"].(bool)
}

func TestInfoShape(t *testing.T) {
	h := newHarness(t)
	res := h.raw("GET", "/v1/info", nil, nil)
	res.ok(t)
	m := res.json(t)
	if m["proto"] != float64(1) || m["bootstrapped"] != false || m["time"].(float64) <= 0 {
		t.Fatalf("info = %v", m)
	}
	h.raw("GET", "/healthz", nil, nil).ok(t)
}

func TestBootstrapOnce(t *testing.T) {
	h := newHarness(t)
	h.bootstrap()
	if !infoBootstrapped(t, h) {
		t.Fatal("bootstrapped = false after bootstrap")
	}

	genesis := makeEntry(0, "", ledger.Root, h.root, ledger.TypeGenesis, genesisData(h.root))
	body := bootstrapBody(testToken, []ledger.Wire{genesis}, nil)
	h.raw("POST", "/v1/bootstrap", body, nil).want(t, http.StatusGone, codeGone)

	// Permanent: a restart with the token still configured changes nothing.
	h.restart()
	h.raw("POST", "/v1/bootstrap", body, nil).want(t, http.StatusGone, codeGone)

	// Nor does removing the token turn 410 into something else.
	h.cfg.BootstrapTokenHash = nil
	h.restart()
	h.raw("POST", "/v1/bootstrap", body, nil).want(t, http.StatusGone, codeGone)
}

func TestBootstrapWrongToken(t *testing.T) {
	h := newHarness(t)
	genesis := makeEntry(0, "", ledger.Root, h.root, ledger.TypeGenesis, genesisData(h.root))
	h.raw("POST", "/v1/bootstrap", bootstrapBody("wrong", []ledger.Wire{genesis}, nil), nil).
		want(t, http.StatusUnauthorized, codeUnauthorized)
	if infoBootstrapped(t, h) {
		t.Fatal("wrong token bootstrapped the server")
	}
	h.raw("POST", "/v1/bootstrap", bootstrapBody(testToken, []ledger.Wire{genesis}, nil), nil).ok(t)
}

func TestBootstrapDisabledWithoutEnv(t *testing.T) {
	h := newHarness(t, withoutBootstrapToken())
	genesis := makeEntry(0, "", ledger.Root, h.root, ledger.TypeGenesis, genesisData(h.root))
	h.raw("POST", "/v1/bootstrap", bootstrapBody(testToken, []ledger.Wire{genesis}, nil), nil).
		want(t, http.StatusForbidden, codeForbidden)
	if infoBootstrapped(t, h) {
		t.Fatal("bootstrap ran without a configured token")
	}
}

func TestBootstrapRejectsBadLedger(t *testing.T) {
	h := newHarness(t)
	genesis := makeEntry(0, "", ledger.Root, h.root, ledger.TypeGenesis, genesisData(h.root))
	hash := func(w ledger.Wire) string {
		e, err := ledger.Parse(w)
		if err != nil {
			t.Fatal(err)
		}
		return enc(e.Hash())
	}
	badKey := map[string]any{"vaultId": "nope", "deviceId": ledger.Recovery, "gen": 1, "wrapped": enc(randBytes(8))}

	cases := []struct {
		name string
		wire []ledger.Wire
		keys []map[string]any
		code string
	}{
		{"empty", []ledger.Wire{}, nil, codeLedgerInvalid},
		{"first is not genesis", []ledger.Wire{makeEntry(0, "", ledger.Root, h.root, ledger.TypeVaultAdd, vaultData(vault1))}, nil, codeLedgerInvalid},
		{"genesis at seq 1", []ledger.Wire{makeEntry(1, "", ledger.Root, h.root, ledger.TypeGenesis, genesisData(h.root))}, nil, codeLedgerInvalid},
		{"seq gap", []ledger.Wire{genesis, makeEntry(2, hash(genesis), ledger.Root, h.root, ledger.TypeVaultAdd, vaultData(vault1))}, nil, codeLedgerInvalid},
		{"key for unknown vault", []ledger.Wire{genesis}, []map[string]any{badKey}, codeBadRequest},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h.raw("POST", "/v1/bootstrap", bootstrapBody(testToken, c.wire, c.keys), nil).want(t, http.StatusBadRequest, c.code)
			if infoBootstrapped(t, h) {
				t.Fatal("failed bootstrap left the server bootstrapped")
			}
		})
	}
	h.raw("POST", "/v1/bootstrap", []byte("not json"), nil).want(t, http.StatusBadRequest, codeBadRequest)
}

func TestBootstrapWritesKeys(t *testing.T) {
	h := newHarness(t)
	admin := h.bootstrap()

	res := h.call(admin.signer(), "GET", keysURI(vault1), nil)
	res.ok(t)
	if n := len(res.list(t, "keys")); n != 1 {
		t.Fatalf("admin keys = %d, want 1", n)
	}
	res = h.call(h.rootSigner(), "GET", keysURI(vault1), nil)
	res.ok(t)
	if n := len(res.list(t, "keys")); n != 1 {
		t.Fatalf("recovery keys = %d, want 1", n)
	}
}
