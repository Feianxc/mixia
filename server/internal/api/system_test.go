package api

import (
	"bytes"
	"database/sql"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"mixia/server/internal/ledger"
	"mixia/server/internal/store"
)

func itoa(n int64) string { return strconv.FormatInt(n, 10) }

func blobFiles(t *testing.T, h *harness) []os.DirEntry {
	t.Helper()
	files, err := os.ReadDir(filepath.Join(h.dir, "blobs"))
	if err != nil {
		t.Fatal(err)
	}
	return files
}

func TestRestartRebuildsState(t *testing.T) {
	h := newHarness(t)
	admin := h.bootstrap()
	member := h.addDevice(ledger.RoleMember, vault1)
	gone := h.addDevice(ledger.RoleMember, vault1)
	h.revoke(gone)
	h.pushChanges(admin, vault1, 1, "a", "b").ok(t)
	req := h.rotateBody(admin.id, admin.sign, vault1, 2, []map[string]any{wrapKey(admin.id, 2)}, "s1")
	h.callJSON(admin.signer(), "POST", rotateURI(vault1), req).ok(t)
	h.commit(entryOf(req))
	h.call(admin.signer(), "PUT", blobURI(vault1, "b"), []byte("payload")).ok(t)

	headBefore := h.st.State().HeadHash
	h.restart()

	if got := h.st.State(); !bytes.Equal(got.HeadHash, headBefore) || got.Head != h.head {
		t.Fatalf("head after restart = %d, want %d", got.Head, h.head)
	}
	h.call(admin.signer(), "GET", "/v1/ledger", nil).ok(t)
	h.call(member.signer(), "GET", "/v1/ledger", nil).ok(t)
	h.call(gone.signer(), "GET", "/v1/ledger", nil).want(t, http.StatusUnauthorized, codeUnauthorized)

	res := h.call(admin.signer(), "GET", changesURI(vault1), nil)
	res.ok(t)
	if gen, head := res.number(t, "gen"), res.number(t, "head"); gen != 2 || head != 3 {
		t.Fatalf("gen=%d head=%d, want 2 3", gen, head)
	}
	res = h.call(admin.signer(), "GET", blobURI(vault1, "b"), nil)
	res.ok(t)
	if !bytes.Equal(res.body, []byte("payload")) {
		t.Fatalf("blob = %q", res.body)
	}
	// The chain continues from the rebuilt head.
	h.addVault("after-restart")
}

func TestRequestFromBeforeRestartCannotBeReplayed(t *testing.T) {
	h := newHarness(t)
	admin := h.bootstrap()
	ts := h.clock.now().UnixMilli()
	nonce := enc(randBytes(16))
	h.signedAt(admin.signer(), "GET", "/v1/ledger", nil, ts, nonce).ok(t)

	// A restart forgets the nonce, which is what the start-time floor is for.
	h.clock.advance(10 * time.Second)
	h.restart()
	h.signedAt(admin.signer(), "GET", "/v1/ledger", nil, ts, nonce).want(t, http.StatusUnauthorized, codeUnauthorized)
}

func tamperDB(t *testing.T, h *harness, stmt string, args ...any) {
	t.Helper()
	h.stop()
	db, err := sql.Open("sqlite", filepath.Join(h.dir, "mixia.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	res, err := db.Exec(stmt, args...)
	if err != nil {
		t.Fatal(err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		t.Fatalf("tamper statement changed nothing: %s", stmt)
	}
}

func TestTamperedDatabaseRefusesToStart(t *testing.T) {
	cases := []struct {
		name string
		stmt string
		args []any
	}{
		{"body altered", `UPDATE ledger SET body = CAST(REPLACE(CAST(body AS TEXT), 'software', 'hardware') AS BLOB) WHERE seq = 3`, nil},
		{"signature altered", `UPDATE ledger SET sig = zeroblob(64) WHERE seq = 1`, nil},
		{"middle entry removed", `DELETE FROM ledger WHERE seq = 1`, nil},
		{"genesis removed", `DELETE FROM ledger WHERE seq = 0`, nil},
		{"entries swapped", `UPDATE ledger SET seq = 100 WHERE seq = 1; UPDATE ledger SET seq = 1 WHERE seq = 2; UPDATE ledger SET seq = 2 WHERE seq = 100`, nil},
		{"vault generation altered", `UPDATE vaults SET gen = 7`, nil},
		{"vault row removed", `DELETE FROM vaults`, nil},
		{"vault row added", `INSERT INTO vaults (vault_id, gen, head) VALUES ('ghost', 1, 0)`, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := newHarness(t)
			h.bootstrap()
			h.addDevice(ledger.RoleMember, vault1)
			tamperDB(t, h, c.stmt, c.args...)

			if st, err := store.Open(h.dir, hugeQuota); err == nil {
				st.Close()
				t.Fatal("store opened a tampered database")
			}
			if _, err := store.Verify(h.dir); err == nil {
				t.Fatal("verify passed a tampered database")
			}
		})
	}
}

func TestBlobRoundTrip(t *testing.T) {
	h := newHarness(t)
	admin := h.bootstrap()
	s := admin.signer()
	uri := blobURI(vault1, "att-1")
	data := randBytes(70_000)

	h.call(s, "GET", uri, nil).want(t, http.StatusNotFound, codeNotFound)
	h.call(s, "DELETE", uri, nil).want(t, http.StatusNotFound, codeNotFound)
	h.call(s, "PUT", uri, data).ok(t)

	res := h.call(s, "GET", uri, nil)
	res.ok(t)
	if !bytes.Equal(res.body, data) {
		t.Fatal("blob bytes differ")
	}
	if ct := res.header.Get("Content-Type"); ct != "application/octet-stream" {
		t.Fatalf("Content-Type = %q", ct)
	}

	// Overwrite replaces, leaving a single file and no temp files.
	h.call(s, "PUT", uri, []byte("short")).ok(t)
	res = h.call(s, "GET", uri, nil)
	res.ok(t)
	if string(res.body) != "short" {
		t.Fatalf("blob = %q", res.body)
	}
	if files := blobFiles(t, h); len(files) != 1 {
		t.Fatalf("files = %d, want 1", len(files))
	}

	h.call(s, "DELETE", uri, nil).ok(t)
	h.call(s, "GET", uri, nil).want(t, http.StatusNotFound, codeNotFound)
	if files := blobFiles(t, h); len(files) != 0 {
		t.Fatalf("files after delete = %d", len(files))
	}
}

func TestBlobPathTraversalRejected(t *testing.T) {
	h := newHarness(t)
	admin := h.bootstrap()
	s := admin.signer()
	secret := filepath.Join(h.dir, "mixia.db")
	before, err := os.ReadFile(secret)
	if err != nil {
		t.Fatal(err)
	}

	bad := []string{
		"/v1/vaults/v1/blobs/..%2f..%2fmixia.db",
		"/v1/vaults/v1/blobs/..%5c..%5cmixia.db",
		"/v1/vaults/v1/blobs/%2e%2e",
		"/v1/vaults/v1/blobs/a%2fb",
		"/v1/vaults/v1/blobs/a%00b",
		"/v1/vaults/v1/blobs/" + strings.Repeat("a", 65),
	}
	for _, uri := range bad {
		t.Run(uri, func(t *testing.T) {
			h.call(s, "PUT", uri, []byte("x")).want(t, http.StatusBadRequest, codeBadRequest)
			h.call(s, "GET", uri, nil).want(t, http.StatusBadRequest, codeBadRequest)
			h.call(s, "DELETE", uri, nil).want(t, http.StatusBadRequest, codeBadRequest)
		})
	}
	// The vault segment gets the same treatment.
	h.call(s, "PUT", "/v1/vaults/..%2fv1/blobs/x", []byte("x")).want(t, http.StatusBadRequest, codeBadRequest)
	h.call(s, "GET", "/v1/vaults/..%2fv1/changes", nil).want(t, http.StatusBadRequest, codeBadRequest)

	// Literal dot segments never reach a handler.
	for _, uri := range []string{"/v1/vaults/v1/blobs/../../x", "/v1/vaults/v1/blobs/./x", "/v1/vaults//v1/blobs/x"} {
		h.call(s, "PUT", uri, []byte("x")).want(t, http.StatusNotFound, codeNotFound)
	}

	if files := blobFiles(t, h); len(files) != 0 {
		t.Fatalf("traversal attempts created %d files", len(files))
	}
	after, err := os.ReadFile(secret)
	if err != nil {
		t.Fatal(err)
	}
	if len(after) < len(before) {
		t.Fatal("database file shrank")
	}
}

func TestBlobNamesDoNotCollideAcrossVaults(t *testing.T) {
	h := newHarness(t)
	admin := h.bootstrap()
	h.addVault("ab")
	h.addVault("a")
	h.mustAppend(h.rootSigner(), func() ledger.Wire {
		return h.rootEntry(ledger.TypeGrant, map[string]any{"deviceId": admin.id, "role": "admin", "vaults": []string{"ab", "a"}})
	})
	s := admin.signer()
	h.call(s, "PUT", blobURI("ab", "c"), []byte("first")).ok(t)
	h.call(s, "PUT", blobURI("a", "bc"), []byte("second")).ok(t)
	res := h.call(s, "GET", blobURI("ab", "c"), nil)
	res.ok(t)
	if string(res.body) != "first" {
		t.Fatalf("blob of vault ab = %q", res.body)
	}
}

func TestBlobSizeLimit(t *testing.T) {
	h := newHarness(t)
	admin := h.bootstrap()
	s := admin.signer()
	h.call(s, "PUT", blobURI(vault1, "max"), make([]byte, maxBlobBody)).ok(t)
	h.call(s, "PUT", blobURI(vault1, "over"), make([]byte, maxBlobBody+1)).want(t, http.StatusRequestEntityTooLarge, codeTooLarge)
	h.call(s, "GET", blobURI(vault1, "over"), nil).want(t, http.StatusNotFound, codeNotFound)
}

func TestBodyLimits(t *testing.T) {
	h := newHarness(t)
	admin := h.bootstrap()
	s := admin.signer()

	h.call(s, "POST", changesURI(vault1), make([]byte, 8<<20+1)).want(t, http.StatusRequestEntityTooLarge, codeTooLarge)
	h.call(s, "POST", changesURI(vault1), make([]byte, 8<<20)).want(t, http.StatusBadRequest, codeBadRequest)

	// The full size passes the limit and fails only for not being JSON.
	h.call(s, "POST", rotateURI(vault1), make([]byte, 96<<20+1)).want(t, http.StatusRequestEntityTooLarge, codeTooLarge)
	h.call(s, "POST", rotateURI(vault1), make([]byte, 96<<20)).want(t, http.StatusBadRequest, codeBadRequest)
}

func TestAnonymousBodyLimit(t *testing.T) {
	const limit = 64 << 10
	fresh := newHarness(t)
	fresh.raw("POST", "/v1/bootstrap", make([]byte, limit+1), nil).want(t, http.StatusRequestEntityTooLarge, codeTooLarge)
	fresh.raw("POST", "/v1/bootstrap", make([]byte, limit), nil).want(t, http.StatusBadRequest, codeBadRequest)

	h := newHarness(t)
	admin := h.bootstrap()
	p := h.openPair(admin, "ABC123")
	uri := "/v1/pair/ABC123/request"
	h.raw("POST", uri, make([]byte, limit+1), p.header()).want(t, http.StatusRequestEntityTooLarge, codeTooLarge)
	h.raw("POST", uri, make([]byte, limit), p.header()).want(t, http.StatusBadRequest, codeBadRequest)
	h.raw("POST", uri, []byte(`{"request":"eA"}`), p.header()).ok(t)
}

// A chunked upload declares no length, so only the reader-side limit can stop it.
func TestChunkedBodyLimit(t *testing.T) {
	h := newHarness(t)
	admin := h.bootstrap()
	s := admin.signer()
	body := make([]byte, maxJSONBody+1)
	uri := changesURI(vault1)
	ts := strconv.FormatInt(h.clock.now().UnixMilli(), 10)
	nonce := enc(randBytes(16))

	req, err := http.NewRequest("POST", h.web.URL+uri, io.MultiReader(bytes.NewReader(body)))
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range authHeaders(s, "POST", uri, ts, nonce, bodyDigest(body)) {
		req.Header.Set(k, v)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	data, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	(&response{status: res.StatusCode, body: data}).want(t, http.StatusRequestEntityTooLarge, codeTooLarge)
}

func TestQuota(t *testing.T) {
	h := newHarness(t, withQuota(100))
	admin := h.bootstrap()
	s := admin.signer()

	h.call(s, "PUT", blobURI(vault1, "a"), make([]byte, 60)).ok(t)
	h.call(s, "PUT", blobURI(vault1, "b"), make([]byte, 60)).want(t, http.StatusRequestEntityTooLarge, codeQuotaExceeded)
	h.call(s, "GET", blobURI(vault1, "b"), nil).want(t, http.StatusNotFound, codeNotFound)
	if files := blobFiles(t, h); len(files) != 1 {
		t.Fatalf("files = %d, want 1 (refused upload must leave nothing)", len(files))
	}

	// Overwriting counts the difference, not the sum.
	h.call(s, "PUT", blobURI(vault1, "a"), make([]byte, 90)).ok(t)

	body := map[string]any{"changes": []any{map[string]any{"id": "c", "gen": 1, "blob": enc(make([]byte, 20))}}}
	h.callJSON(s, "POST", changesURI(vault1), body).want(t, http.StatusRequestEntityTooLarge, codeQuotaExceeded)

	// A retry of a stored id costs nothing even when full.
	h.call(s, "PUT", blobURI(vault1, "a"), make([]byte, 80)).ok(t)
	h.callJSON(s, "POST", changesURI(vault1), body).ok(t)
	h.callJSON(s, "POST", changesURI(vault1), body).ok(t)

	// Deleting frees space, and the count survives a restart.
	h.call(s, "DELETE", blobURI(vault1, "a"), nil).ok(t)
	h.restart()
	h.call(s, "PUT", blobURI(vault1, "b"), make([]byte, 80)).ok(t)
	h.call(s, "PUT", blobURI(vault1, "c"), make([]byte, 1)).want(t, http.StatusRequestEntityTooLarge, codeQuotaExceeded)
}

func TestVaultDeleteFreesQuota(t *testing.T) {
	h := newHarness(t, withQuota(100))
	admin := h.bootstrap()
	h.addVault("v2")
	h.mustAppend(h.rootSigner(), func() ledger.Wire {
		return h.rootEntry(ledger.TypeGrant, map[string]any{"deviceId": admin.id, "role": "admin", "vaults": []string{vault1, "v2"}})
	})
	s := admin.signer()
	h.call(s, "PUT", blobURI(vault1, "a"), make([]byte, 90)).ok(t)
	h.mustAppend(h.rootSigner(), func() ledger.Wire {
		return h.rootEntry(ledger.TypeVaultDelete, map[string]any{"vaultId": vault1})
	})
	h.call(s, "PUT", blobURI("v2", "a"), make([]byte, 90)).ok(t)
}

func TestEmptyCollectionsAreArrays(t *testing.T) {
	h := newHarness(t)
	admin := h.bootstrap()
	s := admin.signer()
	cases := []struct {
		name, want string
		res        *response
	}{
		{"ledger increment", `"entries":[]`, h.call(s, "GET", "/v1/ledger?from="+itoa(h.head+1), nil)},
		{"changes", `"changes":[]`, h.call(s, "GET", changesURI(vault1), nil)},
		{"changes past head", `"changes":[]`, h.call(s, "GET", changesURI(vault1)+"?after=50", nil)},
		{"accepted", `"accepted":[]`, h.callJSON(s, "POST", changesURI(vault1), map[string]any{"changes": []any{}})},
		{"accepted without field", `"accepted":[]`, h.call(s, "POST", changesURI(vault1), []byte(`{}`))},
	}
	member := h.addDevice(ledger.RoleMember, vault1)
	cases = append(cases, struct {
		name, want string
		res        *response
	}{"keys", `"keys":[]`, h.call(member.signer(), "GET", keysURI(vault1), nil)})
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			c.res.ok(t)
			if !bytes.Contains(c.res.body, []byte(c.want)) {
				t.Fatalf("body = %s, want it to contain %s", c.res.body, c.want)
			}
			if bytes.Contains(c.res.body, []byte("null")) {
				t.Fatalf("body has null: %s", c.res.body)
			}
		})
	}
}

func TestCollectionsOfOneAndMany(t *testing.T) {
	h := newHarness(t)
	admin := h.bootstrap()
	s := admin.signer()

	res := h.call(s, "GET", "/v1/ledger?from="+itoa(h.head), nil)
	res.ok(t)
	if n := len(res.list(t, "entries")); n != 1 {
		t.Fatalf("one ledger entry: got %d", n)
	}
	res = h.call(s, "GET", "/v1/ledger", nil)
	res.ok(t)
	if n := int64(len(res.list(t, "entries"))); n != h.head+1 {
		t.Fatalf("many ledger entries: got %d", n)
	}
	h.pushChanges(admin, vault1, 1, "only").ok(t)
	res = h.call(s, "GET", changesURI(vault1), nil)
	res.ok(t)
	if n := len(res.list(t, "changes")); n != 1 {
		t.Fatalf("one change: got %d", n)
	}
	h.pushChanges(admin, vault1, 1, "b", "c").ok(t)
	res = h.call(s, "GET", changesURI(vault1), nil)
	res.ok(t)
	if n := len(res.list(t, "changes")); n != 3 {
		t.Fatalf("many changes: got %d", n)
	}
}

func TestPostLedgerEmptyBatchIsNoOp(t *testing.T) {
	h := newHarness(t)
	admin := h.bootstrap()
	res := h.postEntries(admin.signer())
	res.ok(t)
	if got := res.number(t, "head"); got != h.head {
		t.Fatalf("head = %d, want %d", got, h.head)
	}
}

func TestAnonymousRateLimit(t *testing.T) {
	h := newHarness(t, withRate(0.001, 3))
	for i := 0; i < 3; i++ {
		h.raw("GET", "/v1/info", nil, nil).ok(t)
	}
	h.raw("GET", "/v1/info", nil, nil).want(t, http.StatusTooManyRequests, codeRateLimited)
	h.raw("POST", "/v1/bootstrap", []byte("{}"), nil).want(t, http.StatusTooManyRequests, codeRateLimited)
	h.raw("GET", "/v1/pair/abc", nil, nil).want(t, http.StatusTooManyRequests, codeRateLimited)
	h.raw("POST", "/v1/pair/abc/request", []byte("{}"), nil).want(t, http.StatusTooManyRequests, codeRateLimited)
	h.raw("GET", "/healthz", nil, nil).ok(t) // not rate-limited

	// The bucket refills.
	h.clock.advance(time.Hour)
	h.raw("GET", "/v1/info", nil, nil).ok(t)
}

func TestAuthFailuresCountTowardRateLimit(t *testing.T) {
	h := newHarness(t, withRate(0.001, 3))
	h.bootstrapDirect()
	stranger := newDevice(t)
	for i := 0; i < 3; i++ {
		h.call(stranger.signer(), "GET", "/v1/ledger", nil).want(t, http.StatusUnauthorized, codeUnauthorized)
	}
	h.call(stranger.signer(), "GET", "/v1/ledger", nil).want(t, http.StatusTooManyRequests, codeRateLimited)
}

func TestSuccessfulRequestsDoNotDrainBucket(t *testing.T) {
	h := newHarness(t, withRate(0.001, 3))
	admin := h.bootstrapDirect()
	for i := 0; i < 10; i++ {
		h.call(admin.signer(), "GET", "/v1/ledger", nil).ok(t)
	}
}

// bootstrapDirect bootstraps through the store, spending no rate-limit tokens.
func (h *harness) bootstrapDirect() *testDevice {
	h.t.Helper()
	admin := newDevice(h.t)
	var entries []*ledger.Entry
	push := func(typ string, data map[string]any) {
		w := h.rootEntry(typ, data)
		h.commit(w)
		e, err := ledger.Parse(w)
		if err != nil {
			h.t.Fatal(err)
		}
		entries = append(entries, e)
	}
	push(ledger.TypeGenesis, genesisData(h.root))
	push(ledger.TypeVaultAdd, vaultData(vault1))
	push(ledger.TypeDeviceAdd, deviceData(admin, ledger.RoleAdmin, vault1))
	if err := h.st.Bootstrap(entries, nil, h.clock.now().UnixMilli()); err != nil {
		h.t.Fatal(err)
	}
	return admin
}

func TestCFConnectingIP(t *testing.T) {
	t.Run("trusted", func(t *testing.T) {
		h := newHarness(t, withRate(0.001, 1), withTrustCF())
		ip := func(s string) map[string]string { return map[string]string{"CF-Connecting-IP": s} }
		h.raw("GET", "/v1/info", nil, ip("203.0.113.1")).ok(t)
		h.raw("GET", "/v1/info", nil, ip("203.0.113.1")).want(t, http.StatusTooManyRequests, codeRateLimited)
		h.raw("GET", "/v1/info", nil, ip("203.0.113.2")).ok(t)
		// Garbage falls back to the socket address.
		h.raw("GET", "/v1/info", nil, ip("not an ip")).ok(t)
		h.raw("GET", "/v1/info", nil, ip("also not an ip")).want(t, http.StatusTooManyRequests, codeRateLimited)
	})
	t.Run("untrusted header is ignored", func(t *testing.T) {
		h := newHarness(t, withRate(0.001, 1))
		h.raw("GET", "/v1/info", nil, map[string]string{"CF-Connecting-IP": "203.0.113.1"}).ok(t)
		h.raw("GET", "/v1/info", nil, map[string]string{"CF-Connecting-IP": "203.0.113.2"}).
			want(t, http.StatusTooManyRequests, codeRateLimited)
	})
}

func TestSecurityHeadersAndJSON404(t *testing.T) {
	h := newHarness(t)
	h.bootstrap()
	responses := map[string]*response{
		"ok":             h.raw("GET", "/healthz", nil, nil),
		"unknown path":   h.raw("GET", "/nope", nil, nil),
		"root path":      h.raw("GET", "/", nil, nil),
		"wrong method":   h.raw("DELETE", "/healthz", nil, nil),
		"unclean path":   h.raw("GET", "/v1//info", nil, nil),
		"trailing slash": h.raw("GET", "/v1/info/", nil, nil),
		"unauthorized":   h.raw("GET", "/v1/ledger", nil, nil),
	}
	for name, r := range responses {
		t.Run(name, func(t *testing.T) {
			if got := r.header.Get("X-Content-Type-Options"); got != "nosniff" {
				t.Fatalf("nosniff header = %q", got)
			}
			if got := r.header.Get("Cache-Control"); got != "no-store" {
				t.Fatalf("Cache-Control = %q", got)
			}
			if ct := r.header.Get("Content-Type"); ct != "application/json" {
				t.Fatalf("Content-Type = %q, body %q", ct, r.body)
			}
		})
	}
	for _, name := range []string{"unknown path", "root path", "wrong method", "unclean path", "trailing slash"} {
		responses[name].want(t, http.StatusNotFound, codeNotFound)
	}
}

func TestAudit(t *testing.T) {
	h := newHarness(t)
	admin := h.bootstrap()
	s := admin.signer()
	h.addDevice(ledger.RoleMember, vault1)
	h.openPair(admin, "ABC123")
	req := h.rotateBody(admin.id, admin.sign, vault1, 2, []map[string]any{wrapKey(admin.id, 2)}, "s1")
	h.callJSON(s, "POST", rotateURI(vault1), req).ok(t)
	h.commit(entryOf(req))

	res := h.call(s, "GET", "/v1/audit", nil)
	res.ok(t)
	actions := map[string]bool{}
	for _, raw := range res.list(t, "events") {
		e := raw.(map[string]any)
		if len(e) != 4 || e["ts"] == nil || e["device"] == "" {
			t.Fatalf("event = %v", e)
		}
		actions[e["action"].(string)] = true
	}
	for _, want := range []string{"bootstrap", "device_add", "vault_add", "pair_open", "vault_rotate"} {
		if !actions[want] {
			t.Fatalf("no %q in %v", want, actions)
		}
	}

	res = h.call(s, "GET", "/v1/audit?limit=1", nil)
	res.ok(t)
	events := res.list(t, "events")
	if len(events) != 1 || events[0].(map[string]any)["action"] != "vault_rotate" {
		t.Fatalf("newest event = %v", events)
	}
	if detail := events[0].(map[string]any)["detail"].(string); !strings.Contains(detail, vault1) {
		t.Fatalf("detail = %q", detail)
	}
}

func TestLogsCarryNoSecrets(t *testing.T) {
	var buf bytes.Buffer
	h := newHarness(t, withLogger(log.New(&buf, "", 0)))
	admin := h.bootstrap()
	const vault = "vault-secret-id"
	h.addVault(vault)
	h.mustAppend(h.rootSigner(), func() ledger.Wire {
		return h.rootEntry(ledger.TypeGrant, map[string]any{"deviceId": admin.id, "role": "admin", "vaults": []string{vault1, vault}})
	})
	p := h.openPair(admin, "PAIR-SECRET")
	h.raw("GET", "/v1/pair/PAIR-SECRET", nil, p.header()).ok(t)
	h.raw("GET", "/v1/pair/PAIR-SECRET", nil, map[string]string{hdrPairToken: "wrong-token-value"}).want(t, http.StatusUnauthorized, codeUnauthorized)
	h.call(admin.signer(), "PUT", blobURI(vault, "blob-secret-id"), []byte("attachment-secret")).ok(t)
	h.call(admin.signer(), "GET", changesURI(vault)+"?after=7", nil).ok(t)

	logged := buf.String()
	for _, secret := range []string{vault, "PAIR-SECRET", "blob-secret-id", "attachment-secret", p.token, "wrong-token-value", testToken, admin.id, "after=7"} {
		if strings.Contains(logged, secret) {
			t.Fatalf("log contains %q:\n%s", secret, logged)
		}
	}
	for _, want := range []string{"GET /v1/vaults/{id}/changes 200 ", "PUT /v1/vaults/{id}/blobs/{blobId} 200 ", "GET /v1/pair/{id} 401 "} {
		if !strings.Contains(logged, want) {
			t.Fatalf("log lacks %q:\n%s", want, logged)
		}
	}
}

func TestPanicBecomesJSON500(t *testing.T) {
	h := newHarness(t)
	h.srv.mux.HandleFunc("GET /boom", func(http.ResponseWriter, *http.Request) { panic("secret detail") })
	res := h.raw("GET", "/boom", nil, nil)
	res.want(t, http.StatusInternalServerError, codeInternal)
	if bytes.Contains(res.body, []byte("secret")) {
		t.Fatalf("panic text leaked: %s", res.body)
	}
}

// The client depends on these exact strings. Every other test refers to the
// constants, so a typo in a constant would pass them all.
func TestWireNames(t *testing.T) {
	names := map[string]string{
		codeBadRequest:     "bad_request",
		codeUnauthorized:   "unauthorized",
		codeForbidden:      "forbidden",
		codeNotFound:       "not_found",
		codeLedgerConflict: "ledger_conflict",
		codeLedgerInvalid:  "ledger_invalid",
		codeStaleGen:       "stale_gen",
		codeStaleSnapshot:  "stale_snapshot",
		codeGone:           "gone",
		codeTooLarge:       "too_large",
		codeRateLimited:    "rate_limited",
		codeQuotaExceeded:  "quota_exceeded",
		codePairUsed:       "pair_used",
		codePairExpired:    "pair_expired",
		codeInternal:       "internal",
		hdrDevice:          "X-Mx-Device",
		hdrTs:              "X-Mx-Ts",
		hdrNonce:           "X-Mx-Nonce",
		hdrSig:             "X-Mx-Sig",
		hdrBody:            "X-Mx-Body",
		hdrPairToken:       "X-Mx-Pair-Token",
	}
	for got, want := range names {
		if got != want {
			t.Fatalf("wire name %q, want %q", got, want)
		}
	}
}
