package api

import (
	"bytes"
	"net/http"
	"strings"
	"sync"
	"testing"

	"mixia/server/internal/ledger"
)

func TestVaultAccessControl(t *testing.T) {
	h := newHarness(t)
	admin := h.bootstrap()
	h.call(admin.signer(), "PUT", blobURI(vault1, "b"), []byte("x")).ok(t)

	outsiders := map[string]*testDevice{
		"member outside the vault": h.addDevice(ledger.RoleMember),
		"admin outside the vault":  h.addDevice(ledger.RoleAdmin),
	}
	requests := []struct {
		method, uri string
		body        []byte
	}{
		{"GET", changesURI(vault1), nil},
		{"POST", changesURI(vault1), mustJSON(map[string]any{"changes": []any{change("x", 1)}})},
		{"GET", keysURI(vault1), nil},
		{"PUT", keysURI(vault1), mustJSON(map[string]any{"keys": []any{wrapKey(admin.id, 1)}})},
		{"POST", rotateURI(vault1), []byte("{}")},
		{"PUT", blobURI(vault1, "b"), []byte("y")},
		{"GET", blobURI(vault1, "b"), nil},
		{"DELETE", blobURI(vault1, "b"), nil},
	}
	for name, d := range outsiders {
		for _, r := range requests {
			t.Run(name+"/"+r.method+" "+r.uri, func(t *testing.T) {
				h.call(d.signer(), r.method, r.uri, r.body).want(t, http.StatusForbidden, codeForbidden)
			})
		}
	}

	// A member inside the vault reads and writes, but `adm` routes still refuse it.
	member := h.addDevice(ledger.RoleMember, vault1)
	h.call(member.signer(), "GET", changesURI(vault1), nil).ok(t)
	h.call(member.signer(), "GET", blobURI(vault1, "b"), nil).ok(t)
	h.pushChanges(member, vault1, 1, "m").ok(t)
	h.callJSON(member.signer(), "PUT", keysURI(vault1), map[string]any{"keys": []any{}}).want(t, http.StatusForbidden, codeForbidden)
}

func TestKeysReturnsOnlyOwnWrap(t *testing.T) {
	h := newHarness(t)
	admin := h.bootstrap()
	member := h.addDevice(ledger.RoleMember, vault1)
	wrap := wrapKey(member.id, 1)
	h.callJSON(admin.signer(), "PUT", keysURI(vault1), map[string]any{"keys": []any{wrap}}).ok(t)

	res := h.call(member.signer(), "GET", keysURI(vault1), nil)
	res.ok(t)
	keys := res.list(t, "keys")
	if len(keys) != 1 {
		t.Fatalf("keys = %d, want 1", len(keys))
	}
	k := keys[0].(map[string]any)
	if k["wrapped"] != wrap["wrapped"] || k["gen"] != float64(1) || len(k) != 2 {
		t.Fatalf("key = %v", k)
	}
}

func TestPutKeysRules(t *testing.T) {
	h := newHarness(t)
	admin := h.bootstrap()
	member := h.addDevice(ledger.RoleMember, vault1)
	s := admin.signer()
	put := func(k map[string]any) *response {
		return h.callJSON(s, "PUT", keysURI(vault1), map[string]any{"keys": []any{k}})
	}

	put(wrapKey(member.id, 1)).ok(t)
	put(wrapKey(ledger.Recovery, 1)).ok(t)
	put(wrapKey(member.id, 1)).ok(t) // upsert

	put(wrapKey(member.id, 2)).want(t, http.StatusConflict, codeStaleGen)
	put(wrapKey(member.id, 0)).want(t, http.StatusConflict, codeStaleGen)
	put(wrapKey(newDevice(t).id, 1)).want(t, http.StatusBadRequest, codeBadRequest)
	put(map[string]any{"deviceId": member.id, "gen": 1, "wrapped": ""}).want(t, http.StatusBadRequest, codeBadRequest)
	put(map[string]any{"deviceId": member.id, "gen": 1, "wrapped": "not base64!"}).want(t, http.StatusBadRequest, codeBadRequest)

	h.revoke(member)
	put(wrapKey(member.id, 1)).want(t, http.StatusBadRequest, codeBadRequest)

	h.callJSON(h.rootSigner(), "PUT", keysURI(vault1), map[string]any{"keys": []any{wrapKey(ledger.Recovery, 1)}}).ok(t)
}

func TestChangesIdempotent(t *testing.T) {
	h := newHarness(t)
	admin := h.bootstrap()

	res := h.pushChanges(admin, vault1, 1, "a", "b", "c")
	res.ok(t)
	accepted := res.list(t, "accepted")
	for i, want := range []string{"a", "b", "c"} {
		a := accepted[i].(map[string]any)
		if a["id"] != want || a["seq"] != float64(i+1) {
			t.Fatalf("accepted[%d] = %v", i, a)
		}
	}
	if head := res.number(t, "head"); head != 3 {
		t.Fatalf("head = %d, want 3", head)
	}

	// Mixed retry: b is known and keeps seq 2, d is new.
	res = h.pushChanges(admin, vault1, 1, "b", "d")
	res.ok(t)
	accepted = res.list(t, "accepted")
	if a := accepted[0].(map[string]any); a["seq"] != float64(2) {
		t.Fatalf("retried id got seq %v, want 2", a["seq"])
	}
	if a := accepted[1].(map[string]any); a["seq"] != float64(4) {
		t.Fatalf("new id got seq %v, want 4", a["seq"])
	}

	// The same id twice in one batch is written once.
	res = h.pushChanges(admin, vault1, 1, "e", "e")
	res.ok(t)
	accepted = res.list(t, "accepted")
	if accepted[0].(map[string]any)["seq"] != accepted[1].(map[string]any)["seq"] {
		t.Fatalf("duplicate within batch got two seqs: %v", accepted)
	}

	page := h.call(admin.signer(), "GET", changesURI(vault1), nil)
	page.ok(t)
	if n := len(page.list(t, "changes")); n != 5 {
		t.Fatalf("stored changes = %d, want 5", n)
	}
}

func TestChangeIdsAreScopedPerVault(t *testing.T) {
	h := newHarness(t)
	admin := h.bootstrap()
	h.addVault("v2")
	h.mustAppend(h.rootSigner(), func() ledger.Wire {
		return h.rootEntry(ledger.TypeGrant, map[string]any{"deviceId": admin.id, "role": "admin", "vaults": []string{vault1, "v2"}})
	})
	h.pushChanges(admin, vault1, 1, "same").ok(t)
	res := h.pushChanges(admin, "v2", 1, "same")
	res.ok(t)
	if a := res.list(t, "accepted")[0].(map[string]any); a["seq"] != float64(1) {
		t.Fatalf("seq in second vault = %v, want 1", a["seq"])
	}
}

func TestChangeDeviceIsAuthenticatedDevice(t *testing.T) {
	h := newHarness(t)
	admin := h.bootstrap()
	// A client-supplied device field must be ignored.
	body := map[string]any{"changes": []any{map[string]any{"id": "a", "gen": 1, "blob": enc([]byte("x")), "device": "forged"}}}
	h.callJSON(admin.signer(), "POST", changesURI(vault1), body).ok(t)

	res := h.call(admin.signer(), "GET", changesURI(vault1), nil)
	res.ok(t)
	c := res.list(t, "changes")[0].(map[string]any)
	if c["device"] != admin.id || c["seq"] != float64(1) || c["id"] != "a" || c["gen"] != float64(1) || c["blob"] != enc([]byte("x")) {
		t.Fatalf("change = %v", c)
	}
}

func TestStaleGen(t *testing.T) {
	h := newHarness(t)
	admin := h.bootstrap()
	h.pushChanges(admin, vault1, 2, "a").want(t, http.StatusConflict, codeStaleGen)

	// A batch with one stale change writes nothing.
	body := map[string]any{"changes": []any{change("b", 1), change("c", 9)}}
	h.callJSON(admin.signer(), "POST", changesURI(vault1), body).want(t, http.StatusConflict, codeStaleGen)
	res := h.call(admin.signer(), "GET", changesURI(vault1), nil)
	res.ok(t)
	if n := len(res.list(t, "changes")); n != 0 {
		t.Fatalf("stale batch stored %d changes", n)
	}
}

func TestChangeValidation(t *testing.T) {
	h := newHarness(t)
	admin := h.bootstrap()
	uri := changesURI(vault1)
	bad := []map[string]any{
		{"id": "", "gen": 1, "blob": enc([]byte("x"))},
		{"id": "../x", "gen": 1, "blob": enc([]byte("x"))},
		{"id": "a", "gen": 1, "blob": ""},
		{"id": "a", "gen": 1, "blob": "@@@"},
		{"id": "a", "gen": 1, "blob": enc([]byte("x")) + "="},
	}
	for _, c := range bad {
		h.callJSON(admin.signer(), "POST", uri, map[string]any{"changes": []any{c}}).want(t, http.StatusBadRequest, codeBadRequest)
	}
	h.call(admin.signer(), "POST", uri, []byte("{")).want(t, http.StatusBadRequest, codeBadRequest)
}

func TestBaseHeadSemantics(t *testing.T) {
	h := newHarness(t)
	admin := h.bootstrap()
	s := admin.signer()

	res := h.call(s, "GET", changesURI(vault1), nil)
	res.ok(t)
	if head, base, gen := res.number(t, "head"), res.number(t, "base"), res.number(t, "gen"); head != 0 || base != 1 || gen != 1 {
		t.Fatalf("empty vault: head=%d base=%d gen=%d, want 0 1 1", head, base, gen)
	}
	h.pushChanges(admin, vault1, 1, "a", "b", "c").ok(t)

	res = h.call(s, "GET", changesURI(vault1)+"?after=1", nil)
	res.ok(t)
	if head, base := res.number(t, "head"), res.number(t, "base"); head != 3 || base != 1 {
		t.Fatalf("head=%d base=%d, want 3 1", head, base)
	}
	if n := len(res.list(t, "changes")); n != 2 {
		t.Fatalf("after=1 returned %d, want 2", n)
	}

	// Past the head: an empty page, not an error.
	res = h.call(s, "GET", changesURI(vault1)+"?after=99", nil)
	res.ok(t)
	if n := len(res.list(t, "changes")); n != 0 {
		t.Fatalf("after=99 returned %d", n)
	}
}

func TestChangesLimitAndPaging(t *testing.T) {
	h := newHarness(t)
	admin := h.bootstrap()
	s := admin.signer()
	ids := make([]string, 1005)
	for i := range ids {
		ids[i] = "c" + itoa(int64(i))
	}
	h.pushChanges(admin, vault1, 1, ids...).ok(t)

	res := h.call(s, "GET", changesURI(vault1), nil)
	res.ok(t)
	if n := len(res.list(t, "changes")); n != 500 {
		t.Fatalf("default limit returned %d, want 500", n)
	}
	res = h.call(s, "GET", changesURI(vault1)+"?limit=5000", nil)
	res.ok(t)
	if n := len(res.list(t, "changes")); n != 1000 {
		t.Fatalf("limit=5000 returned %d, want the cap of 1000", n)
	}

	// Walking pages sees every seq exactly once.
	var after, total int64
	for {
		res = h.call(s, "GET", changesURI(vault1)+"?limit=300&after="+itoa(after), nil)
		res.ok(t)
		page := res.list(t, "changes")
		if len(page) == 0 {
			break
		}
		for _, c := range page {
			seq := int64(c.(map[string]any)["seq"].(float64))
			if seq != after+1 {
				t.Fatalf("seq %d after %d", seq, after)
			}
			after = seq
			total++
		}
	}
	if total != 1005 {
		t.Fatalf("walked %d changes, want 1005", total)
	}

	h.call(s, "GET", changesURI(vault1)+"?limit=0", nil).want(t, http.StatusBadRequest, codeBadRequest)
	h.call(s, "GET", changesURI(vault1)+"?limit=x", nil).want(t, http.StatusBadRequest, codeBadRequest)
	h.call(s, "GET", changesURI(vault1)+"?after=x", nil).want(t, http.StatusBadRequest, codeBadRequest)
}

func TestConcurrentChangesGetDistinctSeqs(t *testing.T) {
	h := newHarness(t)
	admin := h.bootstrap()
	var wg sync.WaitGroup
	seqs := make([]int64, 20)
	for i := range seqs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res := h.pushChanges(admin, vault1, 1, "c"+itoa(int64(i)))
			if res.status == http.StatusOK {
				seqs[i] = res.number(t, "head")
			}
		}()
	}
	wg.Wait()
	seen := map[int64]bool{}
	for _, s := range seqs {
		if s < 1 || s > 20 || seen[s] {
			t.Fatalf("seqs = %v", seqs)
		}
		seen[s] = true
	}
}

// rotateFixture has a vault with three changes and two key wraps.
func rotateFixture(t *testing.T) (*harness, *testDevice, *testDevice) {
	h := newHarness(t)
	admin := h.bootstrap()
	member := h.addDevice(ledger.RoleMember, vault1)
	h.callJSON(admin.signer(), "PUT", keysURI(vault1), map[string]any{"keys": []any{wrapKey(member.id, 1)}}).ok(t)
	h.pushChanges(admin, vault1, 1, "a", "b", "c").ok(t)
	return h, admin, member
}

func TestRotate(t *testing.T) {
	h, admin, member := rotateFixture(t)
	s := admin.signer()
	newKeys := []map[string]any{wrapKey(admin.id, 2), wrapKey(ledger.Recovery, 2)}
	req := h.rotateBody(admin.id, admin.sign, vault1, 2, newKeys, "s1", "s2")
	h.callJSON(s, "POST", rotateURI(vault1), req).ok(t)
	h.commit(entryOf(req))

	res := h.call(s, "GET", changesURI(vault1), nil)
	res.ok(t)
	if head, base, gen := res.number(t, "head"), res.number(t, "base"), res.number(t, "gen"); head != 5 || base != 4 || gen != 2 {
		t.Fatalf("head=%d base=%d gen=%d, want 5 4 2", head, base, gen)
	}
	list := res.list(t, "changes")
	if len(list) != 2 {
		t.Fatalf("snapshot size = %d, want 2", len(list))
	}
	first := list[0].(map[string]any)
	if first["id"] != "s1" || first["seq"] != float64(4) || first["device"] != admin.id || first["gen"] != float64(2) {
		t.Fatalf("snapshot change = %v", first)
	}

	// An after below base is clamped to base.
	res = h.call(s, "GET", changesURI(vault1)+"?after=1", nil)
	res.ok(t)
	if n := len(res.list(t, "changes")); n != 2 {
		t.Fatalf("after<base returned %d, want 2", n)
	}

	// Old wraps are gone; the member holds only the new generation.
	res = h.call(member.signer(), "GET", keysURI(vault1), nil)
	res.ok(t)
	memberKeys := res.list(t, "keys")
	if len(memberKeys) != 1 || memberKeys[0].(map[string]any)["gen"] != float64(2) {
		t.Fatalf("member wraps after rotate = %v", memberKeys)
	}
	res = h.call(s, "GET", keysURI(vault1), nil)
	res.ok(t)
	keys := res.list(t, "keys")
	if len(keys) != 1 || keys[0].(map[string]any)["gen"] != float64(2) {
		t.Fatalf("admin keys = %v", keys)
	}
	res = h.call(h.rootSigner(), "GET", keysURI(vault1), nil)
	res.ok(t)
	if keys := res.list(t, "keys"); len(keys) != 1 || keys[0].(map[string]any)["gen"] != float64(2) {
		t.Fatalf("recovery keys = %v", keys)
	}

	// The old generation is closed; the new one continues the seq line.
	h.pushChanges(admin, vault1, 1, "late").want(t, http.StatusConflict, codeStaleGen)
	res = h.pushChanges(admin, vault1, 2, "d")
	res.ok(t)
	if head := res.number(t, "head"); head != 6 {
		t.Fatalf("head = %d, want 6", head)
	}
}

func TestRotateEmptySnapshot(t *testing.T) {
	h, admin, _ := rotateFixture(t)
	req := h.rotateBody(admin.id, admin.sign, vault1, 2, []map[string]any{})
	h.callJSON(admin.signer(), "POST", rotateURI(vault1), req).ok(t)
	h.commit(entryOf(req))

	res := h.call(admin.signer(), "GET", changesURI(vault1), nil)
	res.ok(t)
	if head, base := res.number(t, "head"), res.number(t, "base"); head != 3 || base != 4 {
		t.Fatalf("head=%d base=%d, want 3 4", head, base)
	}
	if n := len(res.list(t, "changes")); n != 0 {
		t.Fatalf("changes = %d", n)
	}
}

func TestRotateByRootRecordsRootAsDevice(t *testing.T) {
	h, _, _ := rotateFixture(t)
	req := h.rotateBody(ledger.Root, h.root, vault1, 2, []map[string]any{wrapKey(ledger.Recovery, 2)}, "s1")
	h.callJSON(h.rootSigner(), "POST", rotateURI(vault1), req).ok(t)
	h.commit(entryOf(req))

	res := h.call(h.rootSigner(), "GET", changesURI(vault1), nil)
	res.ok(t)
	if d := res.list(t, "changes")[0].(map[string]any)["device"]; d != ledger.Root {
		t.Fatalf("snapshot device = %v, want root", d)
	}
}

// snapshotOf captures everything rotate could touch.
func snapshotOf(t *testing.T, h *harness, admin, member *testDevice) string {
	t.Helper()
	var b strings.Builder
	for _, r := range []*response{
		h.call(admin.signer(), "GET", "/v1/ledger", nil),
		h.call(admin.signer(), "GET", changesURI(vault1), nil),
		h.call(admin.signer(), "GET", keysURI(vault1), nil),
		h.call(member.signer(), "GET", keysURI(vault1), nil),
		h.call(h.rootSigner(), "GET", keysURI(vault1), nil),
	} {
		r.ok(t)
		b.Write(r.body)
		b.WriteByte('\n')
	}
	return b.String()
}

func TestRotateIsAtomic(t *testing.T) {
	h, admin, member := rotateFixture(t)
	s := admin.signer()
	h.addVault("v2")
	before := snapshotOf(t, h, admin, member)
	keys := []map[string]any{wrapKey(admin.id, 2)}

	wrongCount := h.rotateBody(admin.id, admin.sign, vault1, 2, keys, "s1", "s2")
	wrongCount["changes"] = wrongCount["changes"].([]map[string]any)[:1]

	keyWrongGen := h.rotateBody(admin.id, admin.sign, vault1, 2, []map[string]any{wrapKey(admin.id, 1)}, "s1")
	keyUnknownDevice := h.rotateBody(admin.id, admin.sign, vault1, 2, []map[string]any{wrapKey(newDevice(t).id, 2)}, "s1")

	changeWrongGen := h.rotateBody(admin.id, admin.sign, vault1, 2, keys, "s1")
	changeWrongGen["changes"].([]map[string]any)[0]["gen"] = 1

	duplicateIDs := h.rotateBody(admin.id, admin.sign, vault1, 2, keys, "s1", "s1")

	genJump := h.rotateBody(admin.id, admin.sign, vault1, 3, keys, "s1")
	// Valid entries that must not ride in through this route: one would delete
	// the vault, the other would rotate a vault the URL does not name.
	deleteEntry := map[string]any{
		"entry": h.rootEntry(ledger.TypeVaultDelete, map[string]any{"vaultId": vault1}),
		"keys":  []any{}, "changes": []any{},
	}
	otherVault := h.rotateBody(admin.id, admin.sign, "v2", 2, keys)
	seqGap := map[string]any{
		"entry": makeEntry(h.head+5, h.prev, admin.id, admin.sign, ledger.TypeVaultRotate, map[string]any{
			"vaultId": vault1, "gen": 2, "keyCommit": "k", "snapshotCount": 0, "snapshotHash": "h",
		}),
		"keys": keys, "changes": []any{},
	}

	cases := []struct {
		name   string
		body   any
		status int
		code   string
	}{
		{"snapshot count mismatch", wrongCount, 400, codeBadRequest},
		{"key with old gen", keyWrongGen, 400, codeBadRequest},
		{"key for unknown device", keyUnknownDevice, 400, codeBadRequest},
		{"change with old gen", changeWrongGen, 400, codeBadRequest},
		{"duplicate snapshot ids", duplicateIDs, 400, codeBadRequest},
		{"gen jump", genJump, 400, codeLedgerInvalid},
		{"entry is not vault_rotate", deleteEntry, 400, codeLedgerInvalid},
		{"entry for another vault", otherVault, 400, codeLedgerInvalid},
		{"seq conflict", seqGap, 409, codeLedgerConflict},
		{"no entry", map[string]any{"keys": keys}, 400, codeBadRequest},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h.callJSON(s, "POST", rotateURI(vault1), c.body).want(t, c.status, c.code)
			if after := snapshotOf(t, h, admin, member); after != before {
				t.Fatalf("state changed:\nbefore %s\nafter  %s", before, after)
			}
		})
	}
}

func TestRotateRefusesNonAdminSigner(t *testing.T) {
	h, admin, member := rotateFixture(t)
	req := h.rotateBody(member.id, member.sign, vault1, 2, []map[string]any{wrapKey(admin.id, 2)})
	h.callJSON(admin.signer(), "POST", rotateURI(vault1), req).want(t, http.StatusBadRequest, codeLedgerInvalid)
}

func TestRotateMissingVault(t *testing.T) {
	h := newHarness(t)
	h.bootstrap()
	req := h.rotateBody(ledger.Root, h.root, "missing", 2, []map[string]any{})
	h.callJSON(h.rootSigner(), "POST", rotateURI("missing"), req).want(t, http.StatusNotFound, codeNotFound)
}

func TestRotateFreesQuota(t *testing.T) {
	h := newHarness(t, withQuota(100))
	admin := h.bootstrap()
	big := enc(bytes.Repeat([]byte("x"), 90))
	h.callJSON(admin.signer(), "POST", changesURI(vault1), map[string]any{
		"changes": []any{map[string]any{"id": "a", "gen": 1, "blob": big}},
	}).ok(t)

	// 90 old + 90 new would exceed 100, but the old log is replaced.
	req := h.rotateBodyBlobs(admin.id, admin.sign, vault1, 2, nil, []string{"s1"}, [][]byte{bytes.Repeat([]byte("x"), 90)})
	h.callJSON(admin.signer(), "POST", rotateURI(vault1), req).ok(t)
}

func TestRotateOverQuota(t *testing.T) {
	h := newHarness(t, withQuota(50))
	admin := h.bootstrap()
	req := h.rotateBodyBlobs(admin.id, admin.sign, vault1, 2, nil, []string{"s1"}, [][]byte{bytes.Repeat([]byte("x"), 60)})
	h.callJSON(admin.signer(), "POST", rotateURI(vault1), req).want(t, http.StatusRequestEntityTooLarge, codeQuotaExceeded)
	if gen := h.st.State().Vaults[vault1].Gen; gen != 1 {
		t.Fatalf("gen = %d after refused rotate", gen)
	}
}

// 旧日志删除后无法找回，所以服务端在动手前核对快照和封装。
func TestRotateRefusesBadSnapshotOrIncompleteWraps(t *testing.T) {
	h, admin, member := rotateFixture(t)
	without := func(req map[string]any, id string) map[string]any {
		var kept []map[string]any
		for _, k := range req["keys"].([]map[string]any) {
			if k["deviceId"] != id {
				kept = append(kept, k)
			}
		}
		req["keys"] = kept
		return req
	}
	tampered := h.rotateBody(admin.id, admin.sign, vault1, 2, nil, "s1")
	tampered["changes"].([]map[string]any)[0]["blob"] = enc([]byte("other-bytes"))
	cases := map[string]map[string]any{
		"snapshot hash mismatch": tampered,
		"recovery wrap missing":  without(h.rotateBody(admin.id, admin.sign, vault1, 2, nil, "s1"), ledger.Recovery),
		"device wrap missing":    without(h.rotateBody(admin.id, admin.sign, vault1, 2, nil, "s1"), member.id),
	}
	for name, req := range cases {
		t.Run(name, func(t *testing.T) {
			res := h.callJSON(admin.signer(), "POST", rotateURI(vault1), req)
			if res.status != 400 {
				t.Fatalf("status = %d, want 400", res.status)
			}
		})
	}
}

// H2: a change the server acknowledged after the client took its snapshot is in
// neither the snapshot nor, once the log is dropped, anywhere else.
func TestRotateRefusesStaleSnapshot(t *testing.T) {
	h, admin, member := rotateFixture(t)
	req := h.rotateBody(admin.id, admin.sign, vault1, 2, nil, "s1") // logHead 3

	h.pushChanges(member, vault1, 1, "acknowledged").ok(t)
	before := snapshotOf(t, h, admin, member)

	res := h.callJSON(admin.signer(), "POST", rotateURI(vault1), req)
	res.want(t, http.StatusConflict, codeStaleSnapshot)
	if head := res.number(t, "head"); head != 4 {
		t.Fatalf("head = %d, want 4", head)
	}
	if after := snapshotOf(t, h, admin, member); after != before {
		t.Fatalf("stale rotate changed state:\nbefore %s\nafter  %s", before, after)
	}

	// The change is still there, and a snapshot taken at the new head goes through.
	req = h.rotateBody(admin.id, admin.sign, vault1, 2, nil, "s1", "s2")
	h.callJSON(admin.signer(), "POST", rotateURI(vault1), req).ok(t)
	h.commit(entryOf(req))
}

func TestRotateRefusesLogHeadAheadOfServer(t *testing.T) {
	h, admin, _ := rotateFixture(t)
	h.tweakRotate = func(data map[string]any) { data["logHead"] = 99 }
	req := h.rotateBody(admin.id, admin.sign, vault1, 2, nil, "s1")
	res := h.callJSON(admin.signer(), "POST", rotateURI(vault1), req)
	res.want(t, http.StatusConflict, codeStaleSnapshot)
	if head := res.number(t, "head"); head != 3 {
		t.Fatalf("head = %d, want 3", head)
	}
}

func TestRotateLogHeadOfEmptyVaultIsZero(t *testing.T) {
	h := newHarness(t)
	admin := h.bootstrap()
	req := h.rotateBody(admin.id, admin.sign, vault1, 2, nil)
	if got := h.vaultHead(vault1); got != 0 {
		t.Fatalf("head = %d", got)
	}
	h.callJSON(admin.signer(), "POST", rotateURI(vault1), req).ok(t)
}

func TestRotateEntryFieldsRefused(t *testing.T) {
	h, admin, _ := rotateFixture(t)
	cases := map[string]func(map[string]any){
		"logHead missing":  func(d map[string]any) { delete(d, "logHead") },
		"logHead null":     func(d map[string]any) { d["logHead"] = nil },
		"logHead negative": func(d map[string]any) { d["logHead"] = -1 },
		"logHead fraction": func(d map[string]any) { d["logHead"] = 1.5 },
		"logHead string":   func(d map[string]any) { d["logHead"] = "3" },
		"keyCommit gone":   func(d map[string]any) { delete(d, "keyCommit") },
		"hash gone":        func(d map[string]any) { delete(d, "snapshotHash") },
	}
	for name, value := range badHash32() {
		cases["keyCommit "+name] = func(d map[string]any) { d["keyCommit"] = value }
		cases["snapshotHash "+name] = func(d map[string]any) { d["snapshotHash"] = value }
	}
	for name, tweak := range cases {
		t.Run(name, func(t *testing.T) {
			h.tweakRotate = tweak
			req := h.rotateBody(admin.id, admin.sign, vault1, 2, nil, "s1")
			h.tweakRotate = nil
			h.callJSON(admin.signer(), "POST", rotateURI(vault1), req).want(t, http.StatusBadRequest, codeLedgerInvalid)
		})
	}
}

// Clients hash an empty snapshot as well, so count=0 gets no pass.
func TestRotateEmptySnapshotStillNeedsItsHash(t *testing.T) {
	h, admin, _ := rotateFixture(t)
	h.tweakRotate = func(d map[string]any) { d["snapshotHash"] = "" }
	req := h.rotateBody(admin.id, admin.sign, vault1, 2, nil)
	h.tweakRotate = nil
	h.callJSON(admin.signer(), "POST", rotateURI(vault1), req).want(t, http.StatusBadRequest, codeLedgerInvalid)
}

// Wraps cover who can read the vault, not everyone on the ledger.
func TestRotateWrapsNeedNotCoverDevicesOutsideTheVault(t *testing.T) {
	h, admin, _ := rotateFixture(t)
	h.addDevice(ledger.RoleMember) // active, but no access to vault1
	req := h.rotateBody(admin.id, admin.sign, vault1, 2, nil, "s1")
	h.callJSON(admin.signer(), "POST", rotateURI(vault1), req).ok(t)
}
