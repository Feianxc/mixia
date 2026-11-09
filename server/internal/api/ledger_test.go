package api

import (
	"crypto/ed25519"
	"crypto/sha256"
	"net/http"
	"testing"

	"mixia/server/internal/edtest"
	"mixia/server/internal/ledger"
)

// ledgerFixture is a bootstrapped server with a second admin and a member, so
// that rule 5's "last admin" cases can be set up on demand.
type ledgerFixture struct {
	*harness
	admin  *testDevice
	member *testDevice
}

func newLedgerFixture(t *testing.T) *ledgerFixture {
	h := newHarness(t)
	admin := h.bootstrap()
	return &ledgerFixture{harness: h, admin: admin, member: h.addDevice(ledger.RoleMember, vault1)}
}

func (f *ledgerFixture) refused(t *testing.T, w ledger.Wire) {
	t.Helper()
	before := f.ledgerHead(f.admin.signer())
	f.postEntries(f.admin.signer(), w).want(t, http.StatusBadRequest, codeLedgerInvalid)
	if after := f.ledgerHead(f.admin.signer()); after != before {
		t.Fatalf("head moved from %d to %d on a refused entry", before, after)
	}
}

func TestLedgerSeqConflict(t *testing.T) {
	f := newLedgerFixture(t)
	admin := f.admin.signer()

	t.Run("gap", func(t *testing.T) {
		w := makeEntry(f.head+2, f.prev, ledger.Root, f.root, ledger.TypeVaultAdd, vaultData("x"))
		res := f.postEntries(admin, w)
		res.want(t, http.StatusConflict, codeLedgerConflict)
		if got := res.number(t, "head"); got != f.head {
			t.Fatalf("conflict head = %d, want %d", got, f.head)
		}
	})
	t.Run("already taken", func(t *testing.T) {
		w := makeEntry(f.head, f.prev, ledger.Root, f.root, ledger.TypeVaultAdd, vaultData("x"))
		f.postEntries(admin, w).want(t, http.StatusConflict, codeLedgerConflict)
	})
	t.Run("gap inside a batch reports the committed head", func(t *testing.T) {
		first := f.rootEntry(ledger.TypeVaultAdd, vaultData("x"))
		sum := sha256.Sum256(first.Body)
		second := makeEntry(f.head+3, enc(sum[:]), ledger.Root, f.root, ledger.TypeVaultAdd, vaultData("y"))
		res := f.postEntries(admin, first, second)
		res.want(t, http.StatusConflict, codeLedgerConflict)
		if got := res.number(t, "head"); got != f.head {
			t.Fatalf("conflict head = %d, want %d", got, f.head)
		}
		if _, ok := f.st.State().Vaults["x"]; ok {
			t.Fatal("first entry of a refused batch took effect")
		}
	})
}

func TestLedgerBatchIsAtomic(t *testing.T) {
	f := newLedgerFixture(t)
	good := f.rootEntry(ledger.TypeVaultAdd, vaultData("x"))
	sum := sha256.Sum256(good.Body)
	bad := makeEntry(f.head+2, enc(sum[:]), ledger.Root, f.root, ledger.TypeVaultAdd, vaultData("x")) // duplicate id
	f.postEntries(f.admin.signer(), good, bad).want(t, http.StatusBadRequest, codeLedgerInvalid)
	if got := f.ledgerHead(f.admin.signer()); got != f.head {
		t.Fatalf("head = %d, want %d", got, f.head)
	}
	if _, ok := f.st.State().Vaults["x"]; ok {
		t.Fatal("refused batch created a vault")
	}

	// Both entries valid: one request appends both.
	second := makeEntry(f.head+2, enc(sum[:]), ledger.Root, f.root, ledger.TypeVaultAdd, vaultData("y"))
	res := f.postEntries(f.admin.signer(), good, second)
	res.ok(t)
	f.commit(good)
	f.commit(second)
	if got := res.number(t, "head"); got != f.head {
		t.Fatalf("head = %d, want %d", got, f.head)
	}
}

func TestLedgerRulesRefused(t *testing.T) {
	f := newLedgerFixture(t)
	other := newDevice(t)
	mismatched := deviceData(other, ledger.RoleMember)
	mismatched["deviceId"] = newDevice(t).id

	badRole := deviceData(other, "owner")
	badLevel := deviceData(other, ledger.RoleMember)
	badLevel["level"] = "quantum"
	unknownVault := deviceData(other, ledger.RoleMember, "missing")
	notOnCurve := deviceData(other, ledger.RoleMember)
	offCurve := make([]byte, 65)
	offCurve[0] = 4
	notOnCurve["authPub"] = enc(offCurve)
	notOnCurve["deviceId"] = ledger.DeviceID(offCurve)

	root := func(typ string, data map[string]any) ledger.Wire { return f.rootEntry(typ, data) }
	adminSigned := func(typ string, data map[string]any) ledger.Wire { return f.deviceEntry(f.admin, typ, data) }

	cases := []struct {
		name  string
		entry ledger.Wire
	}{
		{"prev wrong", makeEntry(f.head+1, enc(randBytes(32)), ledger.Root, f.root, ledger.TypeVaultAdd, vaultData("x"))},
		{"prev empty", makeEntry(f.head+1, "", ledger.Root, f.root, ledger.TypeVaultAdd, vaultData("x"))},
		{"non-admin signer", f.deviceEntry(f.member, ledger.TypeVaultAdd, vaultData("x"))},
		{"unknown signer", f.deviceEntry(other, ledger.TypeVaultAdd, vaultData("x"))},
		{"deviceId does not match authPub", root(ledger.TypeDeviceAdd, mismatched)},
		{"authPub off curve", root(ledger.TypeDeviceAdd, notOnCurve)},
		{"bad role", root(ledger.TypeDeviceAdd, badRole)},
		{"bad level", root(ledger.TypeDeviceAdd, badLevel)},
		{"device_add unknown vault", root(ledger.TypeDeviceAdd, unknownVault)},
		{"device_add duplicate", root(ledger.TypeDeviceAdd, deviceData(f.member, ledger.RoleMember))},
		{"revoke unknown", root(ledger.TypeDeviceRevoke, map[string]any{"deviceId": other.id, "reason": "x"})},
		{"grant unknown", root(ledger.TypeGrant, map[string]any{"deviceId": other.id, "role": "member", "vaults": []string{}})},
		{"grant bad role", root(ledger.TypeGrant, map[string]any{"deviceId": f.member.id, "role": "owner", "vaults": []string{}})},
		{"grant unknown vault", root(ledger.TypeGrant, map[string]any{"deviceId": f.member.id, "role": "member", "vaults": []string{"missing"}})},
		{"vault_add duplicate", root(ledger.TypeVaultAdd, vaultData(vault1))},
		{"vault_add gen 2", root(ledger.TypeVaultAdd, map[string]any{"vaultId": "x", "gen": 2, "keyCommit": enc(randBytes(32))})},
		{"vault_add bad id", root(ledger.TypeVaultAdd, vaultData("../x"))},
		{"vault_delete unknown", root(ledger.TypeVaultDelete, map[string]any{"vaultId": "missing"})},
		{"root_rotate by admin", adminSigned(ledger.TypeRootRotate, genesisData(f.root))},
		{"genesis after seq 0", root(ledger.TypeGenesis, genesisData(f.root))},
		{"unknown type", root("wizard", map[string]any{})},
		{"missing data field", root(ledger.TypeDeviceRevoke, map[string]any{"deviceId": f.member.id})},
		{"vault_rotate outside the rotate route", root(ledger.TypeVaultRotate, map[string]any{
			"vaultId": vault1, "gen": 2, "keyCommit": enc(randBytes(32)), "snapshotCount": 0,
			"snapshotHash": enc(randBytes(32)), "logHead": 0,
		})},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) { f.refused(t, c.entry) })
	}

	t.Run("version", func(t *testing.T) {
		body := mustJSON(map[string]any{"v": 2, "seq": f.head + 1, "prev": f.prev, "ts": 1, "signer": "root", "type": ledger.TypeVaultAdd, "data": vaultData("x")})
		f.refused(t, signWire(body, f.root))
	})
	t.Run("bad signature", func(t *testing.T) {
		w := f.rootEntry(ledger.TypeVaultAdd, vaultData("x"))
		w.Sig = ed25519.Sign(f.root, w.Body) // missing domain prefix
		f.refused(t, w)
	})
	t.Run("body altered after signing", func(t *testing.T) {
		w := f.rootEntry(ledger.TypeVaultAdd, vaultData("x"))
		w.Body = append(append([]byte{}, w.Body...), ' ')
		f.refused(t, w)
	})
	t.Run("body not JSON", func(t *testing.T) {
		f.refused(t, signWire([]byte("nope"), f.root))
	})
}

func TestMemberCannotPostLedger(t *testing.T) {
	f := newLedgerFixture(t)
	w := f.rootEntry(ledger.TypeVaultAdd, vaultData("x"))
	f.postEntries(f.member.signer(), w).want(t, http.StatusForbidden, codeForbidden)
}

func TestLastAdminGuard(t *testing.T) {
	revokeData := func(d *testDevice) map[string]any { return map[string]any{"deviceId": d.id, "reason": "x"} }
	demoteData := func(d *testDevice) map[string]any {
		return map[string]any{"deviceId": d.id, "role": ledger.RoleMember, "vaults": []string{vault1}}
	}

	t.Run("device cannot revoke the last admin", func(t *testing.T) {
		f := newLedgerFixture(t)
		f.refused(t, f.deviceEntry(f.admin, ledger.TypeDeviceRevoke, revokeData(f.admin)))
	})
	t.Run("device cannot demote the last admin", func(t *testing.T) {
		f := newLedgerFixture(t)
		f.refused(t, f.deviceEntry(f.admin, ledger.TypeGrant, demoteData(f.admin)))
	})
	t.Run("root can revoke the last admin", func(t *testing.T) {
		f := newLedgerFixture(t)
		f.revoke(f.admin)
		f.call(f.admin.signer(), "GET", "/v1/ledger", nil).want(t, http.StatusUnauthorized, codeUnauthorized)
	})
	t.Run("root can demote the last admin", func(t *testing.T) {
		f := newLedgerFixture(t)
		f.mustAppend(f.rootSigner(), func() ledger.Wire { return f.rootEntry(ledger.TypeGrant, demoteData(f.admin)) })
		f.postEntries(f.admin.signer()).want(t, http.StatusForbidden, codeForbidden)
	})
	t.Run("device can revoke an admin that is not the last", func(t *testing.T) {
		f := newLedgerFixture(t)
		second := f.addDevice(ledger.RoleAdmin, vault1)
		f.mustAppend(f.admin.signer(), func() ledger.Wire {
			return f.deviceEntry(f.admin, ledger.TypeDeviceRevoke, revokeData(second))
		})
		// Now the last again.
		f.refused(t, f.deviceEntry(f.admin, ledger.TypeDeviceRevoke, revokeData(f.admin)))
	})
	t.Run("a revoked admin does not count", func(t *testing.T) {
		f := newLedgerFixture(t)
		second := f.addDevice(ledger.RoleAdmin, vault1)
		f.revoke(second)
		f.refused(t, f.deviceEntry(f.admin, ledger.TypeGrant, demoteData(f.admin)))
	})
}

func TestRevokedDeviceCannotSign(t *testing.T) {
	f := newLedgerFixture(t)
	second := f.addDevice(ledger.RoleAdmin, vault1)
	f.mustAppend(f.admin.signer(), func() ledger.Wire {
		return f.deviceEntry(second, ledger.TypeVaultAdd, vaultData("signed-while-active"))
	})
	f.revoke(second)
	f.refused(t, f.deviceEntry(second, ledger.TypeVaultAdd, vaultData("x")))
}

func TestRevokedDeviceWithinOneBatch(t *testing.T) {
	f := newLedgerFixture(t)
	second := f.addDevice(ledger.RoleAdmin, vault1)
	revoke := f.deviceEntry(second, ledger.TypeDeviceRevoke, map[string]any{"deviceId": second.id, "reason": "x"})
	sum := sha256.Sum256(revoke.Body)
	after := makeEntry(f.head+2, enc(sum[:]), second.id, second.sign, ledger.TypeVaultAdd, vaultData("x"))
	f.postEntries(f.admin.signer(), revoke, after).want(t, http.StatusBadRequest, codeLedgerInvalid)
	if d, _ := f.st.State().ActiveDevice(second.id); d.ID == "" {
		t.Fatal("refused batch revoked the device")
	}
}

func TestRevokedDeviceStaysRevoked(t *testing.T) {
	f := newLedgerFixture(t)
	f.revoke(f.member)
	f.refused(t, f.rootEntry(ledger.TypeDeviceAdd, deviceData(f.member, ledger.RoleMember))) // rule 7: no reuse
	f.refused(t, f.rootEntry(ledger.TypeDeviceRevoke, map[string]any{"deviceId": f.member.id, "reason": "x"}))
	f.refused(t, f.rootEntry(ledger.TypeGrant, map[string]any{"deviceId": f.member.id, "role": "admin", "vaults": []string{}}))
}

func TestRootRotateReplacesRootKey(t *testing.T) {
	f := newLedgerFixture(t)
	old := f.root
	f.rotateRoot(recoveryWrap(vault1, 1))

	f.refused(t, makeEntry(f.head+1, f.prev, ledger.Root, old, ledger.TypeVaultAdd, vaultData("x")))
	f.call(rootSigner(old), "GET", "/v1/ledger", nil).want(t, http.StatusUnauthorized, codeUnauthorized)

	f.call(f.rootSigner(), "GET", "/v1/ledger", nil).ok(t)
	f.addVault("x")
}

func TestLedgerBodyStoredByteExact(t *testing.T) {
	f := newLedgerFixture(t)
	// Key order, spacing and an unknown field that a re-serializer would lose.
	body := []byte(`{ "type":"vault_add","signer":"root",  "v":1,"seq":` + itoa(f.head+1) + `,"prev":"` + f.prev +
		`","ts":1730000000000,"future":{"z":1,"a":2},"data":{"keyCommit":"` + enc(randBytes(32)) + `","gen":1,"vaultId":"x","extra":"密匣"} }`)
	w := signWire(body, f.root)
	f.mustAppend(f.rootSigner(), func() ledger.Wire { return w })

	res := f.call(f.admin.signer(), "GET", "/v1/ledger?from="+itoa(f.head), nil)
	res.ok(t)
	entries := res.list(t, "entries")
	if len(entries) != 1 {
		t.Fatalf("entries = %d, want 1", len(entries))
	}
	got := entries[0].(map[string]any)
	if got["body"] != enc(body) || got["sig"] != enc(w.Sig) {
		t.Fatalf("entry was not returned byte-exact")
	}
}

func TestLedgerFieldNamesAreCaseSensitive(t *testing.T) {
	f := newLedgerFixture(t)
	// JSON.parse would see no "type" here; encoding/json struct decoding would.
	body := []byte(`{"v":1,"seq":` + itoa(f.head+1) + `,"prev":"` + f.prev + `","ts":1,"signer":"root","Type":"vault_add","data":{"vaultId":"x","gen":1,"keyCommit":"` + enc(randBytes(32)) + `"}}`)
	f.refused(t, signWire(body, f.root))
}

func TestLedgerFromParameter(t *testing.T) {
	f := newLedgerFixture(t)
	admin := f.admin.signer()

	res := f.call(admin, "GET", "/v1/ledger?from=0", nil)
	res.ok(t)
	if n := int64(len(res.list(t, "entries"))); n != f.head+1 {
		t.Fatalf("entries = %d, want %d", n, f.head+1)
	}
	res = f.call(admin, "GET", "/v1/ledger?from="+itoa(f.head), nil)
	res.ok(t)
	if n := len(res.list(t, "entries")); n != 1 {
		t.Fatalf("from=head returned %d entries, want 1 (N is inclusive)", n)
	}
	f.call(admin, "GET", "/v1/ledger?from=abc", nil).want(t, http.StatusBadRequest, codeBadRequest)
	f.call(admin, "GET", "/v1/ledger?from=-1", nil).want(t, http.StatusBadRequest, codeBadRequest)
}

func TestRevokeDeletesKeys(t *testing.T) {
	f := newLedgerFixture(t)
	f.callJSON(f.admin.signer(), "PUT", keysURI(vault1), map[string]any{"keys": []any{wrapKey(f.member.id, 1)}}).ok(t)
	before, err := f.st.Keys(t.Context(), vault1, f.member.id)
	if err != nil || len(before) != 1 {
		t.Fatalf("keys before revoke = %d, %v", len(before), err)
	}
	f.revoke(f.member)
	after, err := f.st.Keys(t.Context(), vault1, f.member.id)
	if err != nil || len(after) != 0 {
		t.Fatalf("keys after revoke = %d, %v", len(after), err)
	}
}

func TestGrantNarrowingDeletesKeys(t *testing.T) {
	f := newLedgerFixture(t)
	f.addVault("v2")
	f.mustAppend(f.rootSigner(), func() ledger.Wire {
		return f.rootEntry(ledger.TypeGrant, map[string]any{"deviceId": f.member.id, "role": "member", "vaults": []string{vault1, "v2"}})
	})
	f.mustAppend(f.rootSigner(), func() ledger.Wire {
		return f.rootEntry(ledger.TypeGrant, map[string]any{"deviceId": f.admin.id, "role": "admin", "vaults": []string{vault1, "v2"}})
	})
	admin := f.admin.signer()
	f.callJSON(admin, "PUT", keysURI(vault1), map[string]any{"keys": []any{wrapKey(f.member.id, 1)}}).ok(t)
	f.callJSON(admin, "PUT", keysURI("v2"), map[string]any{"keys": []any{wrapKey(f.member.id, 1)}}).ok(t)

	f.mustAppend(f.rootSigner(), func() ledger.Wire {
		return f.rootEntry(ledger.TypeGrant, map[string]any{"deviceId": f.member.id, "role": "member", "vaults": []string{vault1}})
	})
	kept, _ := f.st.Keys(t.Context(), vault1, f.member.id)
	gone, _ := f.st.Keys(t.Context(), "v2", f.member.id)
	if len(kept) != 1 || len(gone) != 0 {
		t.Fatalf("after narrowing: kept %d (want 1), removed vault %d (want 0)", len(kept), len(gone))
	}
	f.call(f.member.signer(), "GET", keysURI("v2"), nil).want(t, http.StatusForbidden, codeForbidden)
}

func TestVaultDeleteRemovesEverything(t *testing.T) {
	f := newLedgerFixture(t)
	admin := f.admin.signer()
	f.pushChanges(f.admin, vault1, 1, "a", "b").ok(t)
	f.call(admin, "PUT", blobURI(vault1, "att"), []byte("bytes")).ok(t)
	if files := blobFiles(t, f.harness); len(files) != 1 {
		t.Fatalf("blob files = %d, want 1", len(files))
	}

	f.mustAppend(f.rootSigner(), func() ledger.Wire {
		return f.rootEntry(ledger.TypeVaultDelete, map[string]any{"vaultId": vault1})
	})
	if files := blobFiles(t, f.harness); len(files) != 0 {
		t.Fatalf("blob files after delete = %d, want 0", len(files))
	}
	keys, _ := f.st.Keys(t.Context(), vault1, f.admin.id)
	if len(keys) != 0 {
		t.Fatalf("keys after delete = %d", len(keys))
	}
	f.call(admin, "GET", changesURI(vault1), nil).want(t, http.StatusForbidden, codeForbidden)
	f.call(f.rootSigner(), "GET", changesURI(vault1), nil).want(t, http.StatusNotFound, codeNotFound)
}

func TestReusedVaultIdGrantsNoAccess(t *testing.T) {
	f := newLedgerFixture(t)
	f.pushChanges(f.member, vault1, 1, "old").ok(t)
	f.mustAppend(f.rootSigner(), func() ledger.Wire {
		return f.rootEntry(ledger.TypeVaultDelete, map[string]any{"vaultId": vault1})
	})
	f.addVault(vault1)
	f.call(f.member.signer(), "GET", changesURI(vault1), nil).want(t, http.StatusForbidden, codeForbidden)

	res := f.call(f.rootSigner(), "GET", changesURI(vault1), nil)
	res.ok(t)
	if n := len(res.list(t, "changes")); n != 0 {
		t.Fatalf("recreated vault has %d changes", n)
	}
}

// Every field the client decodes must decode. A value it refuses, once signed
// into the ledger, stops every client's replay for good.
func TestLedgerKeyCommitMustBe32Bytes(t *testing.T) {
	f := newLedgerFixture(t)
	for name, value := range badHash32() {
		t.Run(name, func(t *testing.T) {
			f.refused(t, f.rootEntry(ledger.TypeVaultAdd, map[string]any{"vaultId": "x", "gen": 1, "keyCommit": value}))
		})
	}
	data := vaultData("x")
	delete(data, "keyCommit")
	f.refused(t, f.rootEntry(ledger.TypeVaultAdd, data))
}

// badHash32 lists values that are not the base64url of exactly 32 bytes.
func badHash32() map[string]any {
	return map[string]any{
		"empty":        "",
		"short text":   "k",
		"31 bytes":     enc(randBytes(31)),
		"33 bytes":     enc(randBytes(33)),
		"padded":       enc(randBytes(32)) + "=",
		"not base64":   "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!",
		"number":       32,
		"null":         nil,
		"has newline":  enc(randBytes(32)) + "\n",
		"standard b64": "+" + enc(randBytes(32))[1:],
	}
}

func TestLedgerRefusesInvalidUTF8(t *testing.T) {
	f := newLedgerFixture(t)
	body := []byte(`{"v":1,"seq":` + itoa(f.head+1) + `,"prev":"` + f.prev + `","ts":1,"signer":"root","type":"vault_add","data":{"vaultId":"x","gen":1,"keyCommit":"` +
		enc(randBytes(32)) + "\",\"note\":\"\xff\"}}")
	f.refused(t, signWire(body, f.root))
}

func TestLedgerRefusesSignaturesLibsodiumRejects(t *testing.T) {
	f := newLedgerFixture(t)
	forge := func(body []byte, priv ed25519.PrivateKey) ledger.Wire {
		msg := append([]byte("mixia/ledger/v1\n"), body...)
		sig := edtest.IdentityR(priv, msg)
		if !ed25519.Verify(priv.Public().(ed25519.PublicKey), msg, sig) {
			t.Fatal("test vector is not accepted by crypto/ed25519, so it proves nothing")
		}
		return ledger.Wire{Body: body, Sig: sig}
	}
	t.Run("root", func(t *testing.T) {
		f.refused(t, forge(f.rootEntry(ledger.TypeVaultAdd, vaultData("x")).Body, f.root))
	})
	t.Run("admin device", func(t *testing.T) {
		f.refused(t, forge(f.deviceEntry(f.admin, ledger.TypeVaultAdd, vaultData("x")).Body, f.admin.sign))
	})
}

func TestDeviceAddRefusesUnusableSignPub(t *testing.T) {
	f := newLedgerFixture(t)
	nonCanonical := make([]byte, 32)
	for i := range nonCanonical {
		nonCanonical[i] = 0xff
	}
	nonCanonical[0], nonCanonical[31] = 0xef, 0x7f // p+2, which is not of small order
	keys := map[string][]byte{"non-canonical": nonCanonical}
	for i, p := range edtest.Torsion() {
		keys["torsion "+itoa(int64(i))] = p.Encode()
	}
	for name, key := range keys {
		t.Run(name, func(t *testing.T) {
			data := deviceData(newDevice(t), ledger.RoleMember)
			data["signPub"] = enc(key)
			f.refused(t, f.rootEntry(ledger.TypeDeviceAdd, data))
		})
	}
}

func TestGenesisRefusesSmallOrderRootKey(t *testing.T) {
	h := newHarness(t)
	identity := edtest.Identity().Encode()
	body := mustJSON(map[string]any{
		"v": 1, "seq": 0, "prev": "", "ts": 1, "signer": ledger.Root, "type": ledger.TypeGenesis,
		"data": map[string]any{"ownerId": "o", "rootPub": enc(identity), "recoveryBoxPub": enc(randBytes(32))},
	})
	// R = identity, S = 0 verifies under the identity key for every message.
	sig := append(append([]byte{}, identity...), make([]byte, 32)...)
	if !ed25519.Verify(identity, append([]byte("mixia/ledger/v1\n"), body...), sig) {
		t.Fatal("test vector is not accepted by crypto/ed25519, so it proves nothing")
	}
	req := mustJSON(map[string]any{"token": testToken, "entries": []ledger.Wire{{Body: body, Sig: sig}}, "keys": []any{}})
	h.raw("POST", "/v1/bootstrap", req, nil).want(t, http.StatusBadRequest, codeLedgerInvalid)
}
