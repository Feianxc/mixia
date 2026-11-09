package api

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"mixia/server/internal/ledger"
	"mixia/server/internal/store"
)

const (
	testToken = "bootstrap-token"
	vault1    = "v1"
)

var hugeQuota int64 = 1 << 40

func enc(b []byte) string { return ledger.EncodeB64(b) }

func randBytes(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}

func tokenHash(token string) []byte {
	sum := sha256.Sum256([]byte(token))
	return sum[:]
}

// testDevice is a simulated client: a P-256 auth key and an Ed25519 signing key.
type testDevice struct {
	id      string
	auth    *ecdsa.PrivateKey
	authPub []byte
	sign    ed25519.PrivateKey
	signPub ed25519.PublicKey
}

func newDevice(t *testing.T) *testDevice {
	t.Helper()
	auth, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	authPub, err := auth.PublicKey.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	signPub, sign, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &testDevice{id: ledger.DeviceID(authPub), auth: auth, authPub: authPub, sign: sign, signPub: signPub}
}

// signer authenticates HTTP requests as a device or as root.
type signer struct {
	name string
	sign func(msg []byte) []byte
}

func p256Sign(k *ecdsa.PrivateKey, msg []byte) []byte {
	digest := sha256.Sum256(msg)
	r, s, err := ecdsa.Sign(rand.Reader, k, digest[:])
	if err != nil {
		panic(err)
	}
	out := make([]byte, 64)
	r.FillBytes(out[:32])
	s.FillBytes(out[32:])
	return out
}

func (d *testDevice) signer() signer {
	return signer{name: d.id, sign: func(msg []byte) []byte { return p256Sign(d.auth, msg) }}
}

func rootSigner(k ed25519.PrivateKey) signer {
	return signer{name: ledger.Root, sign: func(msg []byte) []byte { return ed25519.Sign(k, msg) }}
}

type clock struct{ offset atomic.Int64 }

func (c *clock) now() time.Time { return time.Now().Add(time.Duration(c.offset.Load())) }

func (c *clock) advance(d time.Duration) { c.offset.Add(int64(d)) }

// harness runs the full server on a temp directory. It mirrors the ledger head
// so that tests can build the next entry.
type harness struct {
	t     *testing.T
	dir   string
	quota int64
	cfg   Config
	clock *clock

	st  *store.Store
	srv *Server
	web *httptest.Server

	root ed25519.PrivateKey
	head int64
	prev string

	// tweakRotate, when set, edits the data of the next vault_rotate entry
	// before it is signed.
	tweakRotate func(data map[string]any)
}

type option func(*harness)

func withQuota(q int64) option        { return func(h *harness) { h.quota = q } }
func withoutBootstrapToken() option   { return func(h *harness) { h.cfg.BootstrapTokenHash = nil } }
func withTrustCF() option             { return func(h *harness) { h.cfg.TrustCF = true } }
func withLogger(l *log.Logger) option { return func(h *harness) { h.cfg.Log = l } }
func withRate(rps, burst float64) option {
	return func(h *harness) { h.cfg.RateRPS, h.cfg.RateBurst = rps, burst }
}

func newHarness(t *testing.T, opts ...option) *harness {
	t.Helper()
	_, root, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	h := &harness{
		t:     t,
		dir:   t.TempDir(),
		quota: hugeQuota,
		clock: &clock{},
		root:  root,
		head:  -1,
		cfg:   Config{BootstrapTokenHash: tokenHash(testToken), RateRPS: 1e9, RateBurst: 1e9},
	}
	for _, o := range opts {
		o(h)
	}
	h.cfg.Now = h.clock.now
	h.start()
	t.Cleanup(h.stop)
	return h
}

func (h *harness) start() {
	h.t.Helper()
	st, err := store.Open(h.dir, h.quota)
	if err != nil {
		h.t.Fatalf("open store: %v", err)
	}
	h.st = st
	cfg := h.cfg
	cfg.Store = st
	h.srv = New(cfg)
	h.web = httptest.NewServer(h.srv)
}

func (h *harness) stop() {
	if h.web != nil {
		h.web.Close()
		h.web = nil
	}
	if h.st != nil {
		h.st.Close()
		h.st = nil
	}
}

func (h *harness) restart() {
	h.t.Helper()
	h.stop()
	h.start()
}

func (h *harness) rootSigner() signer { return rootSigner(h.root) }

type response struct {
	status int
	header http.Header
	body   []byte
}

func (r *response) json(t *testing.T) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(r.body, &m); err != nil {
		t.Fatalf("response is not JSON (%d): %q", r.status, r.body)
	}
	return m
}

// want asserts the status and, for errors, the wire error code.
func (r *response) want(t *testing.T, status int, code string) {
	t.Helper()
	if r.status != status {
		t.Fatalf("status = %d, want %d; body %q", r.status, status, r.body)
	}
	if code != "" {
		if got := r.json(t)["error"]; got != code {
			t.Fatalf("error = %v, want %q; body %q", got, code, r.body)
		}
	}
}

func (r *response) ok(t *testing.T) {
	t.Helper()
	r.want(t, http.StatusOK, "")
}

// number reads an integer field of a JSON object response.
func (r *response) number(t *testing.T, key string) int64 {
	t.Helper()
	v, ok := r.json(t)[key].(float64)
	if !ok {
		t.Fatalf("field %q is not a number: %q", key, r.body)
	}
	return int64(v)
}

func (r *response) list(t *testing.T, key string) []any {
	t.Helper()
	v, ok := r.json(t)[key].([]any)
	if !ok {
		t.Fatalf("field %q is not an array: %q", key, r.body)
	}
	return v
}

// sent lets a test tamper with a request after it is signed, or with the
// values it is signed over.
type sent struct {
	method, uri string
	body        []byte
	ts, nonce   string
	bodyHash    string
	sig         string
	headers     map[string]string
	skip        map[string]bool
}

type mutate func(*sent)

func bodyDigest(body []byte) string {
	digest := sha256.Sum256(body)
	return hex.EncodeToString(digest[:])
}

func signedString(method, uri, ts, nonce, bodyHash string) []byte {
	return []byte("MIXIA-REQ-1\n" + method + "\n" + uri + "\n" + ts + "\n" + nonce + "\n" + bodyHash)
}

// authHeaders signs exactly the given values, whatever they are.
func authHeaders(s signer, method, uri, ts, nonce, bodyHash string) map[string]string {
	return map[string]string{
		hdrDevice: s.name, hdrTs: ts, hdrNonce: nonce, hdrBody: bodyHash,
		hdrSig: enc(s.sign(signedString(method, uri, ts, nonce, bodyHash))),
	}
}

func (h *harness) raw(method, uri string, body []byte, headers map[string]string) *response {
	h.t.Helper()
	req, err := http.NewRequest(method, h.web.URL+uri, bytes.NewReader(body))
	if err != nil {
		h.t.Fatal(err)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	res, err := client.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer res.Body.Close()
	data, err := io.ReadAll(res.Body)
	if err != nil {
		h.t.Fatal(err)
	}
	return &response{status: res.StatusCode, header: res.Header, body: data}
}

// call sends a correctly signed request. Mutators run after signing, so they
// model an attacker altering a request in flight.
func (h *harness) call(s signer, method, uri string, body []byte, muts ...mutate) *response {
	h.t.Helper()
	ts := strconv.FormatInt(h.clock.now().UnixMilli(), 10)
	nonce := enc(randBytes(16))
	r := &sent{method: method, uri: uri, body: body, ts: ts, nonce: nonce, bodyHash: bodyDigest(body), skip: map[string]bool{}}
	r.sig = enc(s.sign(signedString(method, uri, ts, nonce, r.bodyHash)))
	for _, m := range muts {
		m(r)
	}
	headers := map[string]string{hdrDevice: s.name, hdrTs: r.ts, hdrNonce: r.nonce, hdrBody: r.bodyHash, hdrSig: r.sig}
	for k := range r.skip {
		delete(headers, k)
	}
	for k, v := range r.headers {
		headers[k] = v
	}
	return h.raw(r.method, r.uri, r.body, headers)
}

// signedAt sends a request signed over the given ts, nonce and identity.
func (h *harness) signedAt(s signer, method, uri string, body []byte, ts int64, nonce string) *response {
	h.t.Helper()
	return h.raw(method, uri, body, authHeaders(s, method, uri, strconv.FormatInt(ts, 10), nonce, bodyDigest(body)))
}

func (h *harness) callJSON(s signer, method, uri string, v any, muts ...mutate) *response {
	h.t.Helper()
	return h.call(s, method, uri, mustJSON(v), muts...)
}

func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

// makeEntry builds and signs an entry body.
func makeEntry(seq int64, prev, signerName string, key ed25519.PrivateKey, typ string, data map[string]any) ledger.Wire {
	body := mustJSON(map[string]any{
		"v": 1, "seq": seq, "prev": prev, "ts": time.Now().UnixMilli(),
		"signer": signerName, "type": typ, "data": data,
	})
	return signWire(body, key)
}

func signWire(body []byte, key ed25519.PrivateKey) ledger.Wire {
	return ledger.Wire{Body: body, Sig: ed25519.Sign(key, append([]byte("mixia/ledger/v1\n"), body...))}
}

func (h *harness) rootEntry(typ string, data map[string]any) ledger.Wire {
	return makeEntry(h.head+1, h.prev, ledger.Root, h.root, typ, data)
}

func (h *harness) deviceEntry(d *testDevice, typ string, data map[string]any) ledger.Wire {
	return makeEntry(h.head+1, h.prev, d.id, d.sign, typ, data)
}

// commit advances the local mirror after the server accepted w.
func (h *harness) commit(w ledger.Wire) {
	sum := sha256.Sum256(w.Body)
	h.head++
	h.prev = enc(sum[:])
}

func (h *harness) postEntries(s signer, wires ...ledger.Wire) *response {
	h.t.Helper()
	return h.callJSON(s, "POST", "/v1/ledger", map[string]any{"entries": wires})
}

// mustAppend appends entries one at a time; each is built lazily so that it
// sees the head left by the previous one.
func (h *harness) mustAppend(s signer, build ...func() ledger.Wire) {
	h.t.Helper()
	for _, b := range build {
		w := b()
		h.postEntries(s, w).ok(h.t)
		h.commit(w)
	}
}

func genesisData(root ed25519.PrivateKey) map[string]any {
	return map[string]any{
		"ownerId":        "owner",
		"rootPub":        enc(root.Public().(ed25519.PublicKey)),
		"recoveryBoxPub": enc(randBytes(32)),
	}
}

func deviceData(d *testDevice, role string, vaults ...string) map[string]any {
	if vaults == nil {
		vaults = []string{}
	}
	return map[string]any{
		"deviceId": d.id, "name": "test", "platform": "test", "level": "software", "role": role,
		"authPub": enc(d.authPub), "signPub": enc(d.signPub), "boxPub": enc(randBytes(32)), "vaults": vaults,
	}
}

func vaultData(id string) map[string]any {
	return map[string]any{"vaultId": id, "gen": 1, "keyCommit": enc(randBytes(32))}
}

func wrapKey(deviceID string, gen int64) map[string]any {
	return map[string]any{"deviceId": deviceID, "gen": gen, "wrapped": enc(randBytes(80))}
}

// bootstrap creates genesis, vault v1 and an admin device with access to it.
func (h *harness) bootstrap() *testDevice {
	h.t.Helper()
	admin := newDevice(h.t)
	var wires []ledger.Wire
	push := func(typ string, data map[string]any) {
		w := h.rootEntry(typ, data)
		h.commit(w)
		wires = append(wires, w)
	}
	push(ledger.TypeGenesis, genesisData(h.root))
	push(ledger.TypeVaultAdd, vaultData(vault1))
	push(ledger.TypeDeviceAdd, deviceData(admin, ledger.RoleAdmin, vault1))
	keys := []map[string]any{
		{"vaultId": vault1, "deviceId": admin.id, "gen": 1, "wrapped": enc(randBytes(80))},
		{"vaultId": vault1, "deviceId": ledger.Recovery, "gen": 1, "wrapped": enc(randBytes(80))},
	}
	res := h.raw("POST", "/v1/bootstrap", mustJSON(map[string]any{"token": testToken, "entries": wires, "keys": keys}), nil)
	res.ok(h.t)
	return admin
}

// addDevice has root add a device.
func (h *harness) addDevice(role string, vaults ...string) *testDevice {
	h.t.Helper()
	d := newDevice(h.t)
	h.mustAppend(h.rootSigner(), func() ledger.Wire {
		return h.rootEntry(ledger.TypeDeviceAdd, deviceData(d, role, vaults...))
	})
	return d
}

func (h *harness) addVault(id string) {
	h.t.Helper()
	h.mustAppend(h.rootSigner(), func() ledger.Wire { return h.rootEntry(ledger.TypeVaultAdd, vaultData(id)) })
}

func (h *harness) revoke(d *testDevice) {
	h.t.Helper()
	h.mustAppend(h.rootSigner(), func() ledger.Wire {
		return h.rootEntry(ledger.TypeDeviceRevoke, map[string]any{"deviceId": d.id, "reason": "test"})
	})
}

func change(id string, gen int64) map[string]any {
	return map[string]any{"id": id, "gen": gen, "blob": enc([]byte("ciphertext-" + id))}
}

func changesURI(vault string) string { return "/v1/vaults/" + vault + "/changes" }
func keysURI(vault string) string    { return "/v1/vaults/" + vault + "/keys" }
func rotateURI(vault string) string  { return "/v1/vaults/" + vault + "/rotate" }
func blobURI(vault, id string) string {
	return "/v1/vaults/" + vault + "/blobs/" + id
}

func (h *harness) pushChanges(d *testDevice, vault string, gen int64, ids ...string) *response {
	h.t.Helper()
	list := make([]map[string]any, 0, len(ids))
	for _, id := range ids {
		list = append(list, change(id, gen))
	}
	return h.callJSON(d.signer(), "POST", changesURI(vault), map[string]any{"changes": list})
}

// rotateBody builds a rotate request for gen+1 with the given snapshot ids.
func (h *harness) rotateBody(signerName string, key ed25519.PrivateKey, vault string, gen int64, keys []map[string]any, ids ...string) map[string]any {
	blobs := make([][]byte, len(ids))
	for i, id := range ids {
		blobs[i] = []byte("ciphertext-" + id)
	}
	return h.rotateBodyBlobs(signerName, key, vault, gen, keys, ids, blobs)
}

// rotateBodyBlobs is rotateBody with explicit snapshot contents.
func (h *harness) rotateBodyBlobs(signerName string, key ed25519.PrivateKey, vault string, gen int64, keys []map[string]any, ids []string, blobs [][]byte) map[string]any {
	snapshot := make([]map[string]any, 0, len(ids))
	sum := sha256.New()
	for i, id := range ids {
		snapshot = append(snapshot, map[string]any{"id": id, "gen": gen, "blob": enc(blobs[i])})
		sum.Write([]byte(id))
		sum.Write(blobs[i])
	}
	data := map[string]any{
		"vaultId": vault, "gen": gen, "keyCommit": enc(randBytes(32)),
		"snapshotCount": len(ids), "snapshotHash": enc(sum.Sum(nil)), "logHead": h.vaultHead(vault),
	}
	if h.tweakRotate != nil {
		h.tweakRotate(data)
	}
	entry := makeEntry(h.head+1, h.prev, signerName, key, ledger.TypeVaultRotate, data)
	// 服务端要求封装覆盖恢复和全部有权设备，这里补齐，用例只写它关心的部分
	have := map[any]bool{}
	for _, k := range keys {
		have[k["deviceId"]] = true
	}
	need := []string{ledger.Recovery}
	for id, d := range h.st.State().Devices {
		if !d.Revoked && d.HasVault(vault) {
			need = append(need, id)
		}
	}
	for _, id := range need {
		if !have[id] {
			keys = append(keys, wrapKey(id, gen))
		}
	}
	return map[string]any{"entry": entry, "keys": keys, "changes": snapshot}
}

func entryOf(body map[string]any) ledger.Wire { return body["entry"].(ledger.Wire) }

// vaultHead is what a client would see as the log head, 0 for no such vault.
func (h *harness) vaultHead(vault string) int64 {
	page, err := h.st.Changes(context.Background(), vault, 0, 1)
	if err != nil {
		return 0
	}
	return page.Head
}

func (h *harness) ledgerHead(s signer) int64 {
	h.t.Helper()
	res := h.call(s, "GET", "/v1/ledger", nil)
	res.ok(h.t)
	return res.number(h.t, "head")
}

func fmtURI(format string, args ...any) string { return fmt.Sprintf(format, args...) }
