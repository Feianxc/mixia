//go:build windows

package main

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"hash"
	"io"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// 这些测试驱动真实的 mixia-hwkey.exe 进程和真实 TPM，不是模拟。

var helperPath string

func TestMain(m *testing.M) { os.Exit(runTests(m)) }

func runTests(m *testing.M) int {
	dir, err := os.MkdirTemp("", "mixia-hwkey-test")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer os.RemoveAll(dir)
	// MIXIA_HWKEY_BIN 指向已构建的产物时，整套测试直接验证那个文件。
	helperPath = os.Getenv("MIXIA_HWKEY_BIN")
	if helperPath == "" {
		helperPath = filepath.Join(dir, "mixia-hwkey.exe")
		if out, err := exec.Command("go", "build", "-o", helperPath, ".").CombinedOutput(); err != nil {
			fmt.Fprintf(os.Stderr, "build helper: %v\n%s", err, out)
			return 1
		}
	}

	before, beforeErr := listPCPKeys()
	code := m.Run()
	if beforeErr != nil {
		return code
	}
	after, err := listPCPKeys()
	if err != nil {
		fmt.Fprintf(os.Stderr, "list PCP keys after tests: %v\n", err)
		return 1
	}
	var leaked []string
	for _, k := range after {
		if !slices.Contains(before, k) {
			leaked = append(leaked, k)
		}
	}
	if len(leaked) > 0 {
		fmt.Fprintf(os.Stderr, "LEAKED TEST KEYS: %v\n", leaked)
		return 1
	}
	fmt.Printf("PCP user keys before=%d after=%d, no test keys left behind\n", len(before), len(after))
	return code
}

func listPCPKeys() ([]string, error) {
	type ncryptKeyName struct {
		name, algID *uint16
		legacySpec  uint32
		flags       uint32
	}
	enum := modncrypt.NewProc("NCryptEnumKeys")
	free := modncrypt.NewProc("NCryptFreeBuffer")

	p, err := openProvider()
	if err != nil {
		return nil, err
	}
	defer freeObject(p)

	var names []string
	var state uintptr
	for {
		var item *ncryptKeyName
		r, _, _ := enum.Call(p, 0, uintptr(unsafe.Pointer(&item)), uintptr(unsafe.Pointer(&state)), ncryptSilentFlag)
		if uint32(r) == 0x8009002A { // NTE_NO_MORE_ITEMS
			break
		}
		if err := statusErr("NCryptEnumKeys", r); err != nil {
			return nil, err
		}
		names = append(names, windows.UTF16PtrToString(item.name))
		free.Call(uintptr(unsafe.Pointer(item)))
	}
	if state != 0 {
		free.Call(state)
	}
	return names, nil
}

type helper struct {
	t      *testing.T
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout *bufio.Reader
	stderr bytes.Buffer
	nextID int
	closed bool
}

func startHelper(t *testing.T) *helper {
	t.Helper()
	h := &helper{t: t, cmd: exec.Command(helperPath)}
	h.cmd.Stderr = &h.stderr
	var err error
	if h.stdin, err = h.cmd.StdinPipe(); err != nil {
		t.Fatal(err)
	}
	out, err := h.cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	h.stdout = bufio.NewReader(out)
	if err := h.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(h.close)
	return h
}

// close 关掉 stdin，要求进程干净退出（exit 0）且从未往 stderr 写过任何东西。
func (h *helper) close() {
	h.t.Helper()
	if h.closed {
		return
	}
	h.closed = true
	h.stdin.Close()
	if err := h.cmd.Wait(); err != nil {
		h.t.Errorf("helper exit after stdin EOF: %v", err)
	}
	if h.stderr.Len() != 0 {
		h.t.Errorf("helper wrote %d bytes to stderr", h.stderr.Len())
	}
}

type rpcReply struct {
	ID      int             `json:"id"`
	OK      bool            `json:"ok"`
	Result  json.RawMessage `json:"result"`
	Error   string          `json:"error"`
	Message string          `json:"message"`
}

func (h *helper) call(cmd string, args map[string]string) rpcReply {
	h.t.Helper()
	h.nextID++
	line, err := json.Marshal(map[string]any{"id": h.nextID, "cmd": cmd, "args": args})
	if err != nil {
		h.t.Fatal(err)
	}
	if _, err := h.stdin.Write(append(line, '\n')); err != nil {
		h.t.Fatalf("write %s: %v", cmd, err)
	}
	respLine, err := h.stdout.ReadBytes('\n')
	if err != nil {
		h.t.Fatalf("read %s: %v (stderr %d bytes)", cmd, err, h.stderr.Len())
	}
	var r rpcReply
	if err := json.Unmarshal(respLine, &r); err != nil {
		h.t.Fatalf("%s: bad response %q", cmd, respLine)
	}
	if r.ID != h.nextID {
		h.t.Fatalf("%s: response id %d, want %d", cmd, r.ID, h.nextID)
	}
	return r
}

func (h *helper) mustCall(cmd string, args map[string]string, out any) {
	h.t.Helper()
	r := h.call(cmd, args)
	if !r.OK {
		h.t.Fatalf("%s: %s: %s", cmd, r.Error, r.Message)
	}
	if out != nil {
		if err := json.Unmarshal(r.Result, out); err != nil {
			h.t.Fatalf("%s: result: %v", cmd, err)
		}
	}
}

func (h *helper) requireError(cmd string, args map[string]string, code string) rpcReply {
	h.t.Helper()
	r := h.call(cmd, args)
	if r.OK || r.Error != code {
		h.t.Fatalf("%s: want error %s, got ok=%v error=%s message=%s", cmd, code, r.OK, r.Error, r.Message)
	}
	return r
}

func (h *helper) requireTPM() {
	h.t.Helper()
	var s statusResult
	h.mustCall("status", nil, &s)
	if !s.Available {
		h.t.Skip("TPM unavailable on this machine")
	}
}

func decode(t *testing.T, s string) []byte {
	t.Helper()
	b, err := b64.DecodeString(s)
	if err != nil {
		t.Fatalf("decode %q: %v", s, err)
	}
	return b
}

func newName(t *testing.T) string {
	t.Helper()
	buf := make([]byte, 16)
	rand.Read(buf)
	return b64.EncodeToString(buf)
}

// createKeys 建一对测试密钥，并保证测试结束时删除（用新进程删，不依赖 h 还活着）。
func createKeys(t *testing.T, h *helper, name string) []byte {
	t.Helper()
	t.Cleanup(func() {
		d := startHelper(t)
		if r := d.call("delete", map[string]string{"name": name}); !r.OK && r.Error != codeNoKey {
			t.Errorf("cleanup delete: %s %s", r.Error, r.Message)
		}
		d.close()
	})
	var res pubResult
	h.mustCall("create", map[string]string{"name": name}, &res)
	return decode(t, res.AuthPub)
}

func sign(t *testing.T, h *helper, name string, data []byte) []byte {
	t.Helper()
	var res signResult
	h.mustCall("sign", map[string]string{"name": name, "data": b64.EncodeToString(data)}, &res)
	return decode(t, res.Sig)
}

func seal(t *testing.T, h *helper, name string, data []byte) sealResult {
	t.Helper()
	var res sealResult
	h.mustCall("seal", map[string]string{"name": name, "data": b64.EncodeToString(data)}, &res)
	return res
}

func unseal(t *testing.T, h *helper, name string, s sealResult) []byte {
	t.Helper()
	var res unsealResult
	h.mustCall("unseal", map[string]string{"name": name, "blob": s.Blob, "alg": s.Alg}, &res)
	return decode(t, res.Data)
}

func verify(t *testing.T, pub, data, sig []byte) bool {
	t.Helper()
	key, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), pub)
	if err != nil {
		t.Fatalf("authPub is not a valid P-256 point: %v", err)
	}
	if len(sig) != 64 {
		t.Fatalf("signature is %d bytes, want 64", len(sig))
	}
	digest := sha256.Sum256(data)
	return ecdsa.Verify(key, digest[:],
		new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:]))
}

func TestOAEPPaddingInfoLayout(t *testing.T) {
	var p oaepPaddingInfo
	if unsafe.Sizeof(p) != 24 || unsafe.Offsetof(p.label) != 8 || unsafe.Offsetof(p.labelSz) != 16 {
		t.Fatalf("size=%d label@%d labelSz@%d", unsafe.Sizeof(p), unsafe.Offsetof(p.label), unsafe.Offsetof(p.labelSz))
	}
}

func TestStatusReportsRealTPM(t *testing.T) {
	h := startHelper(t)
	var s statusResult
	h.mustCall("status", nil, &s)
	t.Logf("status = %+v", s)
	if !s.Available {
		t.Skip("TPM unavailable on this machine")
	}
	if s.Level != levelHardware || s.Provider != providerName {
		t.Fatalf("status = %+v", s)
	}

	p, err := openProvider()
	if err != nil {
		t.Fatal(err)
	}
	defer freeObject(p)
	var buf [512]byte
	var n uint32
	r, _, _ := procGetProperty.Call(p, uintptr(unsafe.Pointer(utf16Ptr("PCP_PLATFORM_TYPE"))),
		uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), uintptr(unsafe.Pointer(&n)), ncryptSilentFlag)
	if uint32(r) != 0 {
		t.Logf("PCP_PLATFORM_TYPE: status 0x%08X", uint32(r))
		return
	}
	t.Logf("PCP_PLATFORM_TYPE = %s", windows.UTF16ToString(unsafe.Slice((*uint16)(unsafe.Pointer(&buf[0])), n/2)))
}

// 验证 1：create → pub → sign，Go crypto/ecdsa 验签，篡改后失败。
func TestSignVerifiesWithGoECDSA(t *testing.T) {
	h := startHelper(t)
	h.requireTPM()
	name := newName(t)

	start := time.Now()
	created := createKeys(t, h, name)
	t.Logf("create took %v", time.Since(start).Round(time.Millisecond))

	if len(created) != 65 || created[0] != 0x04 {
		t.Fatalf("authPub: %d bytes, first 0x%02x", len(created), created[0])
	}
	var res pubResult
	h.mustCall("pub", map[string]string{"name": name}, &res)
	pub := decode(t, res.AuthPub)
	if !bytes.Equal(pub, created) {
		t.Fatal("pub differs from create")
	}

	data := []byte("mixia/request/v1\nGET /v1/ledger")
	sig := sign(t, h, name, data)
	if !verify(t, pub, data, sig) {
		t.Fatal("valid signature rejected")
	}

	tampered := bytes.Clone(data)
	tampered[0] ^= 1
	if verify(t, pub, tampered, sig) {
		t.Fatal("signature verified against tampered data")
	}
	badSig := bytes.Clone(sig)
	badSig[10] ^= 1
	if verify(t, pub, data, badSig) {
		t.Fatal("tampered signature verified")
	}

	for _, size := range []int{0, maxSignData} {
		big := bytes.Repeat([]byte{0x5A}, size)
		if !verify(t, pub, big, sign(t, h, name, big)) {
			t.Fatalf("signature over %d bytes rejected", size)
		}
	}
	h.requireError("sign", map[string]string{
		"name": name, "data": b64.EncodeToString(make([]byte, maxSignData+1)),
	}, codeBadRequest)
}

// 验证 2：seal → unseal 还原；篡改解不开；另一把密钥解不开。
func TestSealUnseal(t *testing.T) {
	h := startHelper(t)
	h.requireTPM()
	name, other := newName(t), newName(t)
	createKeys(t, h, name)
	createKeys(t, h, other)

	secret := make([]byte, 32)
	rand.Read(secret)
	sealed := seal(t, h, name, secret)
	t.Logf("seal alg = %s", sealed.Alg)
	if sealed.Alg != algOAEPSHA256 && sealed.Alg != algOAEPSHA1 {
		t.Fatalf("alg = %q", sealed.Alg)
	}
	if n := len(decode(t, sealed.Blob)); n != sealBlobLen {
		t.Fatalf("blob is %d bytes", n)
	}
	if bytes.Contains(decode(t, sealed.Blob), secret) {
		t.Fatal("blob contains the plaintext")
	}
	if !bytes.Equal(unseal(t, h, name, sealed), secret) {
		t.Fatal("unseal did not restore the secret")
	}

	var noAlg unsealResult
	h.mustCall("unseal", map[string]string{"name": name, "blob": sealed.Blob}, &noAlg)
	if !bytes.Equal(decode(t, noAlg.Data), secret) {
		t.Fatal("unseal without alg did not restore the secret")
	}

	for _, size := range []int{0, 1, 31, maxSealData} {
		data := make([]byte, size)
		rand.Read(data)
		r := h.call("seal", map[string]string{"name": name, "data": b64.EncodeToString(data)})
		if !r.OK {
			t.Errorf("seal %d bytes: %s %s", size, r.Error, r.Message)
			continue
		}
		var s sealResult
		json.Unmarshal(r.Result, &s)
		if !bytes.Equal(unseal(t, h, name, s), data) {
			t.Errorf("round trip of %d bytes failed", size)
		}
	}
	h.requireError("seal", map[string]string{
		"name": name, "data": b64.EncodeToString(make([]byte, maxSealData+1)),
	}, codeBadRequest)

	blob := decode(t, sealed.Blob)
	for _, pos := range []int{0, 1, 128, 255} {
		bad := bytes.Clone(blob)
		bad[pos] ^= 0x01
		r := h.requireError("unseal", map[string]string{
			"name": name, "blob": b64.EncodeToString(bad), "alg": sealed.Alg,
		}, codeFailed)
		t.Logf("tampered byte %d: %s", pos, r.Message)
	}

	r := h.requireError("unseal", map[string]string{"name": other, "blob": sealed.Blob, "alg": sealed.Alg}, codeFailed)
	t.Logf("wrong key: %s", r.Message)

	wrongAlg := algOAEPSHA1
	if sealed.Alg == algOAEPSHA1 {
		wrongAlg = algOAEPSHA256
	}
	r = h.requireError("unseal", map[string]string{"name": name, "blob": sealed.Blob, "alg": wrongAlg}, codeFailed)
	t.Logf("wrong alg: %s", r.Message)

	// 连续失败不能把 TPM 锁住或破坏密钥。
	if !bytes.Equal(unseal(t, h, name, sealed), secret) {
		t.Fatal("unseal broke after failed attempts")
	}
}

// 实测 OAEP 各 hash 在这颗 TPM 上的支持情况：Go 用公钥加密，TPM 解密。
func TestOAEPHashMatrix(t *testing.T) {
	h := startHelper(t)
	h.requireTPM()
	name := newName(t)
	createKeys(t, h, name)

	p, err := openProvider()
	if err != nil {
		t.Fatal(err)
	}
	defer freeObject(p)
	k, err := openKey(p, sealKeyName(name))
	if err != nil {
		t.Fatal(err)
	}
	defer freeObject(k)
	pub, err := exportRSAPub(k)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("seal key: %d-bit modulus, e=%d", pub.N.BitLen(), pub.E)

	secret := []byte("0123456789abcdef0123456789abcdef")
	working := 0
	for _, tc := range []struct {
		alg     string
		cng     *uint16
		newHash func() hash.Hash
	}{
		{algOAEPSHA256, hashAlgSHA256W, sha256.New},
		{algOAEPSHA1, hashAlgSHA1W, sha1.New},
	} {
		pad := &oaepPaddingInfo{algID: tc.cng}
		blob, err := ncryptEncrypt(k, secret, pad)
		t.Logf("%s: NCryptEncrypt err=%v len=%d", tc.alg, err, len(blob))
		if err == nil {
			back, err := ncryptDecrypt(k, blob, pad)
			t.Logf("%s: NCryptDecrypt of NCryptEncrypt blob: err=%v match=%v", tc.alg, err, bytes.Equal(back, secret))
		}

		goBlob, err := rsa.EncryptOAEP(tc.newHash(), rand.Reader, pub, secret, nil)
		if err != nil {
			t.Fatal(err)
		}
		back, err := ncryptDecrypt(k, goBlob, pad)
		t.Logf("%s: NCryptDecrypt of Go EncryptOAEP blob: err=%v match=%v", tc.alg, err, bytes.Equal(back, secret))
		if err == nil && bytes.Equal(back, secret) {
			working++
		}
	}
	if working == 0 {
		t.Fatal("TPM cannot decrypt any OAEP hash")
	}
}

// 本机 SHA-256 能用，回退路径平时走不到。注入一个不存在的 hash 名让第一候选失败：
// NCryptEncrypt 报错 → 转 Go 加密 → TPM 解密失败 → 回退到 SHA-1。
func TestSealFallsBackWhenFirstHashFails(t *testing.T) {
	h := startHelper(t)
	h.requireTPM()
	name := newName(t)
	createKeys(t, h, name)

	saved := oaepCandidates
	defer func() { oaepCandidates = saved }()
	oaepCandidates = []oaepAlg{
		{"oaep-broken", utf16Ptr("NOT-A-HASH"), sha256.New},
		saved[1],
	}

	b := ncryptBackend{}
	secret := []byte("0123456789abcdef0123456789abcdef")
	blob, alg, err := b.Seal(name, secret)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if alg != algOAEPSHA1 {
		t.Fatalf("alg = %s, want %s", alg, algOAEPSHA1)
	}
	back, err := b.Unseal(name, blob, alg)
	if err != nil || !bytes.Equal(back, secret) {
		t.Fatalf("unseal: %v", err)
	}

	// alg 不在候选里时必须报错，不能返回“成功 + 空数据”。
	if d, err := b.Unseal(name, blob, algOAEPSHA256); err == nil {
		t.Fatalf("unknown alg returned success with %d bytes", len(d))
	}

	// 所有候选都失败时报错，不产出解不开的 blob。
	oaepCandidates = oaepCandidates[:1]
	if _, _, err := b.Seal(name, secret); err == nil {
		t.Fatal("seal succeeded with no working hash")
	} else {
		t.Logf("no working hash: %v", err)
	}
}

func rawExport(key uintptr, blobType string, flags uintptr) (sizeStatus, dataStatus, n uint32) {
	bt := utf16Ptr(blobType)
	r, _, _ := procExportKey.Call(key, 0, uintptr(unsafe.Pointer(bt)), 0, 0, 0,
		uintptr(unsafe.Pointer(&n)), flags)
	sizeStatus = uint32(r)

	// 大小查询成功不代表能导出，所以无论如何都用真实缓冲区再试一次。
	buf := make([]byte, 8192)
	r, _, _ = procExportKey.Call(key, 0, uintptr(unsafe.Pointer(bt)), 0,
		uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), uintptr(unsafe.Pointer(&n)), flags)
	return sizeStatus, uint32(r), n
}

func rawSetU32(h uintptr, prop string, v uint32) uint32 {
	r, _, _ := procSetProperty.Call(h, uintptr(unsafe.Pointer(utf16Ptr(prop))),
		uintptr(unsafe.Pointer(&v)), 4, 0)
	return uint32(r)
}

const allowPlaintextExport = 0x3 // NCRYPT_ALLOW_EXPORT_FLAG | NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG

// 验证 3：私钥不可导出。对照组先证明同一个探测函数确实能导出可导出的私钥，
// 否则“导出失败”可能只是探测函数本身写错了。
func TestPrivateKeysCannotBeExported(t *testing.T) {
	h := startHelper(t)
	h.requireTPM()
	name := newName(t)
	createKeys(t, h, name)

	t.Run("control: software key with export allowed", func(t *testing.T) {
		var sw, k uintptr
		r, _, _ := procOpenStorageProvider.Call(uintptr(unsafe.Pointer(&sw)),
			uintptr(unsafe.Pointer(utf16Ptr("Microsoft Software Key Storage Provider"))), 0)
		if uint32(r) != 0 {
			t.Fatalf("open software KSP: 0x%08X", uint32(r))
		}
		defer freeObject(sw)
		// 密钥名为 NULL：临时密钥，只在内存，不落盘。
		r, _, _ = procCreatePersistedKey.Call(sw, uintptr(unsafe.Pointer(&k)), uintptr(unsafe.Pointer(algECDSAP256W)), 0, 0, 0)
		if uint32(r) != 0 {
			t.Fatalf("create: 0x%08X", uint32(r))
		}
		defer freeObject(k)
		if s := rawSetU32(k, "Export Policy", allowPlaintextExport); s != 0 {
			t.Fatalf("set export policy: 0x%08X", s)
		}
		r, _, _ = procFinalizeKey.Call(k, 0)
		if uint32(r) != 0 {
			t.Fatalf("finalize: 0x%08X", uint32(r))
		}
		for _, blob := range []string{"ECCPRIVATEBLOB", "PKCS8_PRIVATEKEY"} {
			size, data, n := rawExport(k, blob, ncryptSilentFlag)
			t.Logf("%s: size=0x%08X data=0x%08X bytes=%d", blob, size, data, n)
			if size != 0 || data != 0 || n == 0 {
				t.Fatalf("control failed: probe cannot export %s", blob)
			}
		}
	})

	p, err := openProvider()
	if err != nil {
		t.Fatal(err)
	}
	defer freeObject(p)

	for _, tc := range []struct {
		keyName string
		public  *uint16
		blobs   []string
	}{
		{authKeyName(name), blobECCPublicW, []string{"ECCPRIVATEBLOB", "PKCS8_PRIVATEKEY", "PRIVATEBLOB"}},
		{sealKeyName(name), blobRSAPublicW, []string{"RSAPRIVATEBLOB", "RSAFULLPRIVATEBLOB", "PKCS8_PRIVATEKEY", "PRIVATEBLOB"}},
	} {
		kind := tc.keyName[:len("Mixia-Auth")]
		t.Run(kind, func(t *testing.T) {
			k, err := openKey(p, tc.keyName)
			if err != nil {
				t.Fatal(err)
			}
			defer freeObject(k)

			if _, err := exportKey(k, tc.public); err != nil {
				t.Fatalf("public export must work: %v", err)
			}
			policy, err := getPropertyU32(k, utf16Ptr("Export Policy"))
			t.Logf("Export Policy = 0x%X (err=%v)", policy, err)
			if err == nil && policy != 0 {
				t.Errorf("export policy is 0x%X, want 0", policy)
			}
			usage, err := getPropertyU32(k, utf16Ptr("Key Usage"))
			t.Logf("Key Usage = 0x%X (err=%v)", usage, err)

			check := func(stage string) {
				for _, blob := range tc.blobs {
					// 两种 flags 都试：PCP 对个别 blob 类型不接受 silent，
					// 不能让标志错误掩盖真实结果。
					for _, flags := range []uintptr{ncryptSilentFlag, 0} {
						size, data, n := rawExport(k, blob, flags)
						t.Logf("%s %s flags=0x%X: size=0x%08X data=0x%08X", stage, blob, flags, size, data)
						if data == 0 {
							t.Errorf("%s: private key exported as %s (%d bytes)", stage, blob, n)
						}
					}
				}
			}
			check("default")

			s := rawSetU32(k, "Export Policy", allowPlaintextExport)
			t.Logf("raising Export Policy on the finalized key: 0x%08X", s)
			check("after raise attempt")
		})
	}

	// 把策略放开再建：如果 PCP 仍然不导出，就说明靠的是硬件，不只是策略位。
	t.Run("PCP key requested with export allowed", func(t *testing.T) {
		keyName := authKeyName(newName(t))
		var k uintptr
		r, _, _ := procCreatePersistedKey.Call(p, uintptr(unsafe.Pointer(&k)), uintptr(unsafe.Pointer(algECDSAP256W)),
			uintptr(unsafe.Pointer(utf16Ptr(keyName))), 0, 0)
		if uint32(r) != 0 {
			t.Fatalf("create: 0x%08X", uint32(r))
		}
		defer freeObject(k)
		t.Cleanup(func() {
			if _, err := deleteKey(p, keyName); err != nil {
				t.Errorf("cleanup: %v", err)
			}
		})
		t.Logf("set Export Policy before finalize: 0x%08X", rawSetU32(k, "Export Policy", allowPlaintextExport))
		r, _, _ = procFinalizeKey.Call(k, 0)
		t.Logf("finalize: 0x%08X", uint32(r))
		if uint32(r) != 0 {
			return
		}
		for _, blob := range []string{"ECCPRIVATEBLOB", "PKCS8_PRIVATEKEY"} {
			size, data, n := rawExport(k, blob, 0)
			t.Logf("%s: size=0x%08X data=0x%08X", blob, size, data)
			if data == 0 {
				t.Errorf("private key exported as %s (%d bytes)", blob, n)
			}
		}
	})
}

// tpmPublicArea 从 PCP 的 opaque blob（PCP_KEY_BLOB_WIN8 头 + TPM2B_PUBLIC）取出
// TPM 对象的类型和属性。这里只读公开区；私有区是被 TPM 包裹的，测试不触碰也不打印。
func tpmPublicArea(t *testing.T, key uintptr) (objType uint16, attrs uint32) {
	t.Helper()
	blob := make([]byte, 8192)
	var n uint32
	r, _, _ := procExportKey.Call(key, 0, uintptr(unsafe.Pointer(utf16Ptr("OpaqueKeyBlob"))), 0,
		uintptr(unsafe.Pointer(&blob[0])), uintptr(len(blob)), uintptr(unsafe.Pointer(&n)), 0)
	if uint32(r) != 0 {
		t.Fatalf("export opaque blob: 0x%08X", uint32(r))
	}
	blob = blob[:n]
	if len(blob) < 20 || binary.LittleEndian.Uint32(blob) != 0x4D504350 { // BCRYPT_PCP_KEY_MAGIC
		t.Fatalf("not a PCP key blob (%d bytes)", len(blob))
	}
	header := binary.LittleEndian.Uint32(blob[4:])
	cbPublic := binary.LittleEndian.Uint32(blob[16:])
	pub := blob[header : header+cbPublic]
	if int(binary.BigEndian.Uint16(pub))+2 != len(pub) {
		t.Fatalf("public area is not a TPM2B_PUBLIC (%d bytes)", len(pub))
	}
	pub = pub[2:] // TPMT_PUBLIC: type u16, nameAlg u16, objectAttributes u32
	if alg := binary.BigEndian.Uint16(pub[2:]); alg != 0x000B {
		t.Fatalf("nameAlg = 0x%04X, want SHA-256", alg)
	}
	return binary.BigEndian.Uint16(pub), binary.BigEndian.Uint32(pub[4:])
}

// 比 NCryptExportKey 失败更硬的证据：TPM 自己把对象标成不可复制。
// fixedTPM + fixedParent 意味着 TPM 拒绝 TPM2_Duplicate，
// sensitiveDataOrigin 意味着私钥在 TPM 内生成，从未存在于 TPM 之外。
func TestKeysAreFixedToThisTPM(t *testing.T) {
	const (
		fixedTPM            = 1 << 1
		fixedParent         = 1 << 4
		sensitiveDataOrigin = 1 << 5
		decrypt             = 1 << 17
		sign                = 1 << 18
		tpmAlgRSA           = 0x0001
		tpmAlgECC           = 0x0023
	)
	h := startHelper(t)
	h.requireTPM()
	name := newName(t)
	createKeys(t, h, name)

	p, err := openProvider()
	if err != nil {
		t.Fatal(err)
	}
	defer freeObject(p)

	for _, tc := range []struct {
		keyName  string
		wantType uint16
		allowed  uint32
		denied   uint32
	}{
		{authKeyName(name), tpmAlgECC, sign, decrypt},
		{sealKeyName(name), tpmAlgRSA, decrypt, sign},
	} {
		k, err := openKey(p, tc.keyName)
		if err != nil {
			t.Fatal(err)
		}
		defer freeObject(k)
		objType, attrs := tpmPublicArea(t, k)
		t.Logf("%s: type=0x%04X objectAttributes=0x%08X fixedTPM=%v fixedParent=%v sensitiveDataOrigin=%v sign=%v decrypt=%v",
			tc.keyName[:len("Mixia-Auth")], objType, attrs,
			attrs&fixedTPM != 0, attrs&fixedParent != 0, attrs&sensitiveDataOrigin != 0,
			attrs&sign != 0, attrs&decrypt != 0)
		if objType != tc.wantType {
			t.Errorf("type = 0x%04X, want 0x%04X", objType, tc.wantType)
		}
		const required = fixedTPM | fixedParent | sensitiveDataOrigin
		if attrs&required != required {
			t.Errorf("objectAttributes 0x%08X lack fixedTPM/fixedParent/sensitiveDataOrigin", attrs)
		}
		if attrs&tc.allowed == 0 || attrs&tc.denied != 0 {
			t.Errorf("objectAttributes 0x%08X have the wrong usage bits", attrs)
		}
	}
}

// Seal 密钥只允许解密：它不该能被当成 RSA 签名器使用。
func TestSealKeyCannotSign(t *testing.T) {
	h := startHelper(t)
	h.requireTPM()
	name := newName(t)
	createKeys(t, h, name)

	p, err := openProvider()
	if err != nil {
		t.Fatal(err)
	}
	defer freeObject(p)
	k, err := openKey(p, sealKeyName(name))
	if err != nil {
		t.Fatal(err)
	}
	defer freeObject(k)

	type pkcs1PaddingInfo struct{ algID *uint16 }
	const ncryptPadPKCS1Flag = 0x2
	pad := &pkcs1PaddingInfo{hashAlgSHA256W}
	digest := sha256.Sum256([]byte("x"))
	out := make([]byte, 256)
	var n uint32
	r, _, _ := procSignHash.Call(k, uintptr(unsafe.Pointer(pad)),
		uintptr(unsafe.Pointer(&digest[0])), uintptr(len(digest)),
		uintptr(unsafe.Pointer(&out[0])), uintptr(len(out)),
		uintptr(unsafe.Pointer(&n)), ncryptSilentFlag|ncryptPadPKCS1Flag)
	t.Logf("NCryptSignHash with seal key: 0x%08X", uint32(r))
	if uint32(r) == 0 {
		t.Fatal("seal key produced a signature")
	}
}

// 验证 4：换一个进程后 pub 和 unseal 仍可用。
func TestKeysSurviveProcessRestart(t *testing.T) {
	first := startHelper(t)
	first.requireTPM()
	name := newName(t)
	pub := createKeys(t, first, name)
	secret := []byte("device-secret-for-restart-test-!")
	sealed := seal(t, first, name, secret)
	firstPID := first.cmd.Process.Pid
	first.close()

	second := startHelper(t)
	if second.cmd.Process.Pid == firstPID {
		t.Fatal("expected a new process")
	}
	var res pubResult
	second.mustCall("pub", map[string]string{"name": name}, &res)
	if !bytes.Equal(decode(t, res.AuthPub), pub) {
		t.Fatal("pub changed across restart")
	}
	if !bytes.Equal(unseal(t, second, name, sealed), secret) {
		t.Fatal("unseal failed across restart")
	}
	data := []byte("after restart")
	if !verify(t, pub, data, sign(t, second, name, data)) {
		t.Fatal("signature after restart does not verify")
	}
}

// 验证 5：delete 后 sign 返回 no_key。
func TestDeleteRemovesBothKeys(t *testing.T) {
	h := startHelper(t)
	h.requireTPM()
	name := newName(t)
	createKeys(t, h, name)
	sealed := seal(t, h, name, []byte("secret"))

	var res deleteResult
	h.mustCall("delete", map[string]string{"name": name}, &res)
	if !res.Auth || !res.Seal {
		t.Fatalf("delete = %+v", res)
	}

	args := map[string]string{"name": name}
	r := h.requireError("sign", map[string]string{"name": name, "data": "aGk"}, codeNoKey)
	t.Logf("sign after delete: %s", r.Message)
	h.requireError("pub", args, codeNoKey)
	h.requireError("seal", map[string]string{"name": name, "data": "aGk"}, codeNoKey)
	h.requireError("unseal", map[string]string{"name": name, "blob": sealed.Blob, "alg": sealed.Alg}, codeNoKey)
	h.requireError("delete", args, codeNoKey)

	keys, err := listPCPKeys()
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range keys {
		if strings.HasSuffix(k, name) {
			t.Fatalf("key still listed: %s", k)
		}
	}
}

func TestCreateNeverTouchesExistingKeys(t *testing.T) {
	h := startHelper(t)
	h.requireTPM()
	name := newName(t)
	pub := createKeys(t, h, name)
	secret := []byte("must survive a second create")
	sealed := seal(t, h, name, secret)

	r := h.requireError("create", map[string]string{"name": name}, codeExists)
	t.Logf("second create: %s", r.Message)
	if !strings.Contains(r.Message, "0x8009000F") {
		t.Fatalf("message lacks raw SECURITY_STATUS: %s", r.Message)
	}
	var res pubResult
	h.mustCall("pub", map[string]string{"name": name}, &res)
	if !bytes.Equal(decode(t, res.AuthPub), pub) {
		t.Fatal("second create replaced the auth key")
	}

	// 半套状态：只剩 Seal 密钥。create 先建出 Auth，再因 Seal 已存在而失败：
	// 必须报 exists，回滚新建的 Auth，并且不能破坏已有的 Seal。
	p, err := openProvider()
	if err != nil {
		t.Fatal(err)
	}
	defer freeObject(p)
	if ok, err := deleteKey(p, authKeyName(name)); !ok || err != nil {
		t.Fatalf("delete auth: %v %v", ok, err)
	}
	h.requireError("create", map[string]string{"name": name}, codeExists)
	h.requireError("pub", map[string]string{"name": name}, codeNoKey)
	if !bytes.Equal(unseal(t, h, name, sealed), secret) {
		t.Fatal("create damaged the existing seal key")
	}

	var del deleteResult
	h.mustCall("delete", map[string]string{"name": name}, &del)
	if del.Auth || !del.Seal {
		t.Fatalf("partial delete = %+v", del)
	}
}

func TestLongestNameWorks(t *testing.T) {
	h := startHelper(t)
	h.requireTPM()
	name := strings.Repeat("a", 32) + newName(t) + "bbbbbbbbbb"
	if len(name) != 64 {
		t.Fatalf("name length %d", len(name))
	}
	pub := createKeys(t, h, name)
	data := []byte("x")
	if !verify(t, pub, data, sign(t, h, name, data)) {
		t.Fatal("signature rejected")
	}
}

// name 是 base64url，大小写有意义，只差大小写的两个 name 不能撞到同一把密钥。
func TestKeyNamesAreCaseSensitive(t *testing.T) {
	h := startHelper(t)
	h.requireTPM()
	name := "CaseAb" + newName(t)
	createKeys(t, h, name)

	swapped := []rune(name)
	for i, c := range swapped {
		switch {
		case c >= 'a' && c <= 'z':
			swapped[i] = c - 32
		case c >= 'A' && c <= 'Z':
			swapped[i] = c + 32
		}
	}
	h.requireError("pub", map[string]string{"name": string(swapped)}, codeNoKey)
}

func median(d []time.Duration) time.Duration {
	s := slices.Sorted(slices.Values(d))
	if len(s)%2 == 1 {
		return s[len(s)/2]
	}
	return (s[len(s)/2-1] + s[len(s)/2]) / 2
}

func report(t *testing.T, label string, d []time.Duration) {
	t.Helper()
	t.Logf("%s: median %v, min %v, max %v, samples %v", label,
		median(d).Round(10*time.Microsecond), slices.Min(d).Round(10*time.Microsecond),
		slices.Max(d).Round(10*time.Microsecond), d)
}

// 验证 6：计时。走完整链路（JSON → 管道 → NCrypt → TPM → 管道 → JSON），各 10 次取中位数。
func TestTiming(t *testing.T) {
	h := startHelper(t)
	h.requireTPM()
	name := newName(t)
	createKeys(t, h, name)
	secret := make([]byte, 32)
	rand.Read(secret)
	sealed := seal(t, h, name, secret)
	data := make([]byte, 1024)

	const rounds = 10
	var signs, unseals []time.Duration
	for range rounds {
		start := time.Now()
		sign(t, h, name, data)
		signs = append(signs, time.Since(start))
	}
	for range rounds {
		start := time.Now()
		unseal(t, h, name, sealed)
		unseals = append(unseals, time.Since(start))
	}
	report(t, "sign", signs)
	report(t, "unseal", unseals)
}

// r 或 s 高位为 0 的概率约 1/128。用 MIXIA_HWKEY_SOAK=<次数> 运行，确认这种情况下
// 签名仍是定长 64 字节且可验证。默认跳过，因为要跑上千次 TPM 操作。
func TestSignaturesStayFixedWidth(t *testing.T) {
	count, _ := strconv.Atoi(os.Getenv("MIXIA_HWKEY_SOAK"))
	if count == 0 {
		t.Skip("set MIXIA_HWKEY_SOAK to run")
	}
	h := startHelper(t)
	h.requireTPM()
	name := newName(t)
	pub := createKeys(t, h, name)

	leadingZero := 0
	data := make([]byte, 32)
	for i := range count {
		rand.Read(data)
		sig := sign(t, h, name, data)
		if !verify(t, pub, data, sig) {
			t.Fatalf("signature %d rejected", i)
		}
		if sig[0] == 0 || sig[32] == 0 {
			leadingZero++
		}
	}
	t.Logf("%d signatures verified, %d with a leading zero byte in r or s", count, leadingZero)
}
