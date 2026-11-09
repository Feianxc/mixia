//go:build windows

package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"math/big"
	"unsafe"

	"golang.org/x/sys/windows"
)

// 所有 ncrypt 调用都直接写 proc.Call(uintptr(unsafe.Pointer(...)))，不要包一层通用
// 函数：LazyProc.Call 的 //go:uintptrescapes 只保护直接写在实参列表里的转换，
// 经过 wrapper 后栈上变量可能在调用途中被移动。

var (
	modncrypt = windows.NewLazySystemDLL("ncrypt.dll")

	procOpenStorageProvider = modncrypt.NewProc("NCryptOpenStorageProvider")
	procIsAlgSupported      = modncrypt.NewProc("NCryptIsAlgSupported")
	procCreatePersistedKey  = modncrypt.NewProc("NCryptCreatePersistedKey")
	procOpenKey             = modncrypt.NewProc("NCryptOpenKey")
	procSetProperty         = modncrypt.NewProc("NCryptSetProperty")
	procGetProperty         = modncrypt.NewProc("NCryptGetProperty")
	procFinalizeKey         = modncrypt.NewProc("NCryptFinalizeKey")
	procExportKey           = modncrypt.NewProc("NCryptExportKey")
	procSignHash            = modncrypt.NewProc("NCryptSignHash")
	procEncrypt             = modncrypt.NewProc("NCryptEncrypt")
	procDecrypt             = modncrypt.NewProc("NCryptDecrypt")
	procDeleteKey           = modncrypt.NewProc("NCryptDeleteKey")
	procFreeObject          = modncrypt.NewProc("NCryptFreeObject")
)

const (
	ncryptSilentFlag       = 0x00000040
	ncryptPadOAEPFlag      = 0x00000004
	pcpSignatureKey        = 0x00000001 // NCRYPT_PCP_SIGNATURE_KEY
	pcpEncryptionKey       = 0x00000002 // NCRYPT_PCP_ENCRYPTION_KEY
	ncryptImplHardwareFlag = 0x00000001

	eccPublicP256Magic = 0x31534345 // BCRYPT_ECDSA_PUBLIC_P256_MAGIC "ECS1"
	rsaPublicMagic     = 0x31415352 // BCRYPT_RSAPUBLIC_MAGIC "RSA1"

	rsaKeyBits = 2048
	p256Size   = 32
)

var (
	providerNameW   = utf16Ptr(providerName)
	algECDSAP256W   = utf16Ptr("ECDSA_P256")
	algRSAW         = utf16Ptr("RSA")
	propLengthW     = utf16Ptr("Length")
	propPCPUsageW   = utf16Ptr("PCP_KEY_USAGE_POLICY")
	propImplTypeW   = utf16Ptr("Impl Type")
	blobECCPublicW  = utf16Ptr("ECCPUBLICBLOB")
	blobRSAPublicW  = utf16Ptr("RSAPUBLICBLOB")
	hashAlgSHA256W  = utf16Ptr("SHA256")
	hashAlgSHA1W    = utf16Ptr("SHA1")
	oaepCandidates  = []oaepAlg{{algOAEPSHA256, hashAlgSHA256W, sha256.New}, {algOAEPSHA1, hashAlgSHA1W, sha1.New}}
	errSealMismatch = &apiError{codeFailed, "seal self-check returned different data"}
)

// oaepPaddingInfo 对应 BCRYPT_OAEP_PADDING_INFO。x64 下 8+8+4 再补 4 字节，共 24 字节，
// 与 Go 对这个结构的布局一致。
type oaepPaddingInfo struct {
	algID   *uint16
	label   *byte
	labelSz uint32
}

type oaepAlg struct {
	name    string
	cngHash *uint16
	newHash func() hash.Hash
}

func (a oaepAlg) padding() *oaepPaddingInfo { return &oaepPaddingInfo{algID: a.cngHash} }

func utf16Ptr(s string) *uint16 {
	p, err := windows.UTF16PtrFromString(s)
	if err != nil {
		panic(err)
	}
	return p
}

func authKeyName(name string) string { return "Mixia-Auth-" + name }
func sealKeyName(name string) string { return "Mixia-Seal-" + name }

func statusErr(op string, r uintptr) error {
	status := uint32(r)
	if status == 0 {
		return nil
	}
	return &apiError{statusCode(status), fmt.Sprintf("%s: SECURITY_STATUS 0x%08X", op, status)}
}

func hasCode(err error, code string) bool {
	var ae *apiError
	return errors.As(err, &ae) && ae.code == code
}

func openProvider() (uintptr, error) {
	var h uintptr
	r, _, _ := procOpenStorageProvider.Call(
		uintptr(unsafe.Pointer(&h)), uintptr(unsafe.Pointer(providerNameW)), 0)
	return h, statusErr("NCryptOpenStorageProvider", r)
}

func freeObject(h uintptr) {
	if h != 0 {
		procFreeObject.Call(h)
	}
}

func openKey(provider uintptr, keyName string) (uintptr, error) {
	var h uintptr
	r, _, _ := procOpenKey.Call(
		provider, uintptr(unsafe.Pointer(&h)), uintptr(unsafe.Pointer(utf16Ptr(keyName))),
		0, ncryptSilentFlag)
	return h, statusErr("NCryptOpenKey", r)
}

func getPropertyU32(h uintptr, prop *uint16) (uint32, error) {
	var v, n uint32
	r, _, _ := procGetProperty.Call(
		h, uintptr(unsafe.Pointer(prop)), uintptr(unsafe.Pointer(&v)), 4,
		uintptr(unsafe.Pointer(&n)), ncryptSilentFlag)
	if err := statusErr("NCryptGetProperty", r); err != nil {
		return 0, err
	}
	if n != 4 {
		return 0, &apiError{codeFailed, "NCryptGetProperty: unexpected property size"}
	}
	return v, nil
}

func setPropertyU32(h uintptr, prop *uint16, v uint32) error {
	r, _, _ := procSetProperty.Call(
		h, uintptr(unsafe.Pointer(prop)), uintptr(unsafe.Pointer(&v)), 4, ncryptSilentFlag)
	return statusErr("NCryptSetProperty", r)
}

func exportKey(key uintptr, blobType *uint16) ([]byte, error) {
	var n uint32
	r, _, _ := procExportKey.Call(
		key, 0, uintptr(unsafe.Pointer(blobType)), 0, 0, 0,
		uintptr(unsafe.Pointer(&n)), ncryptSilentFlag)
	if err := statusErr("NCryptExportKey", r); err != nil {
		return nil, err
	}
	buf := make([]byte, n)
	r, _, _ = procExportKey.Call(
		key, 0, uintptr(unsafe.Pointer(blobType)), 0,
		uintptr(unsafe.Pointer(unsafe.SliceData(buf))), uintptr(n),
		uintptr(unsafe.Pointer(&n)), ncryptSilentFlag)
	if err := statusErr("NCryptExportKey", r); err != nil {
		return nil, err
	}
	return buf[:n], nil
}

func createKey(provider uintptr, alg *uint16, keyName string, usage, bits uint32) error {
	var k uintptr
	r, _, _ := procCreatePersistedKey.Call(
		provider, uintptr(unsafe.Pointer(&k)), uintptr(unsafe.Pointer(alg)),
		uintptr(unsafe.Pointer(utf16Ptr(keyName))), 0, 0)
	if err := statusErr("NCryptCreatePersistedKey", r); err != nil {
		return err
	}
	defer freeObject(k)

	if bits != 0 {
		if err := setPropertyU32(k, propLengthW, bits); err != nil {
			return err
		}
	}
	if err := setPropertyU32(k, propPCPUsageW, usage); err != nil {
		return err
	}
	r, _, _ = procFinalizeKey.Call(k, ncryptSilentFlag)
	return statusErr("NCryptFinalizeKey", r)
}

// deleteKey 删除一把密钥，返回它是否存在过。
func deleteKey(provider uintptr, keyName string) (bool, error) {
	k, err := openKey(provider, keyName)
	if hasCode(err, codeNoKey) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	// dwFlags 必须是 0：文档列了 NCRYPT_SILENT_FLAG，但 PCP 实测返回 NTE_BAD_FLAGS。
	r, _, _ := procDeleteKey.Call(k, 0)
	if err := statusErr("NCryptDeleteKey", r); err != nil {
		freeObject(k) // 只有失败时句柄才还属于我们；成功时已被 NCryptDeleteKey 释放
		return false, err
	}
	return true, nil
}

func eccBlobToPoint(blob []byte) ([]byte, error) {
	if len(blob) != 8+2*p256Size ||
		binary.LittleEndian.Uint32(blob[0:]) != eccPublicP256Magic ||
		binary.LittleEndian.Uint32(blob[4:]) != p256Size {
		return nil, &apiError{codeFailed, "unexpected ECC public key blob"}
	}
	point := make([]byte, 1+2*p256Size)
	point[0] = 0x04
	copy(point[1:], blob[8:])
	return point, nil
}

func exportAuthPub(key uintptr) ([]byte, error) {
	blob, err := exportKey(key, blobECCPublicW)
	if err != nil {
		return nil, err
	}
	return eccBlobToPoint(blob)
}

func exportRSAPub(key uintptr) (*rsa.PublicKey, error) {
	blob, err := exportKey(key, blobRSAPublicW)
	if err != nil {
		return nil, err
	}
	bad := &apiError{codeFailed, "unexpected RSA public key blob"}
	const header = 24 // BCRYPT_RSAKEY_BLOB
	if len(blob) < header || binary.LittleEndian.Uint32(blob[0:]) != rsaPublicMagic {
		return nil, bad
	}
	cbExp := int(binary.LittleEndian.Uint32(blob[8:]))
	cbMod := int(binary.LittleEndian.Uint32(blob[12:]))
	if cbExp <= 0 || cbExp > 8 || cbMod != rsaKeyBits/8 || len(blob) != header+cbExp+cbMod {
		return nil, bad
	}
	exp := new(big.Int).SetBytes(blob[header : header+cbExp])
	if !exp.IsInt64() {
		return nil, bad
	}
	return &rsa.PublicKey{
		N: new(big.Int).SetBytes(blob[header+cbExp:]),
		E: int(exp.Int64()),
	}, nil
}

func ncryptEncrypt(key uintptr, data []byte, pad *oaepPaddingInfo) ([]byte, error) {
	out := make([]byte, rsaKeyBits/8)
	var n uint32
	r, _, _ := procEncrypt.Call(
		key, uintptr(unsafe.Pointer(unsafe.SliceData(data))), uintptr(len(data)),
		uintptr(unsafe.Pointer(pad)),
		uintptr(unsafe.Pointer(unsafe.SliceData(out))), uintptr(len(out)),
		uintptr(unsafe.Pointer(&n)), ncryptSilentFlag|ncryptPadOAEPFlag)
	if err := statusErr("NCryptEncrypt", r); err != nil {
		return nil, err
	}
	return out[:n], nil
}

func ncryptDecrypt(key uintptr, blob []byte, pad *oaepPaddingInfo) ([]byte, error) {
	out := make([]byte, rsaKeyBits/8)
	var n uint32
	r, _, _ := procDecrypt.Call(
		key, uintptr(unsafe.Pointer(unsafe.SliceData(blob))), uintptr(len(blob)),
		uintptr(unsafe.Pointer(pad)),
		uintptr(unsafe.Pointer(unsafe.SliceData(out))), uintptr(len(out)),
		uintptr(unsafe.Pointer(&n)), ncryptSilentFlag|ncryptPadOAEPFlag)
	if err := statusErr("NCryptDecrypt", r); err != nil {
		clear(out)
		return nil, err
	}
	data := append([]byte(nil), out[:n]...)
	clear(out)
	return data, nil
}

// sealWith 用指定 hash 加密，再立刻用 TPM 解一次确认。公钥运算在软件里完成，
// TPM 不支持这个 hash 时加密照样成功，只有解密才会暴露问题；而封存后解不开的
// 设备秘密等于永久丢失，所以必须回读。
func sealWith(key uintptr, alg oaepAlg, data []byte) ([]byte, error) {
	blob, err := ncryptEncrypt(key, data, alg.padding())
	if err != nil {
		pub, pubErr := exportRSAPub(key)
		if pubErr != nil {
			return nil, err
		}
		blob, err = rsa.EncryptOAEP(alg.newHash(), rand.Reader, pub, data, nil)
		if err != nil {
			return nil, &apiError{codeFailed, "rsa.EncryptOAEP failed"}
		}
	}
	back, err := ncryptDecrypt(key, blob, alg.padding())
	if err != nil {
		return nil, err
	}
	defer clear(back)
	if subtle.ConstantTimeCompare(back, data) != 1 {
		return nil, errSealMismatch
	}
	return blob, nil
}

type ncryptBackend struct{}

func newBackend() backend { return ncryptBackend{} }

func (ncryptBackend) Status() statusResult {
	res := unavailableBackend{}.Status()
	if modncrypt.Load() != nil {
		return res
	}
	p, err := openProvider()
	if err != nil {
		return res
	}
	defer freeObject(p)
	for _, alg := range []*uint16{algECDSAP256W, algRSAW} {
		r, _, _ := procIsAlgSupported.Call(p, uintptr(unsafe.Pointer(alg)), 0)
		if uint32(r) != 0 {
			return res
		}
	}
	impl, err := getPropertyU32(p, propImplTypeW)
	if err != nil || impl&ncryptImplHardwareFlag == 0 {
		return res
	}
	res.Available = true
	res.Level = levelHardware
	return res
}

func (ncryptBackend) Create(name string) (pub []byte, err error) {
	p, err := openProvider()
	if err != nil {
		return nil, err
	}
	defer freeObject(p)

	// 失败时只回滚本次调用亲手建成的密钥，已有的密钥绝不能动。
	var created []string
	defer func() {
		if err != nil {
			for _, keyName := range created {
				deleteKey(p, keyName)
			}
		}
	}()

	// 不需要预先检查是否存在：名字已被占用时 NCryptCreatePersistedKey 立刻返回
	// NTE_EXISTS（实测不到 3 ms，不生成密钥、不覆盖）。
	// createKey 失败时密钥没有 finalize，不会落盘，所以只记录成功建好的。
	// ECC 先建：它很快，名字冲突或 RSA 失败时回滚代价小。
	authName, sealName := authKeyName(name), sealKeyName(name)
	if err = createKey(p, algECDSAP256W, authName, pcpSignatureKey, 0); err != nil {
		return nil, err
	}
	created = append(created, authName)

	if err = createKey(p, algRSAW, sealName, pcpEncryptionKey, rsaKeyBits); err != nil {
		return nil, err
	}
	created = append(created, sealName)

	k, err := openKey(p, authName)
	if err != nil {
		return nil, err
	}
	defer freeObject(k)
	return exportAuthPub(k)
}

func withKey(keyName string, fn func(key uintptr) error) error {
	p, err := openProvider()
	if err != nil {
		return err
	}
	defer freeObject(p)
	k, err := openKey(p, keyName)
	if err != nil {
		return err
	}
	defer freeObject(k)
	return fn(k)
}

func (ncryptBackend) Pub(name string) (pub []byte, err error) {
	err = withKey(authKeyName(name), func(k uintptr) error {
		pub, err = exportAuthPub(k)
		return err
	})
	return pub, err
}

func (ncryptBackend) Sign(name string, digest []byte) (sig []byte, err error) {
	err = withKey(authKeyName(name), func(k uintptr) error {
		out := make([]byte, 2*p256Size)
		var n uint32
		r, _, _ := procSignHash.Call(
			k, 0,
			uintptr(unsafe.Pointer(unsafe.SliceData(digest))), uintptr(len(digest)),
			uintptr(unsafe.Pointer(unsafe.SliceData(out))), uintptr(len(out)),
			uintptr(unsafe.Pointer(&n)), ncryptSilentFlag)
		if err := statusErr("NCryptSignHash", r); err != nil {
			return err
		}
		if int(n) != len(out) {
			return &apiError{codeFailed, fmt.Sprintf("NCryptSignHash: unexpected signature size %d", n)}
		}
		sig = out
		return nil
	})
	return sig, err
}

func (ncryptBackend) Seal(name string, data []byte) (blob []byte, algName string, err error) {
	err = withKey(sealKeyName(name), func(k uintptr) error {
		var firstErr error
		for _, alg := range oaepCandidates {
			b, e := sealWith(k, alg, data)
			if e == nil {
				blob, algName = b, alg.name
				return nil
			}
			if hasCode(e, codeNoKey) || hasCode(e, codeTPMUnavailable) {
				return e
			}
			if firstErr == nil {
				firstErr = e
			}
		}
		return firstErr
	})
	return blob, algName, err
}

// Unseal 优先按 alg 解密；alg 为空时依次尝试 SHA-256、SHA-1。
func (ncryptBackend) Unseal(name string, blob []byte, algName string) (data []byte, err error) {
	err = withKey(sealKeyName(name), func(k uintptr) error {
		var firstErr error
		for _, alg := range oaepCandidates {
			if algName != "" && alg.name != algName {
				continue
			}
			d, e := ncryptDecrypt(k, blob, alg.padding())
			if e == nil {
				data = d
				return nil
			}
			if firstErr == nil {
				firstErr = e
			}
		}
		if firstErr == nil {
			return &apiError{codeFailed, "unknown alg"}
		}
		return firstErr
	})
	return data, err
}

func (ncryptBackend) Delete(name string) (deleteResult, error) {
	var res deleteResult
	p, err := openProvider()
	if err != nil {
		return res, err
	}
	defer freeObject(p)

	var authErr, sealErr error
	res.Auth, authErr = deleteKey(p, authKeyName(name))
	res.Seal, sealErr = deleteKey(p, sealKeyName(name))
	if authErr != nil {
		return res, authErr
	}
	if sealErr != nil {
		return res, sealErr
	}
	if !res.Auth && !res.Seal {
		return res, &apiError{codeNoKey, "no keys for this name"}
	}
	return res, nil
}
