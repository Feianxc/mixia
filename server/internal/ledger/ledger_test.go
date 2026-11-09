package ledger

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestDecodeB64IsStrict(t *testing.T) {
	good := EncodeB64([]byte{0xff, 0xee, 0x01})
	if _, err := DecodeB64(good); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{
		good + "=",  // padding
		good + "\n", // the stdlib skips newlines unless told otherwise
		"ab\r\ncd",  //
		"AB+/",      // standard alphabet
		"QQ",        // canonical
	} {
		_, err := DecodeB64(bad)
		if bad == "QQ" {
			if err != nil {
				t.Fatalf("canonical %q refused: %v", bad, err)
			}
			continue
		}
		if err == nil {
			t.Fatalf("%q accepted", bad)
		}
	}
	// Non-zero trailing bits decode to the same bytes as "QQ" in lax mode.
	if _, err := DecodeB64("QR"); err == nil {
		t.Fatal("non-canonical trailing bits accepted")
	}
}

func TestB64JSONRoundTrip(t *testing.T) {
	type doc struct {
		V B64 `json:"v"`
	}
	raw, err := json.Marshal(doc{V: []byte("hello")})
	if err != nil {
		t.Fatal(err)
	}
	var back doc
	if err := json.Unmarshal(raw, &back); err != nil || string(back.V) != "hello" {
		t.Fatalf("round trip: %v %q", err, back.V)
	}
	for _, bad := range []string{`{"v":null}`, `{"v":3}`, `{"v":"@@"}`, `{"v":"QQ\n"}`, `{"v":"QQ\r"}`, `{"v":"QR"}`, `{"v":"QQ=="}`} {
		if err := json.Unmarshal([]byte(bad), &back); err == nil {
			t.Fatalf("%s accepted", bad)
		}
	}
}

func TestValidID(t *testing.T) {
	for _, ok := range []string{"a", "A-b_9", strings.Repeat("x", 64)} {
		if !ValidID(ok) {
			t.Fatalf("%q refused", ok)
		}
	}
	for _, bad := range []string{"", strings.Repeat("x", 65), "a/b", "a.b", "..", "a\n", "a b", "密"} {
		if ValidID(bad) {
			t.Fatalf("%q accepted", bad)
		}
	}
}

func TestParseRejectsMalformedBodies(t *testing.T) {
	valid := `{"v":1,"seq":0,"prev":"","ts":1,"signer":"root","type":"genesis","data":{}}`
	if _, err := Parse(Wire{Body: []byte(valid)}); err != nil {
		t.Fatal(err)
	}
	bad := map[string]string{
		"not JSON":        `nope`,
		"array":           `[]`,
		"null":            `null`,
		"trailing data":   valid + `{}`,
		"invalid UTF-8":   "{\"v\":1,\"seq\":0,\"prev\":\"\",\"ts\":1,\"signer\":\"root\",\"type\":\"genesis\",\"data\":{\"x\":\"\xff\"}}",
		"missing seq":     `{"v":1,"prev":"","ts":1,"signer":"root","type":"genesis","data":{}}`,
		"null seq":        `{"v":1,"seq":null,"prev":"","ts":1,"signer":"root","type":"genesis","data":{}}`,
		"float seq":       `{"v":1,"seq":1.5,"prev":"","ts":1,"signer":"root","type":"genesis","data":{}}`,
		"string seq":      `{"v":1,"seq":"0","prev":"","ts":1,"signer":"root","type":"genesis","data":{}}`,
		"null data":       `{"v":1,"seq":0,"prev":"","ts":1,"signer":"root","type":"genesis","data":null}`,
		"data not object": `{"v":1,"seq":0,"prev":"","ts":1,"signer":"root","type":"genesis","data":[]}`,
	}
	for name, body := range bad {
		t.Run(name, func(t *testing.T) {
			_, err := Parse(Wire{Body: []byte(body)})
			var inv *InvalidError
			if !errors.As(err, &inv) {
				t.Fatalf("err = %v", err)
			}
		})
	}
}

func genesisWire(t *testing.T, priv ed25519.PrivateKey) Wire {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"v": 1, "seq": 0, "prev": "", "ts": 1, "signer": "root", "type": "genesis",
		"data": map[string]any{
			"ownerId":        "o",
			"rootPub":        EncodeB64(priv.Public().(ed25519.PublicKey)),
			"recoveryBoxPub": EncodeB64(make([]byte, 32)),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return Wire{Body: body, Sig: ed25519.Sign(priv, append([]byte(signPrefix), body...))}
}

func TestReplay(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	w := genesisWire(t, priv)

	st, err := Replay(nil)
	if err != nil || st.Bootstrapped() || st.Head != -1 {
		t.Fatalf("empty replay: %+v, %v", st, err)
	}
	st, err = Replay([]Wire{w})
	if err != nil || st.Head != 0 || len(st.GenesisHash) != 32 {
		t.Fatalf("replay: %+v, %v", st, err)
	}
	w.Sig[0] ^= 1
	if _, err := Replay([]Wire{w}); err == nil {
		t.Fatal("replay accepted a forged genesis")
	}
}

func TestCloneIsIsolated(t *testing.T) {
	s := New()
	s.Vaults["a"] = Vault{ID: "a", Gen: 1}
	s.Devices["d"] = Device{ID: "d"}
	c := s.Clone()
	c.Vaults["b"] = Vault{ID: "b", Gen: 1}
	delete(c.Devices, "d")
	if len(s.Vaults) != 1 || len(s.Devices) != 1 {
		t.Fatal("clone shares maps with the original")
	}
}
