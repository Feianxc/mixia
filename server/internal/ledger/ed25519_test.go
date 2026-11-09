package ledger

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"math/big"
	"testing"

	"mixia/server/internal/edtest"
)

func newKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

// le builds a 32-byte little-endian value from low byte, fill and top byte.
func le(low, fill, top byte) []byte {
	b := bytes.Repeat([]byte{fill}, 32)
	b[0], b[31] = low, top
	return b
}

// The table is checked by arithmetic, not against a second copy of itself.
func TestSmallOrderTableIsExactlyTheTorsion(t *testing.T) {
	eight := big.NewInt(8)
	for i, entry := range smallOrderEncodings {
		p, ok := edtest.Decode(entry[:])
		if !ok {
			t.Fatalf("entry %d is not a curve point", i)
		}
		if !p.Mul(eight).Equal(edtest.Identity()) {
			t.Fatalf("entry %d is not of small order", i)
		}
	}
	for i, p := range edtest.Torsion() {
		enc := p.Encode()
		if !hasSmallOrder(enc) {
			t.Fatalf("torsion point %d not recognized", i)
		}
		enc[31] ^= 0x80
		if !hasSmallOrder(enc) {
			t.Fatalf("torsion point %d not recognized with the sign bit flipped", i)
		}
	}
	// The two torsion points with a second, non-canonical spelling of y.
	for _, enc := range [][]byte{le(0xed, 0xff, 0x7f), le(0xee, 0xff, 0x7f), le(0xed, 0xff, 0xff), le(0xee, 0xff, 0xff)} {
		if !hasSmallOrder(enc) {
			t.Fatalf("%x not recognized", enc)
		}
	}
	if hasSmallOrder(edtest.Base().Encode()) {
		t.Fatal("base point flagged")
	}
	pub, _ := newKey(t)
	if hasSmallOrder(pub) {
		t.Fatal("ordinary key flagged")
	}
}

func TestIsCanonicalPoint(t *testing.T) {
	cases := []struct {
		name string
		enc  []byte
		want bool
	}{
		{"zero", make([]byte, 32), true},
		{"p-1", le(0xec, 0xff, 0x7f), true},
		{"p", le(0xed, 0xff, 0x7f), false},
		{"p+1", le(0xee, 0xff, 0x7f), false},
		{"2^255-1", le(0xff, 0xff, 0x7f), false},
		{"sign bit does not matter below p", le(0xec, 0xff, 0xff), true},
		{"sign bit does not matter above p", le(0xed, 0xff, 0xff), false},
		{"top byte below 0x7f", le(0xff, 0xff, 0x7e), true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := isCanonicalPoint(c.enc); got != c.want {
				t.Fatalf("isCanonicalPoint = %v, want %v", got, c.want)
			}
		})
	}
	// A hole in any middle byte means the value is below p.
	for i := 1; i < 31; i++ {
		enc := le(0xff, 0xff, 0x7f)
		enc[i] = 0xfe
		if !isCanonicalPoint(enc) {
			t.Fatalf("byte %d ignored", i)
		}
	}
}

func TestValidEd25519Pub(t *testing.T) {
	pub, _ := newKey(t)
	if !validEd25519Pub(pub) {
		t.Fatal("ordinary key refused")
	}
	if validEd25519Pub(pub[:31]) {
		t.Fatal("short key accepted")
	}
	if validEd25519Pub(edtest.Identity().Encode()) {
		t.Fatal("identity accepted")
	}
	// p+2 spells y=2 non-canonically, and is not of small order.
	nonCanonical := le(0xef, 0xff, 0x7f)
	if hasSmallOrder(nonCanonical) || validEd25519Pub(nonCanonical) {
		t.Fatal("non-canonical key accepted")
	}
}

func TestStrictVerifyAcceptsOrdinarySignatures(t *testing.T) {
	pub, priv := newKey(t)
	msg := []byte("message")
	sig := ed25519.Sign(priv, msg)
	if !StrictVerify(pub, msg, sig) {
		t.Fatal("valid signature refused")
	}
	if StrictVerify(pub, []byte("other"), sig) {
		t.Fatal("signature accepted for another message")
	}
	if StrictVerify(pub, msg, sig[:63]) || StrictVerify(pub, msg, append(sig[:64:64], 0)) {
		t.Fatal("wrong-length signature accepted")
	}
	if StrictVerify(pub[:31], msg, sig) || StrictVerify(nil, msg, sig) {
		t.Fatal("wrong-length key accepted")
	}
}

func TestStrictVerifyRejectsIdentityR(t *testing.T) {
	pub, priv := newKey(t)
	msg := []byte("poison")
	sig := edtest.IdentityR(priv, msg)
	if !ed25519.Verify(pub, msg, sig) {
		t.Fatal("test vector is not accepted by crypto/ed25519, so it proves nothing")
	}
	if StrictVerify(pub, msg, sig) {
		t.Fatal("R = identity accepted")
	}
}

func TestStrictVerifyRejectsEverySmallOrderR(t *testing.T) {
	_, priv := newKey(t)
	a := edtest.Secret(priv)
	torsion := edtest.Torsion()
	pub := edtest.MixedKey(a, torsion[1])
	if !validEd25519Pub(pub) {
		t.Fatal("mixed-order key should pass the key checks, so that only R is at fault")
	}
	for i, target := range torsion {
		msg, sig := edtest.TorsionR(a, torsion[1], target, pub)
		if !ed25519.Verify(pub, msg, sig) {
			t.Fatalf("vector %d is not accepted by crypto/ed25519", i)
		}
		if StrictVerify(pub, msg, sig) {
			t.Fatalf("small-order R %d accepted", i)
		}
	}
}

func TestStrictVerifyRejectsSmallOrderKeys(t *testing.T) {
	torsion := edtest.Torsion()
	for i, key := range torsion {
		msg, sig := edtest.SmallOrderKey(key, torsion)
		if !ed25519.Verify(key.Encode(), msg, sig) {
			t.Fatalf("vector %d is not accepted by crypto/ed25519", i)
		}
		if StrictVerify(key.Encode(), msg, sig) {
			t.Fatalf("small-order key %d accepted", i)
		}

		// With an ordinary R, nothing but the key itself is wrong.
		msg, sig = edtest.SmallOrderKeyOrdinaryR(key, torsion)
		if hasSmallOrder(sig[:32]) || !ed25519.Verify(key.Encode(), msg, sig) {
			t.Fatalf("vector %d does not isolate the key", i)
		}
		if StrictVerify(key.Encode(), msg, sig) {
			t.Fatalf("small-order key %d accepted with an ordinary R", i)
		}
	}
}
