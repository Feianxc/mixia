// Package edtest is exact, slow Ed25519 arithmetic for building signatures a
// normal signer never produces. It exists for tests and nothing else imports it.
package edtest

import (
	"crypto/ed25519"
	"crypto/sha512"
	"fmt"
	"math/big"
	"slices"
)

var (
	p      = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))
	order  = mustInt("7237005577332262213973186563042994240857116359379907606001950938285454250989")
	curveD = mod(new(big.Int).Mul(big.NewInt(-121665), inv(big.NewInt(121666))))
	sqrtM1 = new(big.Int).Exp(big.NewInt(2), new(big.Int).Div(new(big.Int).Sub(p, big.NewInt(1)), big.NewInt(4)), p)
)

func mustInt(s string) *big.Int {
	v, ok := new(big.Int).SetString(s, 10)
	if !ok {
		panic("bad constant")
	}
	return v
}

func mod(v *big.Int) *big.Int { return new(big.Int).Mod(v, p) }
func inv(v *big.Int) *big.Int { return new(big.Int).ModInverse(v, p) }

func mul(vs ...*big.Int) *big.Int {
	out := big.NewInt(1)
	for _, v := range vs {
		out = mod(new(big.Int).Mul(out, v))
	}
	return out
}

// Point is an affine point on edwards25519.
type Point struct{ X, Y *big.Int }

// Identity is the neutral element.
func Identity() Point { return Point{big.NewInt(0), big.NewInt(1)} }

// Base is the standard generator.
func Base() Point {
	enc := make([]byte, 32)
	enc[0] = 0x58
	for i := 1; i < 32; i++ {
		enc[i] = 0x66
	}
	b, ok := Decode(enc)
	if !ok {
		panic("bad base point")
	}
	return b
}

// Add is the complete twisted Edwards addition for a=-1.
func (a Point) Add(b Point) Point {
	t := mul(curveD, a.X, b.X, a.Y, b.Y)
	x := new(big.Int).Add(mul(a.X, b.Y), mul(a.Y, b.X))
	y := new(big.Int).Add(mul(a.Y, b.Y), mul(a.X, b.X))
	return Point{
		mul(x, inv(new(big.Int).Add(big.NewInt(1), t))),
		mul(y, inv(new(big.Int).Sub(big.NewInt(1), t))),
	}
}

// Mul returns [k]a for k >= 0.
func (a Point) Mul(k *big.Int) Point {
	out := Identity()
	for i := k.BitLen() - 1; i >= 0; i-- {
		out = out.Add(out)
		if k.Bit(i) == 1 {
			out = out.Add(a)
		}
	}
	return out
}

// Neg returns -a.
func (a Point) Neg() Point { return Point{mod(new(big.Int).Neg(a.X)), a.Y} }

// Equal reports whether two points are the same.
func (a Point) Equal(b Point) bool { return a.X.Cmp(b.X) == 0 && a.Y.Cmp(b.Y) == 0 }

func littleEndian(v *big.Int) []byte {
	out := v.FillBytes(make([]byte, 32))
	slices.Reverse(out)
	return out
}

func fromLittleEndian(b []byte) *big.Int {
	r := slices.Clone(b)
	slices.Reverse(r)
	return new(big.Int).SetBytes(r)
}

// Encode returns the canonical 32-byte encoding.
func (a Point) Encode() []byte {
	out := littleEndian(a.Y)
	out[31] |= byte(a.X.Bit(0)) << 7
	return out
}

// Decode reads an encoding. Like most implementations it also takes y >= p.
func Decode(s []byte) (Point, bool) {
	raw := slices.Clone(s)
	sign := raw[31] >> 7
	raw[31] &= 0x7f
	y := mod(fromLittleEndian(raw))
	yy := mul(y, y)
	u := mod(new(big.Int).Sub(yy, big.NewInt(1)))
	v := mod(new(big.Int).Add(mul(curveD, yy), big.NewInt(1)))
	xx := mul(u, inv(v))
	x := new(big.Int).Exp(xx, new(big.Int).Div(new(big.Int).Add(p, big.NewInt(3)), big.NewInt(8)), p)
	if mul(x, x).Cmp(xx) != 0 {
		x = mul(x, sqrtM1)
	}
	if mul(x, x).Cmp(xx) != 0 {
		return Point{}, false
	}
	if x.Bit(0) != uint(sign) {
		x = mod(new(big.Int).Neg(x))
	}
	return Point{x, y}, true
}

// Torsion returns the eight points of order dividing 8. It multiplies an
// arbitrary curve point by the group order, so the result owes nothing to any
// hard-coded table.
func Torsion() []Point {
	for y := int64(2); ; y++ {
		q, ok := Decode(littleEndian(big.NewInt(y)))
		if !ok {
			continue
		}
		gen := q.Mul(order)
		if gen.Mul(big.NewInt(4)).Equal(Identity()) {
			continue // order below 8
		}
		pts := []Point{Identity()}
		for i := 1; i < 8; i++ {
			pts = append(pts, pts[i-1].Add(gen))
		}
		return pts
	}
}

// Secret returns the clamped signing scalar of a key.
func Secret(priv ed25519.PrivateKey) *big.Int {
	h := sha512.Sum512(priv.Seed())
	h[0] &= 248
	h[31] &= 127
	h[31] |= 64
	return fromLittleEndian(h[:32])
}

// Challenge is H(R || A || M) mod L.
func Challenge(r, pub, msg []byte) *big.Int {
	h := sha512.New()
	h.Write(r)
	h.Write(pub)
	h.Write(msg)
	sum := h.Sum(nil)
	return new(big.Int).Mod(fromLittleEndian(sum), order)
}

// signWithR returns R || k*a mod L.
func signWithR(r []byte, a *big.Int, pub, msg []byte) []byte {
	s := new(big.Int).Mod(new(big.Int).Mul(Challenge(r, pub, msg), a), order)
	return append(slices.Clone(r), littleEndian(s)...)
}

// IdentityR signs msg with R set to the neutral element, which any holder of
// priv can do: S = k*a makes [S]B - [k]A vanish.
func IdentityR(priv ed25519.PrivateKey, msg []byte) []byte {
	pub := priv.Public().(ed25519.PublicKey)
	return signWithR(Identity().Encode(), Secret(priv), pub, msg)
}

// MixedKey returns the encoding of [a]B + t, a key with a torsion component.
func MixedKey(a *big.Int, t Point) []byte { return Base().Mul(a).Add(t).Encode() }

// TorsionR makes a signature under pub = MixedKey(a, t) whose R is exactly
// target. With S = k*a the verification equation yields -[k]t, so it searches
// for a message whose challenge lands on target.
func TorsionR(a *big.Int, t, target Point, pub []byte) (msg, sig []byte) {
	r := target.Encode()
	for i := 0; ; i++ {
		msg = fmt.Appendf(nil, "message %d", i)
		if t.Mul(Challenge(r, pub, msg)).Neg().Equal(target) {
			return msg, signWithR(r, a, pub, msg)
		}
	}
}

// SmallOrderKeyOrdinaryR makes a signature under the small-order key t whose R
// is not of small order, so that only the key is at fault. The verification
// equation yields [S]B - [k]t, which it searches to match R = [S]B + tail.
func SmallOrderKeyOrdinaryR(t Point, torsion []Point) (msg, sig []byte) {
	pub := t.Encode()
	s := big.NewInt(1234567)
	sb := Base().Mul(s)
	for i := 0; ; i++ {
		msg = fmt.Appendf(nil, "message %d", i)
		for _, tail := range torsion {
			r := sb.Add(tail)
			if t.Mul(Challenge(r.Encode(), pub, msg)).Neg().Equal(tail) {
				return msg, append(r.Encode(), littleEndian(s)...)
			}
		}
	}
}

// SmallOrderKey makes a signature under the small-order key t: S = 0, and the
// verification equation yields -[k]t, which it searches to match some R.
func SmallOrderKey(t Point, torsion []Point) (msg, sig []byte) {
	pub := t.Encode()
	for i := 0; ; i++ {
		msg = fmt.Appendf(nil, "message %d", i)
		for _, r := range torsion {
			if t.Mul(Challenge(r.Encode(), pub, msg)).Neg().Equal(r) {
				return msg, append(r.Encode(), make([]byte, 32)...)
			}
		}
	}
}
