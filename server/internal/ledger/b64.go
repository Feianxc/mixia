package ledger

import (
	"encoding/base64"
	"errors"
	"strings"
)

var b64enc = base64.RawURLEncoding.Strict()

var errB64 = errors.New("invalid base64url")

// DecodeB64 decodes unpadded base64url strictly: non-canonical trailing bits
// and the CR/LF that encoding/base64 silently skips are both rejected, so a
// decoded value re-encodes to exactly the string the client sent.
func DecodeB64(s string) ([]byte, error) {
	if strings.ContainsAny(s, "\r\n") {
		return nil, errB64
	}
	return b64enc.DecodeString(s)
}

// EncodeB64 encodes unpadded base64url.
func EncodeB64(b []byte) string { return b64enc.EncodeToString(b) }

// B64 is binary data that crosses JSON as unpadded base64url (spec section 0).
type B64 []byte

func (b B64) MarshalJSON() ([]byte, error) {
	out := make([]byte, b64enc.EncodedLen(len(b))+2)
	out[0] = '"'
	b64enc.Encode(out[1:], b)
	out[len(out)-1] = '"'
	return out, nil
}

// UnmarshalJSON decodes in place rather than through DecodeB64: a snapshot can
// carry tens of MiB in one field, and a string conversion would copy all of it.
func (b *B64) UnmarshalJSON(data []byte) error {
	if len(data) < 2 || data[0] != '"' || data[len(data)-1] != '"' {
		return errB64
	}
	src := data[1 : len(data)-1]
	out := make([]byte, b64enc.DecodedLen(len(src)))
	n, err := b64enc.Decode(out, src)
	if err != nil {
		return err
	}
	*b = out[:n]
	return nil
}
