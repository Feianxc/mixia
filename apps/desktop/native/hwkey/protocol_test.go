package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// fakeBackend 让协议层不依赖硬件也能测试。
type fakeBackend struct {
	unavailableBackend
	gotDigest []byte
	gotAlg    string
	panicOn   string
}

func (f *fakeBackend) Sign(name string, digest []byte) ([]byte, error) {
	if name == f.panicOn {
		panic("secret-in-panic")
	}
	f.gotDigest = digest
	return []byte{1, 2, 3}, nil
}

func (f *fakeBackend) Unseal(_ string, _ []byte, alg string) ([]byte, error) {
	f.gotAlg = alg
	return []byte("plain"), nil
}

func (f *fakeBackend) Pub(string) ([]byte, error) {
	return nil, &apiError{codeNoKey, "NCryptOpenKey: SECURITY_STATUS 0x80090016"}
}

type reply struct {
	ID      json.RawMessage `json:"id"`
	OK      bool            `json:"ok"`
	Result  json.RawMessage `json:"result"`
	Error   string          `json:"error"`
	Message string          `json:"message"`
}

func runLines(t *testing.T, b backend, input string) []reply {
	t.Helper()
	var out bytes.Buffer
	if err := serve(strings.NewReader(input), &out, b); err != nil {
		t.Fatalf("serve: %v", err)
	}
	var replies []reply
	for line := range bytes.Lines(out.Bytes()) {
		var r reply
		if err := json.Unmarshal(line, &r); err != nil {
			t.Fatalf("response is not JSON: %q", line)
		}
		replies = append(replies, r)
	}
	return replies
}

func one(t *testing.T, b backend, input string) reply {
	t.Helper()
	replies := runLines(t, b, input)
	if len(replies) != 1 {
		t.Fatalf("want 1 response, got %d", len(replies))
	}
	return replies[0]
}

func TestLineHandling(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  int
	}{
		{"empty stdin exits cleanly", "", 0},
		{"blank lines are ignored", "\n  \r\n\n", 0},
		{"one line", `{"id":1,"cmd":"status"}` + "\n", 1},
		{"last line without newline", `{"id":1,"cmd":"status"}`, 1},
		{"crlf", `{"id":1,"cmd":"status"}` + "\r\n", 1},
		{"many lines", strings.Repeat(`{"id":1,"cmd":"status"}`+"\n", 3), 3},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := len(runLines(t, unavailableBackend{}, tc.input)); got != tc.want {
				t.Fatalf("got %d responses, want %d", got, tc.want)
			}
		})
	}
}

func TestIDIsEchoed(t *testing.T) {
	for _, id := range []string{`1`, `"abc"`, `null`} {
		r := one(t, unavailableBackend{}, fmt.Sprintf(`{"id":%s,"cmd":"status"}`, id))
		if string(r.ID) != id {
			t.Errorf("id = %s, want %s", r.ID, id)
		}
	}
}

// 1 MiB 数据的请求行远超 bufio.Scanner 默认的 64 KiB。
func TestLargestSignRequestFitsOneLine(t *testing.T) {
	data := bytes.Repeat([]byte{0xAB}, maxSignData)
	f := &fakeBackend{}
	r := one(t, f, fmt.Sprintf(`{"id":1,"cmd":"sign","args":{"name":"n","data":"%s"}}`, b64.EncodeToString(data)))
	if !r.OK {
		t.Fatalf("1 MiB sign rejected: %s %s", r.Error, r.Message)
	}
	want := sha256.Sum256(data)
	if !bytes.Equal(f.gotDigest, want[:]) {
		t.Fatal("backend did not receive SHA-256 of data")
	}

	over := b64.EncodeToString(append(data, 0))
	r = one(t, f, fmt.Sprintf(`{"id":2,"cmd":"sign","args":{"name":"n","data":"%s"}}`, over))
	if r.OK || r.Error != codeBadRequest || string(r.ID) != "2" {
		t.Fatalf("1 MiB + 1: %+v", r)
	}
}

func TestOversizedLineDoesNotBreakTheStream(t *testing.T) {
	input := strings.Repeat("x", maxLineLen+1) + "\n" + `{"id":7,"cmd":"status"}` + "\n"
	replies := runLines(t, unavailableBackend{}, input)
	if len(replies) != 2 {
		t.Fatalf("got %d responses, want 2", len(replies))
	}
	if replies[0].OK || replies[0].Error != codeBadRequest || string(replies[0].ID) != "null" {
		t.Fatalf("oversized line: %+v", replies[0])
	}
	if !replies[1].OK || string(replies[1].ID) != "7" {
		t.Fatalf("next line: %+v", replies[1])
	}
}

func TestBadRequests(t *testing.T) {
	blob := b64.EncodeToString(make([]byte, sealBlobLen))
	tests := []struct {
		name string
		line string
	}{
		{"not json", `{nope`},
		{"unknown cmd", `{"id":1,"cmd":"format-tpm"}`},
		{"args wrong type", `{"id":1,"cmd":"sign","args":[1]}`},
		{"no args", `{"id":1,"cmd":"pub"}`},
		{"empty name", `{"id":1,"cmd":"pub","args":{"name":""}}`},
		{"name 65 chars", `{"id":1,"cmd":"pub","args":{"name":"` + strings.Repeat("a", 65) + `"}}`},
		{"name with space", `{"id":1,"cmd":"pub","args":{"name":"a b"}}`},
		{"name with path", `{"id":1,"cmd":"pub","args":{"name":"..\\x"}}`},
		{"name with newline", `{"id":1,"cmd":"pub","args":{"name":"abc\n"}}`},
		{"name non-ascii", `{"id":1,"cmd":"pub","args":{"name":"密匣"}}`},
		{"missing data", `{"id":1,"cmd":"sign","args":{"name":"n"}}`},
		{"padded base64", `{"id":1,"cmd":"sign","args":{"name":"n","data":"QQ=="}}`},
		{"std alphabet", `{"id":1,"cmd":"sign","args":{"name":"n","data":"+/+/"}}`},
		{"seal 191 bytes", `{"id":1,"cmd":"seal","args":{"name":"n","data":"` + b64.EncodeToString(make([]byte, 191)) + `"}}`},
		{"missing blob", `{"id":1,"cmd":"unseal","args":{"name":"n"}}`},
		{"short blob", `{"id":1,"cmd":"unseal","args":{"name":"n","blob":"AAAA"}}`},
		{"long blob", `{"id":1,"cmd":"unseal","args":{"name":"n","blob":"` + b64.EncodeToString(make([]byte, 257)) + `"}}`},
		{"unknown alg", `{"id":1,"cmd":"unseal","args":{"name":"n","blob":"` + blob + `","alg":"pkcs1"}}`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := one(t, &fakeBackend{}, tc.line)
			if r.OK || r.Error != codeBadRequest {
				t.Fatalf("got %+v", r)
			}
		})
	}
}

func TestNameBoundaries(t *testing.T) {
	for _, name := range []string{"a", strings.Repeat("Z", 64), "AZaz09_-"} {
		r := one(t, &fakeBackend{}, fmt.Sprintf(`{"id":1,"cmd":"pub","args":{"name":"%s"}}`, name))
		if r.Error != codeNoKey {
			t.Errorf("%q should reach the backend, got %+v", name, r)
		}
	}
}

func TestUnsealPassesAlgThrough(t *testing.T) {
	blob := b64.EncodeToString(make([]byte, sealBlobLen))
	for _, alg := range []string{algOAEPSHA256, algOAEPSHA1, ""} {
		f := &fakeBackend{}
		r := one(t, f, fmt.Sprintf(`{"id":1,"cmd":"unseal","args":{"name":"n","blob":"%s","alg":"%s"}}`, blob, alg))
		if !r.OK || f.gotAlg != alg {
			t.Errorf("alg %q: %+v, backend got %q", alg, r, f.gotAlg)
		}
	}
}

func TestBackendErrorKeepsCodeAndStatus(t *testing.T) {
	r := one(t, &fakeBackend{}, `{"id":9,"cmd":"pub","args":{"name":"n"}}`)
	if r.OK || r.Error != codeNoKey || !strings.Contains(r.Message, "0x80090016") || string(r.ID) != "9" {
		t.Fatalf("got %+v", r)
	}
}

// 输入里的内容不能经错误消息回显：调用方可能把 message 写进日志。
func TestErrorsNeverEchoInput(t *testing.T) {
	const secret = "1234567890123"
	for _, line := range []string{
		`{"id":1,"cmd":"seal","args":{"name":"n","data":` + secret + `}}`,
		`{"id":1,"cmd":"seal","args":` + secret + `}`,
		`{"id":1,"cmd":"seal","args":{"name":"` + secret + `!","data":"AA"}}`,
		`{"id":` + secret,
	} {
		r := one(t, &fakeBackend{}, line)
		if r.OK || strings.Contains(r.Message, secret) {
			t.Errorf("%s -> %+v", line, r)
		}
	}
}

func TestPanicBecomesFailureAndServingContinues(t *testing.T) {
	input := `{"id":1,"cmd":"sign","args":{"name":"boom","data":""}}` + "\n" + `{"id":2,"cmd":"status"}` + "\n"
	replies := runLines(t, &fakeBackend{panicOn: "boom"}, input)
	if len(replies) != 2 {
		t.Fatalf("got %d responses", len(replies))
	}
	if r := replies[0]; r.OK || r.Error != codeFailed || string(r.ID) != "1" || strings.Contains(r.Message, "secret") {
		t.Fatalf("panic response: %+v", r)
	}
	if !replies[1].OK {
		t.Fatalf("server stopped after panic: %+v", replies[1])
	}
}

func TestUnavailableBackendNeverPretends(t *testing.T) {
	r := one(t, unavailableBackend{}, `{"id":1,"cmd":"status"}`)
	var s statusResult
	if err := json.Unmarshal(r.Result, &s); err != nil {
		t.Fatal(err)
	}
	if s.Available || s.Level != levelNone || s.Provider != providerName {
		t.Fatalf("status = %+v", s)
	}
	for _, cmd := range []string{"create", "pub", "delete"} {
		r := one(t, unavailableBackend{}, fmt.Sprintf(`{"id":1,"cmd":"%s","args":{"name":"n"}}`, cmd))
		if r.OK || r.Error != codeTPMUnavailable {
			t.Errorf("%s: %+v", cmd, r)
		}
	}
}
