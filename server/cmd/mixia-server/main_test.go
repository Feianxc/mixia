package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"mixia/server/internal/ledger"
)

func freeAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().String()
}

func bootstrapBody(t *testing.T, token string) []byte {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(map[string]any{
		"v": 1, "seq": 0, "prev": "", "ts": 1, "signer": "root", "type": "genesis",
		"data": map[string]any{
			"ownerId": "o", "rootPub": ledger.EncodeB64(pub), "recoveryBoxPub": ledger.EncodeB64(make([]byte, 32)),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	wire := ledger.Wire{Body: body, Sig: ed25519.Sign(priv, append([]byte("mixia/ledger/v1\n"), body...))}
	out, err := json.Marshal(map[string]any{"token": token, "entries": []ledger.Wire{wire}, "keys": []any{}})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// startServer runs `serve` in-process and returns a stop function that waits
// for it to exit and reports its error.
func startServer(t *testing.T, addr string) func() error {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- run(ctx, []string{"serve"}, io.Discard) }()
	for i := 0; ; i++ {
		res, err := http.Get("http://" + addr + "/healthz")
		if err == nil {
			res.Body.Close()
			break
		}
		select {
		case err := <-done:
			t.Fatalf("serve exited early: %v", err)
		default:
		}
		if i == 200 {
			t.Fatal("server did not come up")
		}
		time.Sleep(10 * time.Millisecond)
	}
	stopped := false
	stop := func() error {
		if stopped {
			return nil
		}
		stopped = true
		cancel()
		return <-done
	}
	t.Cleanup(func() { stop() })
	return stop
}

func TestServeBackupVerifyLifecycle(t *testing.T) {
	const token = "s3cret"
	sum := sha256.Sum256([]byte(token))
	dir := t.TempDir()
	addr := freeAddr(t)
	t.Setenv("MIXIA_ADDR", addr)
	t.Setenv("MIXIA_DATA", dir)
	t.Setenv("MIXIA_BOOTSTRAP_TOKEN_SHA256", hex.EncodeToString(sum[:]))
	stop := startServer(t, addr)
	base := "http://" + addr

	post := func() int {
		res, err := http.Post(base+"/v1/bootstrap", "application/json", bytes.NewReader(bootstrapBody(t, token)))
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		return res.StatusCode
	}
	if got := post(); got != http.StatusOK {
		t.Fatalf("bootstrap = %d", got)
	}

	// Both offline commands run beside the live server.
	dest := filepath.Join(t.TempDir(), "backup.db")
	if err := run(context.Background(), []string{"backup", dest}, io.Discard); err != nil {
		t.Fatalf("backup: %v", err)
	}
	if fi, err := os.Stat(dest); err != nil || fi.Size() == 0 {
		t.Fatalf("backup file: %v", err)
	}
	var out bytes.Buffer
	if err := run(context.Background(), []string{"verify"}, &out); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !strings.Contains(out.String(), "ledger:    ok, 1 entries, head 0") {
		t.Fatalf("verify output:\n%s", out.String())
	}

	if err := stop(); err != nil {
		t.Fatalf("serve returned %v after shutdown", err)
	}
	// A clean close checkpoints and removes the WAL.
	if _, err := os.Stat(filepath.Join(dir, "mixia.db-wal")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("WAL still present after shutdown: %v", err)
	}

	stop = startServer(t, addr)
	if got := post(); got != http.StatusGone {
		t.Fatalf("bootstrap after restart = %d, want 410", got)
	}
	if err := stop(); err != nil {
		t.Fatal(err)
	}
}

func TestShutdownDrainsInFlightRequest(t *testing.T) {
	dir := t.TempDir()
	addr := freeAddr(t)
	t.Setenv("MIXIA_ADDR", addr)
	t.Setenv("MIXIA_DATA", dir)
	// With a token configured the handler has to read the body before replying.
	t.Setenv("MIXIA_BOOTSTRAP_TOKEN_SHA256", strings.Repeat("ab", 32))
	stop := startServer(t, addr)

	// A request whose body is still arriving when shutdown starts must finish.
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	io.WriteString(conn, "POST /v1/bootstrap HTTP/1.1\r\nHost: x\r\nContent-Length: 2\r\n\r\n{")
	time.Sleep(50 * time.Millisecond)
	stopped := make(chan error, 1)
	go func() { stopped <- stop() }()
	time.Sleep(50 * time.Millisecond)
	io.WriteString(conn, "}")
	reply, err := io.ReadAll(conn)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(reply, []byte(`"error":"unauthorized"`)) {
		t.Fatalf("reply = %q", reply)
	}
	if err := <-stopped; err != nil {
		t.Fatal(err)
	}
}

func TestLoadConfigRejectsBadEnv(t *testing.T) {
	cases := []struct{ key, value string }{
		{"MIXIA_QUOTA_BYTES", "lots"},
		{"MIXIA_QUOTA_BYTES", "0"},
		{"MIXIA_BOOTSTRAP_TOKEN_SHA256", "abc"},
		{"MIXIA_BOOTSTRAP_TOKEN_SHA256", strings.Repeat("g", 64)},
		{"MIXIA_RATE_RPS", "fast"},
		{"MIXIA_RATE_BURST", "-1"},
	}
	for _, c := range cases {
		t.Run(c.key+"="+c.value, func(t *testing.T) {
			t.Setenv(c.key, c.value)
			if _, _, err := loadConfig(); err == nil {
				t.Fatal("bad value accepted")
			}
		})
	}
}

func TestLoadConfigDefaults(t *testing.T) {
	for _, k := range []string{"MIXIA_QUOTA_BYTES", "MIXIA_BOOTSTRAP_TOKEN_SHA256", "MIXIA_TRUST_CF"} {
		t.Setenv(k, "")
	}
	cfg, quota, err := loadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if quota != 4<<30 || cfg.BootstrapTokenHash != nil || cfg.TrustCF {
		t.Fatalf("quota=%d cfg=%+v", quota, cfg)
	}
	t.Setenv("MIXIA_TRUST_CF", "1")
	if cfg, _, _ := loadConfig(); !cfg.TrustCF {
		t.Fatal("MIXIA_TRUST_CF=1 ignored")
	}
}

func TestUsage(t *testing.T) {
	for _, args := range [][]string{nil, {"nope"}, {"serve", "extra"}, {"backup"}, {"verify", "x"}} {
		if err := run(context.Background(), args, io.Discard); !errors.Is(err, errUsage) {
			t.Fatalf("run(%v) = %v", args, err)
		}
	}
}
