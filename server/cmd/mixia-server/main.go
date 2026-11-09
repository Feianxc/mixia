// Command mixia-server is the Mixia sync server.
package main

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"mixia/server/internal/api"
	"mixia/server/internal/store"
)

const (
	defaultAddr  = "127.0.0.1:8096"
	defaultData  = "./data"
	defaultQuota = 4 << 30

	shutdownGrace = 30 * time.Second
)

const usage = `usage:
  mixia-server serve            run the server
  mixia-server backup <dest.db> write a consistent copy of the database
  mixia-server verify           check ledger integrity and print a summary

environment:
  MIXIA_ADDR                    listen address (default 127.0.0.1:8096)
  MIXIA_DATA                    data directory (default ./data)
  MIXIA_QUOTA_BYTES             total storage quota (default 4 GiB)
  MIXIA_BOOTSTRAP_TOKEN_SHA256  hex SHA-256 of the bootstrap token; unset disables bootstrap
  MIXIA_TRUST_CF=1              rate-limit by CF-Connecting-IP
  MIXIA_RATE_RPS                per-IP refill rate, tokens per second (default 5)
  MIXIA_RATE_BURST              per-IP bucket size (default 30)
`

var errUsage = errors.New("usage")

func main() {
	log.SetFlags(log.LstdFlags | log.LUTC)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	switch err := run(ctx, os.Args[1:], os.Stdout); {
	case errors.Is(err, errUsage):
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	case err != nil:
		fmt.Fprintln(os.Stderr, "mixia-server:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, out io.Writer) error {
	dir := envOr("MIXIA_DATA", defaultData)
	switch {
	case len(args) == 1 && args[0] == "serve":
		return serve(ctx, dir)
	case len(args) == 2 && args[0] == "backup":
		return store.Backup(dir, args[1])
	case len(args) == 1 && args[0] == "verify":
		return verify(out, dir)
	}
	return errUsage
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envFloat(key string) (float64, error) {
	raw := os.Getenv(key)
	if raw == "" {
		return 0, nil
	}
	v, err := strconv.ParseFloat(raw, 64)
	if err != nil || v <= 0 {
		return 0, fmt.Errorf("%s must be a positive number", key)
	}
	return v, nil
}

func loadConfig() (api.Config, int64, error) {
	var cfg api.Config
	quota := int64(defaultQuota)
	if raw := os.Getenv("MIXIA_QUOTA_BYTES"); raw != "" {
		v, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || v <= 0 {
			return cfg, 0, errors.New("MIXIA_QUOTA_BYTES must be a positive integer")
		}
		quota = v
	}
	if raw := os.Getenv("MIXIA_BOOTSTRAP_TOKEN_SHA256"); raw != "" {
		sum, err := hex.DecodeString(raw)
		if err != nil || len(sum) != 32 {
			return cfg, 0, errors.New("MIXIA_BOOTSTRAP_TOKEN_SHA256 must be 64 hex characters")
		}
		cfg.BootstrapTokenHash = sum
	}
	cfg.TrustCF = os.Getenv("MIXIA_TRUST_CF") == "1"
	var err error
	if cfg.RateRPS, err = envFloat("MIXIA_RATE_RPS"); err != nil {
		return cfg, 0, err
	}
	if cfg.RateBurst, err = envFloat("MIXIA_RATE_BURST"); err != nil {
		return cfg, 0, err
	}
	return cfg, quota, nil
}

// serve runs until ctx ends, then drains in-flight requests.
func serve(ctx context.Context, dir string) error {
	cfg, quota, err := loadConfig()
	if err != nil {
		return err
	}
	st, err := store.Open(dir, quota)
	if err != nil {
		return err
	}
	defer st.Close()
	cfg.Store = st
	cfg.Log = log.Default()
	handler := api.New(cfg)

	srv := &http.Server{
		Addr:              envOr("MIXIA_ADDR", defaultAddr),
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		// Sized for a 96 MiB rotate over a slow link.
		ReadTimeout:    15 * time.Minute,
		WriteTimeout:   15 * time.Minute,
		IdleTimeout:    2 * time.Minute,
		MaxHeaderBytes: 32 << 10,
		// net/http's own messages can quote client input.
		ErrorLog: log.New(io.Discard, "", 0),
	}

	go handler.RunJanitor(ctx)

	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServe() }()
	log.Printf("listening on %s", srv.Addr)

	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	log.Printf("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownGrace)
	defer cancel()
	return srv.Shutdown(shutdownCtx)
}

func verify(out io.Writer, dir string) error {
	sum, err := store.Verify(dir)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "ledger:    ok, %d entries, head %d\n", sum.Entries, sum.Head)
	fmt.Fprintf(out, "genesis:   %s\n", sum.GenesisHash)
	fmt.Fprintf(out, "head hash: %s\n", sum.HeadHash)
	fmt.Fprintf(out, "devices:   %d active (%d admin), %d revoked\n", sum.DevicesActive, sum.Admins, sum.DevicesRevoked)
	fmt.Fprintf(out, "vaults:    %d\n", sum.Vaults)
	fmt.Fprintf(out, "changes:   %d (%d bytes)\n", sum.Changes, sum.ChangeBytes)
	fmt.Fprintf(out, "keys:      %d\n", sum.Keys)
	fmt.Fprintf(out, "blobs:     %d (%d bytes)\n", sum.Blobs, sum.BlobBytes)
	fmt.Fprintf(out, "pairs:     %d\n", sum.OpenPairs)
	fmt.Fprintf(out, "audit:     %d events\n", sum.AuditEvents)
	return nil
}
