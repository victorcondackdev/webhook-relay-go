// Command relayd runs the webhook relay as an HTTP service.
//
// Configuration comes from flags, each of which can also be set through the
// environment variable shown in -help:
//
//	relayd -addr :8080 -data /var/lib/webhook-relay -fsync always
//
// On SIGINT or SIGTERM relayd stops accepting API requests, drains in-flight
// deliveries for up to -shutdown-timeout, and closes the write-ahead log.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/victorcondackdev/webhook-relay-go/api"
	"github.com/victorcondackdev/webhook-relay-go/relay"
	"github.com/victorcondackdev/webhook-relay-go/wal"
)

var version = "dev"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:], os.Getenv, os.Stderr, nil); err != nil {
		fmt.Fprintln(os.Stderr, "relayd:", err)
		os.Exit(1)
	}
}

type config struct {
	addr            string
	store           string
	dataDir         string
	fsync           string
	workers         int
	allowCIDRs      string
	allowHTTP       bool
	followRedirects bool
	token           string
	requestTimeout  time.Duration
	shutdownTimeout time.Duration
	compactEvery    time.Duration
	logLevel        string
}

func parseFlags(args []string, getenv func(string) string, out io.Writer) (config, error) {
	var c config
	fs := flag.NewFlagSet("relayd", flag.ContinueOnError)
	fs.SetOutput(out)
	env := func(name, def string) string {
		if v := getenv(name); v != "" {
			return v
		}
		return def
	}
	envDur := func(name string, def time.Duration) time.Duration {
		if d, err := time.ParseDuration(getenv(name)); err == nil {
			return d
		}
		return def
	}
	envInt := func(name string, def int) int {
		var n int
		if _, err := fmt.Sscan(getenv(name), &n); err == nil {
			return n
		}
		return def
	}
	fs.StringVar(&c.addr, "addr", env("RELAY_ADDR", ":8080"), "listen address (RELAY_ADDR)")
	fs.StringVar(&c.store, "store", env("RELAY_STORE", "wal"), "store: wal or memory (RELAY_STORE)")
	fs.StringVar(&c.dataDir, "data", env("RELAY_DATA_DIR", "data"), "WAL directory (RELAY_DATA_DIR)")
	fs.StringVar(&c.fsync, "fsync", env("RELAY_FSYNC", "always"), "fsync policy: always, interval or never (RELAY_FSYNC)")
	fs.IntVar(&c.workers, "workers", envInt("RELAY_WORKERS", 32), "concurrent deliveries (RELAY_WORKERS)")
	fs.StringVar(&c.allowCIDRs, "allow-cidrs", env("RELAY_ALLOW_CIDRS", ""), "comma-separated private ranges endpoints may target (RELAY_ALLOW_CIDRS)")
	fs.BoolVar(&c.allowHTTP, "allow-http", env("RELAY_ALLOW_HTTP", "") == "true", "allow plain-http endpoint URLs (RELAY_ALLOW_HTTP)")
	fs.BoolVar(&c.followRedirects, "follow-redirects", env("RELAY_FOLLOW_REDIRECTS", "") == "true", "follow up to 3 redirects, each SSRF-checked (RELAY_FOLLOW_REDIRECTS)")
	fs.DurationVar(&c.requestTimeout, "request-timeout", envDur("RELAY_REQUEST_TIMEOUT", 15*time.Second), "per-attempt timeout (RELAY_REQUEST_TIMEOUT)")
	fs.DurationVar(&c.shutdownTimeout, "shutdown-timeout", envDur("RELAY_SHUTDOWN_TIMEOUT", 30*time.Second), "drain deadline on shutdown (RELAY_SHUTDOWN_TIMEOUT)")
	fs.DurationVar(&c.compactEvery, "compact-interval", envDur("RELAY_COMPACT_INTERVAL", time.Minute), "how often to check whether the WAL needs compaction (RELAY_COMPACT_INTERVAL)")
	fs.StringVar(&c.logLevel, "log-level", env("RELAY_LOG_LEVEL", "info"), "debug, info, warn or error (RELAY_LOG_LEVEL)")
	showVersion := fs.Bool("version", false, "print version and exit")
	if err := fs.Parse(args); err != nil {
		return c, err
	}
	if *showVersion {
		fmt.Fprintln(out, "relayd", version)
		return c, flag.ErrHelp
	}
	c.token = getenv("RELAY_API_TOKEN") // never a flag: it would show up in ps
	return c, nil
}

// run starts the service and blocks until ctx is cancelled. ready, if not
// nil, receives the bound address once the listener is up.
func run(ctx context.Context, args []string, getenv func(string) string, logOut io.Writer, ready func(addr string)) error {
	cfg, err := parseFlags(args, getenv, logOut)
	if errors.Is(err, flag.ErrHelp) {
		return nil
	}
	if err != nil {
		return err
	}
	var level slog.Level
	if err := level.UnmarshalText([]byte(cfg.logLevel)); err != nil {
		return fmt.Errorf("log level: %w", err)
	}
	logger := slog.New(slog.NewJSONHandler(logOut, &slog.HandlerOptions{Level: level}))

	guard := &relay.Guard{AllowHTTP: cfg.allowHTTP}
	for _, s := range strings.Split(cfg.allowCIDRs, ",") {
		if s = strings.TrimSpace(s); s == "" {
			continue
		}
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return fmt.Errorf("allow-cidrs: %w", err)
		}
		guard.Allow = append(guard.Allow, p)
	}

	var store relay.Store
	var fileStore *relay.FileStore
	switch cfg.store {
	case "memory":
		store = relay.NewMemStore()
		logger.Warn("using the in-memory store: deliveries are lost on restart")
	case "wal":
		policy, err := wal.ParseSyncPolicy(cfg.fsync)
		if err != nil {
			return err
		}
		fileStore, err = relay.OpenFileStore(relay.FileStoreOptions{Dir: cfg.dataDir, Sync: policy})
		if err != nil {
			return fmt.Errorf("open wal: %w", err)
		}
		rec := fileStore.Recovery()
		logger.Info("wal recovered", "dir", cfg.dataDir, "records", rec.Records, "torn_bytes", rec.TruncatedBytes,
			"discarded_compaction", rec.DiscardedCompaction, "fsync", policy.String())
		store = fileStore
	default:
		return fmt.Errorf("unknown store %q", cfg.store)
	}
	defer store.Close()

	eng, err := relay.New(relay.Config{
		Store: store, Workers: cfg.workers, Guard: guard, FollowRedirects: cfg.followRedirects,
		RequestTimeout: cfg.requestTimeout, Logger: logger, UserAgent: "webhook-relay-go/" + version,
	})
	if err != nil {
		return err
	}
	if err := eng.Start(ctx); err != nil {
		return err
	}

	ln, err := net.Listen("tcp", cfg.addr)
	if err != nil {
		eng.Shutdown(context.Background())
		return err
	}
	srv := &http.Server{
		Handler:           api.New(eng, api.Options{Token: cfg.token, Logger: logger}),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	if cfg.token == "" {
		logger.Warn("RELAY_API_TOKEN is not set: the API is unauthenticated")
	}
	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve(ln) }()
	logger.Info("relayd listening", "addr", ln.Addr().String(), "version", version)
	if ready != nil {
		ready(ln.Addr().String())
	}

	compactDone := make(chan struct{})
	go func() {
		defer close(compactDone)
		if fileStore == nil || cfg.compactEvery <= 0 {
			return
		}
		t := time.NewTicker(cfg.compactEvery)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if fileStore.NeedsCompaction() {
					before := fileStore.LogBytes()
					if err := fileStore.Compact(ctx); err != nil {
						logger.Error("wal compaction", "err", err)
						continue
					}
					logger.Info("wal compacted", "before_bytes", before, "after_bytes", fileStore.LogBytes())
				}
			}
		}
	}()

	select {
	case <-ctx.Done():
	case err := <-serveErr:
		eng.Shutdown(context.Background())
		return err
	}
	logger.Info("shutting down", "drain_timeout", cfg.shutdownTimeout.String())
	sctx, cancel := context.WithTimeout(context.Background(), cfg.shutdownTimeout)
	defer cancel()
	// Stop taking new messages first, then drain deliveries.
	if err := srv.Shutdown(sctx); err != nil {
		logger.Warn("http shutdown", "err", err)
	}
	if err := eng.Shutdown(sctx); err != nil {
		logger.Warn("delivery drain incomplete; remaining deliveries stay pending", "err", err)
	}
	<-compactDone
	logger.Info("stopped")
	return nil
}
