// Command receiver is a minimal merchant-side webhook consumer. It shows the
// three things every receiver must do:
//
//  1. Verify the signature over the raw body before trusting anything in it.
//  2. Deduplicate on webhook-id, because delivery is at-least-once.
//  3. Acknowledge quickly with a 2xx and do slow work asynchronously.
//
// Run it with the secret returned when the endpoint was created:
//
//	WEBHOOK_SECRET=whsec_... go run ./examples/receiver -addr :9000
//
// During a rotation pass both secrets, comma-separated.
package main

import (
	"encoding/json"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/victorcondackdev/webhook-relay-go/signature"
)

func main() {
	addr := flag.String("addr", ":9000", "listen address")
	flag.Parse()
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	v, err := signature.NewVerifier(strings.Split(os.Getenv("WEBHOOK_SECRET"), ",")...)
	if err != nil {
		logger.Error("WEBHOOK_SECRET must hold one or more whsec_ secrets or whpk_ public keys", "err", err)
		os.Exit(1)
	}
	h := newHandler(v, newDedup(24*time.Hour), logger)
	srv := &http.Server{Addr: *addr, Handler: h, ReadHeaderTimeout: 5 * time.Second}
	logger.Info("receiver listening", "addr", *addr)
	if err := srv.ListenAndServe(); err != nil {
		logger.Error("serve", "err", err)
		os.Exit(1)
	}
}

// event is the Standard Webhooks payload envelope sent by the relay.
type event struct {
	Type      string          `json:"type"`
	Timestamp time.Time       `json:"timestamp"`
	Data      json.RawMessage `json:"data"`
}

// dedup remembers processed webhook-ids for ttl. A production receiver would
// use its database (a unique index on the id, inserted in the same
// transaction as the business effect) so the check survives restarts.
type dedup struct {
	mu   sync.Mutex
	ttl  time.Duration
	seen map[string]time.Time
	now  func() time.Time
}

func newDedup(ttl time.Duration) *dedup {
	return &dedup{ttl: ttl, seen: map[string]time.Time{}, now: time.Now}
}

// firstTime records id and reports whether it had not been seen.
func (d *dedup) firstTime(id string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	now := d.now()
	if len(d.seen) > 10_000 {
		for k, at := range d.seen {
			if now.Sub(at) > d.ttl {
				delete(d.seen, k)
			}
		}
	}
	if at, ok := d.seen[id]; ok && now.Sub(at) <= d.ttl {
		return false
	}
	d.seen[id] = now
	return true
}

func newHandler(v *signature.Verifier, seen *dedup, logger *slog.Logger) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("POST /webhooks", v.Middleware(1<<20, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get(signature.HeaderID)
		if !seen.firstTime(id) {
			// Already processed: acknowledge again so the relay stops retrying.
			logger.Info("duplicate delivery ignored", "webhook_id", id)
			w.WriteHeader(http.StatusOK)
			return
		}
		var ev event
		if err := json.NewDecoder(r.Body).Decode(&ev); err != nil {
			http.Error(w, "bad payload", http.StatusBadRequest)
			return
		}
		switch ev.Type {
		case "pix.received", "charge.paid":
			// Enqueue the business effect here; do not block the response.
			logger.Info("payment event", "webhook_id", id, "type", ev.Type, "data", string(ev.Data))
		default:
			logger.Info("event ignored", "webhook_id", id, "type", ev.Type)
		}
		w.WriteHeader(http.StatusNoContent)
	})))
	return mux
}
