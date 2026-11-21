package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func env(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func TestRunServesAndShutsDown(t *testing.T) {
	var hits atomic.Int32
	merchant := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer merchant.Close()

	dir := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	addrCh := make(chan string, 1)
	logs := &syncBuffer{}
	done := make(chan error, 1)
	go func() {
		done <- run(ctx, []string{"-addr", "127.0.0.1:0", "-data", dir, "-fsync", "interval", "-compact-interval", "10ms"},
			env(map[string]string{"RELAY_ALLOW_CIDRS": "127.0.0.0/8", "RELAY_ALLOW_HTTP": "true", "RELAY_API_TOKEN": "t0k", "RELAY_WORKERS": "4"}),
			logs, func(a string) { addrCh <- a })
	}()
	var base string
	select {
	case a := <-addrCh:
		base = "http://" + a
	case err := <-done:
		t.Fatal(err)
	}

	call := func(method, path string, body any) map[string]any {
		b, _ := json.Marshal(body)
		req, _ := http.NewRequest(method, base+path, bytes.NewReader(b))
		req.Header.Set("Authorization", "Bearer t0k")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		raw, _ := io.ReadAll(resp.Body)
		var out map[string]any
		json.Unmarshal(raw, &out)
		if resp.StatusCode >= 300 {
			t.Fatalf("%s %s = %d %s", method, path, resp.StatusCode, raw)
		}
		return out
	}
	call("POST", "/v1/endpoints", map[string]any{"url": merchant.URL})
	call("POST", "/v1/messages", map[string]any{"event_type": "pix.received", "payload": map[string]int{"amount": 1}})
	deadline := time.Now().Add(5 * time.Second)
	for hits.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if hits.Load() != 1 {
		t.Fatal("message not delivered")
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	out := logs.String()
	for _, want := range []string{`"msg":"relayd listening"`, `"msg":"delivery attempt"`, `"msg":"stopped"`} {
		if !strings.Contains(out, want) {
			t.Errorf("log missing %s", want)
		}
	}

	// A second start recovers the endpoint from the WAL.
	ctx2, cancel2 := context.WithCancel(context.Background())
	go func() {
		done <- run(ctx2, []string{"-addr", "127.0.0.1:0", "-data", dir}, env(nil), logs, func(string) { cancel2() })
	}()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(logs.String(), `"msg":"relay started"`) || !strings.Contains(logs.String(), `"endpoints":1`) {
		t.Fatalf("endpoint not recovered:\n%s", logs.String())
	}
}

func TestRunMemoryStore(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	logs := &syncBuffer{}
	err := run(ctx, []string{"-addr", "127.0.0.1:0", "-store", "memory"}, env(nil), logs, func(string) { cancel() })
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(logs.String(), "in-memory store") || !strings.Contains(logs.String(), "unauthenticated") {
		t.Fatalf("warnings missing:\n%s", logs.String())
	}
}

func TestRunConfigErrors(t *testing.T) {
	tests := []struct {
		name string
		args []string
		env  map[string]string
		want string
	}{
		{"unknown store", []string{"-store", "redis"}, nil, "unknown store"},
		{"bad fsync", []string{"-fsync", "sometimes", "-data", t.TempDir()}, nil, "sync policy"},
		{"bad cidr", nil, map[string]string{"RELAY_ALLOW_CIDRS": "10.0.0.0/33"}, "allow-cidrs"},
		{"bad log level", []string{"-log-level", "loud"}, nil, "log level"},
		{"bad flag", []string{"-nope"}, nil, "flag provided but not defined"},
		{"bad addr", []string{"-addr", "256.0.0.1:99999", "-store", "memory"}, nil, "listen"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := run(context.Background(), tt.args, env(tt.env), io.Discard, nil)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err = %v, want %q", err, tt.want)
			}
		})
	}
	var out bytes.Buffer
	if err := run(context.Background(), []string{"-version"}, env(nil), &out, nil); err != nil || !strings.Contains(out.String(), "relayd dev") {
		t.Fatalf("-version: %v %q", err, out.String())
	}
	if c, _ := parseFlags(nil, env(map[string]string{"RELAY_REQUEST_TIMEOUT": "3s", "RELAY_WORKERS": "x"}), io.Discard); c.requestTimeout != 3*time.Second || c.workers != 32 {
		t.Fatalf("env parsing: %+v", c)
	}
}
