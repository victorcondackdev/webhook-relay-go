package relay

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"
)

// envelope is the JSON body sent to receivers, following the payload
// structure recommended by Standard Webhooks.
type envelope struct {
	Type      string          `json:"type"`
	Timestamp time.Time       `json:"timestamp"`
	Data      json.RawMessage `json:"data"`
}

// Body returns the exact bytes the engine sends for msg.
func Body(msg Message) []byte {
	b, _ := json.Marshal(envelope{Type: msg.EventType, Timestamp: msg.CreatedAt.UTC(), Data: msg.Payload})
	return b
}

// send performs one attempt. It returns the attempt record and, for
// throttling responses, the receiver's Retry-After if it sent one.
func (e *Engine) send(ctx context.Context, ep Endpoint, msg Message, d Delivery) (att Attempt, retryAfter time.Duration, hasRetryAfter bool) {
	start := e.clock.Now()
	att = Attempt{
		ID: NewID("att"), DeliveryID: d.ID, MessageID: msg.ID, EndpointID: ep.ID,
		Number: d.Attempts + 1, StartedAt: start,
	}
	wallStart := time.Now()
	fail := func(o Outcome, err error) (Attempt, time.Duration, bool) {
		att.Outcome, att.Error, att.Duration = o, truncate(err.Error(), 512), time.Since(wallStart)
		return att, 0, false
	}

	signer, err := e.signerFor(ep, start)
	if err != nil {
		return fail(OutcomeConfig, err)
	}
	body := Body(msg)
	ctx, cancel := context.WithTimeout(ctx, e.cfg.RequestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ep.URL, bytes.NewReader(body))
	if err != nil {
		return fail(OutcomeConfig, err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", e.cfg.UserAgent)
	signer.SetHeaders(req.Header, msg.ID, start, body)
	if msg.TraceParent != "" {
		req.Header.Set("traceparent", msg.TraceParent)
		if msg.TraceState != "" {
			req.Header.Set("tracestate", msg.TraceState)
		}
	}

	resp, err := e.client.Do(req)
	if err != nil {
		switch {
		case isBlocked(err):
			return fail(OutcomeBlocked, err)
		case isTimeout(err):
			return fail(OutcomeTimeout, err)
		default:
			return fail(OutcomeNetwork, err)
		}
	}
	snippet, rerr := io.ReadAll(io.LimitReader(resp.Body, int64(e.cfg.MaxResponseBytes)))
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxDrainBytes)) // allow connection reuse
	resp.Body.Close()
	att.Duration = time.Since(wallStart)
	att.StatusCode = resp.StatusCode
	att.Response = sanitize(snippet)

	switch code := resp.StatusCode; {
	case code >= 200 && code < 300:
		att.Outcome = OutcomeSuccess
		if rerr != nil && isTimeout(rerr) {
			// The receiver answered 2xx; a slow body does not undo that.
			att.Error = "response body read timed out after 2xx"
		}
	case code == http.StatusGone:
		att.Outcome = OutcomeGone
	case code == http.StatusTooManyRequests || code == http.StatusServiceUnavailable:
		ra, ok := ParseRetryAfter(resp.Header.Get("Retry-After"), e.clock.Now())
		if code == http.StatusTooManyRequests || ok {
			att.Outcome = OutcomeThrottled
		} else {
			att.Outcome = OutcomeHTTP5xx
		}
		retryAfter, hasRetryAfter = ra, ok
	case code >= 300 && code < 400:
		att.Outcome = OutcomeRedirect
		att.Error = "redirect to " + truncate(resp.Header.Get("Location"), 256) + " not followed"
	case code >= 500:
		att.Outcome = OutcomeHTTP5xx
	default:
		att.Outcome = OutcomeHTTP4xx
	}
	return att, retryAfter, hasRetryAfter
}

func isTimeout(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n] + "…"
}

// sanitize makes a response snippet safe to store and log: invalid UTF-8 is
// replaced and control characters other than newline and tab are dropped.
func sanitize(b []byte) string {
	s := strings.ToValidUTF8(string(b), "�")
	return strings.Map(func(r rune) rune {
		if r < 0x20 && r != '\n' && r != '\t' {
			return -1
		}
		return r
	}, s)
}
