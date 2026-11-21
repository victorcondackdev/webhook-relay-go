// Package api exposes a relay.Engine over HTTP/JSON.
//
//	POST   /v1/endpoints                  create an endpoint (returns its signing secret once)
//	GET    /v1/endpoints                  list endpoints
//	GET    /v1/endpoints/{id}             get an endpoint
//	PATCH  /v1/endpoints/{id}             update, disable/enable, rotate_secret
//	DELETE /v1/endpoints/{id}             delete an endpoint and its deliveries
//	GET    /v1/endpoints/{id}/secret      current signing keys
//	POST   /v1/endpoints/{id}/replay      re-send retained messages (?since=RFC3339)
//	POST   /v1/messages                   publish; fans out to subscribed endpoints
//	GET    /v1/messages/{id}              message and its deliveries
//	GET    /v1/messages/{id}/attempts     attempt log
//	GET    /v1/dlq                        dead-lettered deliveries (?endpoint_id=&limit=)
//	POST   /v1/dlq/{id}/retry             move a dead delivery back to pending
//	GET    /healthz                       liveness
//	GET    /metrics                       Prometheus metrics
//
// Errors are RFC 9457 problem details (application/problem+json).
package api

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/victorcondackdev/webhook-relay-go/relay"
	"github.com/victorcondackdev/webhook-relay-go/signature"
)

// Options configures the handler.
type Options struct {
	// Token, if set, is required as "Authorization: Bearer <token>" on every
	// /v1 route.
	Token string
	// MaxBodyBytes bounds request bodies. Default 1 MiB.
	MaxBodyBytes int64
	Logger       *slog.Logger
}

type server struct {
	eng  *relay.Engine
	opts Options
	log  *slog.Logger
}

// New returns the HTTP handler for eng.
func New(eng *relay.Engine, opts Options) http.Handler {
	if opts.MaxBodyBytes <= 0 {
		opts.MaxBodyBytes = 1 << 20
	}
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.NewJSONHandler(io.Discard, nil))
	}
	s := &server{eng: eng, opts: opts, log: opts.Logger}
	mux := http.NewServeMux()
	v1 := func(pattern string, h http.HandlerFunc) { mux.Handle(pattern, s.auth(h)) }
	v1("POST /v1/endpoints", s.createEndpoint)
	v1("GET /v1/endpoints", s.listEndpoints)
	v1("GET /v1/endpoints/{id}", s.getEndpoint)
	v1("PATCH /v1/endpoints/{id}", s.patchEndpoint)
	v1("DELETE /v1/endpoints/{id}", s.deleteEndpoint)
	v1("GET /v1/endpoints/{id}/secret", s.getSecret)
	v1("POST /v1/endpoints/{id}/replay", s.replay)
	v1("POST /v1/messages", s.publish)
	v1("GET /v1/messages/{id}", s.getMessage)
	v1("GET /v1/messages/{id}/attempts", s.attempts)
	v1("GET /v1/dlq", s.listDLQ)
	v1("POST /v1/dlq/{id}/retry", s.retryDLQ)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		if err := eng.WriteMetrics(r.Context(), w); err != nil {
			s.log.Error("write metrics", "err", err)
		}
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		problem(w, http.StatusNotFound, "not-found", "Not Found", "no route for "+r.Method+" "+r.URL.Path)
	})
	return s.logRequests(s.recover(mux))
}

// Problem is an RFC 9457 problem details object.
type Problem struct {
	Type   string `json:"type"`
	Title  string `json:"title"`
	Status int    `json:"status"`
	Detail string `json:"detail,omitempty"`
}

const problemBase = "urn:webhook-relay:problem:"

func problem(w http.ResponseWriter, status int, slug, title, detail string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(Problem{Type: problemBase + slug, Title: title, Status: status, Detail: detail})
}

// fail maps engine errors to problem responses.
func (s *server) fail(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, relay.ErrNotFound):
		problem(w, http.StatusNotFound, "not-found", "Not Found", err.Error())
	case errors.Is(err, relay.ErrBlockedDestination):
		problem(w, http.StatusUnprocessableEntity, "blocked-destination", "Destination Not Allowed", err.Error())
	case errors.Is(err, relay.ErrInvalid):
		problem(w, http.StatusUnprocessableEntity, "invalid-request", "Invalid Request", err.Error())
	case errors.Is(err, relay.ErrPayloadTooLarge):
		problem(w, http.StatusRequestEntityTooLarge, "payload-too-large", "Payload Too Large", err.Error())
	case errors.Is(err, relay.ErrIdempotencyConflict):
		problem(w, http.StatusConflict, "idempotency-conflict", "Idempotency Key Conflict", err.Error())
	case errors.Is(err, relay.ErrNotDead):
		problem(w, http.StatusConflict, "not-dead-lettered", "Delivery Not Dead-Lettered", err.Error())
	case errors.Is(err, relay.ErrEndpointDisabled):
		problem(w, http.StatusConflict, "endpoint-disabled", "Endpoint Disabled", err.Error())
	default:
		s.log.Error("internal error", "err", err)
		problem(w, http.StatusInternalServerError, "internal", "Internal Server Error", "")
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// decode reads a JSON body strictly: unknown fields and trailing data are
// rejected, and the body is size-limited.
func (s *server) decode(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, s.opts.MaxBodyBytes)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			problem(w, http.StatusRequestEntityTooLarge, "payload-too-large", "Payload Too Large", fmt.Sprintf("request body exceeds %d bytes", mbe.Limit))
			return false
		}
		problem(w, http.StatusBadRequest, "malformed-json", "Malformed JSON", err.Error())
		return false
	}
	if dec.More() {
		problem(w, http.StatusBadRequest, "malformed-json", "Malformed JSON", "unexpected data after the JSON object")
		return false
	}
	return true
}

func (s *server) auth(next http.Handler) http.Handler {
	if s.opts.Token == "" {
		return next
	}
	want := []byte("Bearer " + s.opts.Token)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), want) != 1 {
			w.Header().Set("WWW-Authenticate", `Bearer realm="webhook-relay"`)
			problem(w, http.StatusUnauthorized, "unauthorized", "Unauthorized", "missing or invalid bearer token")
			return
		}
		next.ServeHTTP(w, r)
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

func (s *server) logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		if r.URL.Path == "/healthz" || r.URL.Path == "/metrics" {
			return
		}
		s.log.Info("http request", "method", r.Method, "path", r.URL.Path, "status", rec.status, "duration", time.Since(start))
	})
}

func (s *server) recover(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if v := recover(); v != nil {
				if v == http.ErrAbortHandler {
					panic(v)
				}
				s.log.Error("panic", "value", fmt.Sprint(v), "path", r.URL.Path)
				problem(w, http.StatusInternalServerError, "internal", "Internal Server Error", "")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// endpointView is the public JSON shape of an endpoint. Secrets are only
// included on creation and rotation; ed25519 public keys are always shown.
type endpointView struct {
	ID             string              `json:"id"`
	URL            string              `json:"url"`
	Description    string              `json:"description,omitempty"`
	EventTypes     []string            `json:"event_types"`
	Signing        relay.SigningScheme `json:"signing"`
	Secret         string              `json:"secret,omitempty"`
	PublicKey      string              `json:"public_key,omitempty"`
	Ordered        bool                `json:"ordered"`
	MaxConcurrency int                 `json:"max_concurrency,omitempty"`
	RateLimit      float64             `json:"rate_limit,omitempty"`
	Burst          int                 `json:"burst,omitempty"`
	Disabled       bool                `json:"disabled"`
	DisabledReason string              `json:"disabled_reason,omitempty"`
	CreatedAt      time.Time           `json:"created_at"`
	UpdatedAt      time.Time           `json:"updated_at"`
}

func view(ep relay.Endpoint, withSecret bool) endpointView {
	v := endpointView{
		ID: ep.ID, URL: ep.URL, Description: ep.Description, EventTypes: ep.EventTypes, Signing: ep.Signing,
		Ordered: ep.Ordered, MaxConcurrency: ep.MaxConcurrency, RateLimit: ep.RateLimit, Burst: ep.Burst,
		Disabled: ep.Disabled, DisabledReason: ep.DisabledReason, CreatedAt: ep.CreatedAt, UpdatedAt: ep.UpdatedAt,
	}
	if v.EventTypes == nil {
		v.EventTypes = []string{}
	}
	if n := len(ep.Keys); n > 0 {
		newest := ep.Keys[n-1].Key
		if withSecret {
			v.Secret = newest
		}
		v.PublicKey = publicKey(ep.Signing, newest)
	}
	return v
}

func publicKey(scheme relay.SigningScheme, key string) string {
	if scheme != relay.SigningEd25519 {
		return ""
	}
	sk, err := signature.ParseSigningKey(key)
	if err != nil {
		return ""
	}
	return sk.Public().String()
}

type createEndpointReq struct {
	URL            string              `json:"url"`
	Description    string              `json:"description"`
	EventTypes     []string            `json:"event_types"`
	Signing        relay.SigningScheme `json:"signing"`
	Secret         string              `json:"secret"`
	Ordered        bool                `json:"ordered"`
	MaxConcurrency int                 `json:"max_concurrency"`
	RateLimit      float64             `json:"rate_limit"`
	Burst          int                 `json:"burst"`
}

func (s *server) createEndpoint(w http.ResponseWriter, r *http.Request) {
	var req createEndpointReq
	if !s.decode(w, r, &req) {
		return
	}
	ep, err := s.eng.CreateEndpoint(r.Context(), relay.EndpointSpec{
		URL: req.URL, Description: req.Description, EventTypes: req.EventTypes, Signing: req.Signing, Secret: req.Secret,
		Ordered: req.Ordered, MaxConcurrency: req.MaxConcurrency, RateLimit: req.RateLimit, Burst: req.Burst,
	})
	if err != nil {
		s.fail(w, err)
		return
	}
	w.Header().Set("Location", "/v1/endpoints/"+ep.ID)
	writeJSON(w, http.StatusCreated, view(ep, true))
}

func (s *server) listEndpoints(w http.ResponseWriter, r *http.Request) {
	eps, err := s.eng.ListEndpoints(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	out := make([]endpointView, len(eps))
	for i, ep := range eps {
		out[i] = view(ep, false)
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": out})
}

func (s *server) getEndpoint(w http.ResponseWriter, r *http.Request) {
	ep, err := s.eng.GetEndpoint(r.Context(), r.PathValue("id"))
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, view(ep, false))
}

type patchEndpointReq struct {
	URL            *string   `json:"url"`
	Description    *string   `json:"description"`
	EventTypes     *[]string `json:"event_types"`
	Disabled       *bool     `json:"disabled"`
	Ordered        *bool     `json:"ordered"`
	MaxConcurrency *int      `json:"max_concurrency"`
	RateLimit      *float64  `json:"rate_limit"`
	Burst          *int      `json:"burst"`
	RotateSecret   bool      `json:"rotate_secret"`
}

func (s *server) patchEndpoint(w http.ResponseWriter, r *http.Request) {
	var req patchEndpointReq
	if !s.decode(w, r, &req) {
		return
	}
	ep, err := s.eng.UpdateEndpoint(r.Context(), r.PathValue("id"), relay.EndpointPatch{
		URL: req.URL, Description: req.Description, EventTypes: req.EventTypes, Disabled: req.Disabled,
		Ordered: req.Ordered, MaxConcurrency: req.MaxConcurrency, RateLimit: req.RateLimit, Burst: req.Burst,
		RotateSecret: req.RotateSecret,
	})
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, view(ep, req.RotateSecret))
}

func (s *server) deleteEndpoint(w http.ResponseWriter, r *http.Request) {
	if err := s.eng.DeleteEndpoint(r.Context(), r.PathValue("id")); err != nil {
		s.fail(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type keyView struct {
	Key       string     `json:"key"`
	PublicKey string     `json:"public_key,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

func (s *server) getSecret(w http.ResponseWriter, r *http.Request) {
	ep, err := s.eng.GetEndpoint(r.Context(), r.PathValue("id"))
	if err != nil {
		s.fail(w, err)
		return
	}
	keys := []keyView{}
	for _, k := range ep.ActiveKeys(time.Now()) {
		keys = append(keys, keyView{Key: k.Key, PublicKey: publicKey(ep.Signing, k.Key), CreatedAt: k.CreatedAt, ExpiresAt: k.ExpiresAt})
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{"signing": ep.Signing, "keys": keys})
}

func (s *server) replay(w http.ResponseWriter, r *http.Request) {
	var since time.Time
	if v := r.URL.Query().Get("since"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			problem(w, http.StatusBadRequest, "invalid-request", "Invalid Request", "since must be an RFC 3339 timestamp")
			return
		}
		since = t
	}
	n, err := s.eng.Replay(r.Context(), r.PathValue("id"), since)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"scheduled": n})
}

type publishReq struct {
	EventType      string          `json:"event_type"`
	Payload        json.RawMessage `json:"payload"`
	IdempotencyKey string          `json:"idempotency_key"`
}

type messageView struct {
	relay.Message
	Deliveries []relay.Delivery `json:"deliveries"`
}

func (s *server) publish(w http.ResponseWriter, r *http.Request) {
	var req publishReq
	if !s.decode(w, r, &req) {
		return
	}
	key := req.IdempotencyKey
	if h := r.Header.Get("Idempotency-Key"); h != "" {
		if key != "" && key != h {
			problem(w, http.StatusBadRequest, "invalid-request", "Invalid Request", "Idempotency-Key header and idempotency_key field differ")
			return
		}
		key = h
	}
	msg, dlvs, created, err := s.eng.Publish(r.Context(), relay.PublishInput{
		EventType: req.EventType, Payload: req.Payload, IdempotencyKey: key,
		TraceParent: r.Header.Get("traceparent"), TraceState: r.Header.Get("tracestate"),
	})
	if err != nil {
		s.fail(w, err)
		return
	}
	if dlvs == nil {
		dlvs = []relay.Delivery{}
	}
	status := http.StatusAccepted
	if !created {
		status = http.StatusOK
		w.Header().Set("Idempotent-Replayed", "true")
	}
	w.Header().Set("Location", "/v1/messages/"+msg.ID)
	writeJSON(w, status, messageView{Message: msg, Deliveries: dlvs})
}

func (s *server) getMessage(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	msg, err := s.eng.GetMessage(r.Context(), id)
	if err != nil {
		s.fail(w, err)
		return
	}
	dlvs, err := s.eng.Deliveries(r.Context(), id)
	if err != nil {
		s.fail(w, err)
		return
	}
	if dlvs == nil {
		dlvs = []relay.Delivery{}
	}
	writeJSON(w, http.StatusOK, messageView{Message: msg, Deliveries: dlvs})
}

func (s *server) attempts(w http.ResponseWriter, r *http.Request) {
	atts, err := s.eng.Attempts(r.Context(), r.PathValue("id"))
	if err != nil {
		s.fail(w, err)
		return
	}
	if atts == nil {
		atts = []relay.Attempt{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": atts})
}

func (s *server) listDLQ(w http.ResponseWriter, r *http.Request) {
	limit := 100
	if v := r.URL.Query().Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 1000 {
			problem(w, http.StatusBadRequest, "invalid-request", "Invalid Request", "limit must be between 1 and 1000")
			return
		}
		limit = n
	}
	dead, err := s.eng.DeadLetters(r.Context(), strings.TrimSpace(r.URL.Query().Get("endpoint_id")), limit)
	if err != nil {
		s.fail(w, err)
		return
	}
	if dead == nil {
		dead = []relay.Delivery{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": dead})
}

func (s *server) retryDLQ(w http.ResponseWriter, r *http.Request) {
	d, err := s.eng.RetryDead(r.Context(), r.PathValue("id"))
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusAccepted, d)
}
