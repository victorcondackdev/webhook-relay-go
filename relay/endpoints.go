package relay

import (
	"context"
	"fmt"
	"time"

	"github.com/victorcondackdev/webhook-relay-go/signature"
)

// EndpointSpec describes an endpoint to create.
type EndpointSpec struct {
	URL            string
	Description    string
	EventTypes     []string
	Signing        SigningScheme // default SigningHMAC
	Secret         string        // optional caller-supplied whsec_/whsk_ key; generated if empty
	Ordered        bool
	MaxConcurrency int
	RateLimit      float64
	Burst          int
}

// EndpointPatch changes an endpoint. Nil fields are left as they are.
type EndpointPatch struct {
	URL            *string
	Description    *string
	EventTypes     *[]string
	Disabled       *bool
	Ordered        *bool
	MaxConcurrency *int
	RateLimit      *float64
	Burst          *int
	// RotateSecret adds a new signing key. The previous keys keep signing
	// for Config.KeyRotationOverlap, so receivers can switch without
	// rejecting deliveries.
	RotateSecret bool
}

func (e *Engine) validateSpec(url string, events []string, conc int, rate float64, burst int) error {
	if err := e.cfg.Guard.ValidateURL(url); err != nil {
		return err
	}
	for _, ev := range events {
		if ev != "*" && !eventTypeRe.MatchString(ev) && !eventTypeRe.MatchString(ev[:max(len(ev)-1, 0)]) {
			return fmt.Errorf("%w: invalid event type filter %q", ErrInvalid, ev)
		}
	}
	if conc < 0 || conc > 1024 || rate < 0 || burst < 0 {
		return fmt.Errorf("%w: concurrency, rate_limit and burst must be non-negative (concurrency at most 1024)", ErrInvalid)
	}
	return nil
}

func newKey(scheme SigningScheme) (string, error) {
	if scheme == SigningEd25519 {
		k, err := signature.GenerateSigningKey()
		return k.String(), err
	}
	s, err := signature.GenerateSecret()
	return s.String(), err
}

func checkKey(scheme SigningScheme, key string) error {
	var err error
	if scheme == SigningEd25519 {
		_, err = signature.ParseSigningKey(key)
	} else {
		_, err = signature.ParseSecret(key)
	}
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	return nil
}

// CreateEndpoint registers an endpoint. The URL is validated against the
// destination policy and a signing key is generated unless one is supplied.
func (e *Engine) CreateEndpoint(ctx context.Context, spec EndpointSpec) (Endpoint, error) {
	if spec.Signing == "" {
		spec.Signing = SigningHMAC
	}
	if spec.Signing != SigningHMAC && spec.Signing != SigningEd25519 {
		return Endpoint{}, fmt.Errorf("%w: signing must be %q or %q", ErrInvalid, SigningHMAC, SigningEd25519)
	}
	if err := e.validateSpec(spec.URL, spec.EventTypes, spec.MaxConcurrency, spec.RateLimit, spec.Burst); err != nil {
		return Endpoint{}, err
	}
	key := spec.Secret
	if key == "" {
		var err error
		if key, err = newKey(spec.Signing); err != nil {
			return Endpoint{}, err
		}
	} else if err := checkKey(spec.Signing, key); err != nil {
		return Endpoint{}, err
	}
	now := e.clock.Now()
	ep := Endpoint{
		ID: NewID("ep"), URL: spec.URL, Description: spec.Description, EventTypes: spec.EventTypes,
		Signing: spec.Signing, Keys: []EndpointKey{{Key: key, CreatedAt: now}},
		Ordered: spec.Ordered, MaxConcurrency: spec.MaxConcurrency, RateLimit: spec.RateLimit, Burst: spec.Burst,
		CreatedAt: now, UpdatedAt: now,
	}
	if err := e.store.PutEndpoint(ctx, ep); err != nil {
		return Endpoint{}, err
	}
	e.mu.Lock()
	e.laneLocked(ep)
	e.mu.Unlock()
	return ep, nil
}

// GetEndpoint returns an endpoint.
func (e *Engine) GetEndpoint(ctx context.Context, id string) (Endpoint, error) {
	return e.store.GetEndpoint(ctx, id)
}

// ListEndpoints returns all endpoints, oldest first.
func (e *Engine) ListEndpoints(ctx context.Context) ([]Endpoint, error) {
	return e.store.ListEndpoints(ctx)
}

// UpdateEndpoint applies p. Disabling an endpoint dead-letters its pending
// deliveries; re-enabling it resets its circuit breaker.
func (e *Engine) UpdateEndpoint(ctx context.Context, id string, p EndpointPatch) (Endpoint, error) {
	ep, err := e.store.GetEndpoint(ctx, id)
	if err != nil {
		return Endpoint{}, err
	}
	now := e.clock.Now()
	if p.URL != nil {
		ep.URL = *p.URL
	}
	if p.Description != nil {
		ep.Description = *p.Description
	}
	if p.EventTypes != nil {
		ep.EventTypes = *p.EventTypes
	}
	if p.Ordered != nil {
		ep.Ordered = *p.Ordered
	}
	if p.MaxConcurrency != nil {
		ep.MaxConcurrency = *p.MaxConcurrency
	}
	if p.RateLimit != nil {
		ep.RateLimit = *p.RateLimit
	}
	if p.Burst != nil {
		ep.Burst = *p.Burst
	}
	if err := e.validateSpec(ep.URL, ep.EventTypes, ep.MaxConcurrency, ep.RateLimit, ep.Burst); err != nil {
		return Endpoint{}, err
	}
	if p.RotateSecret {
		key, err := newKey(ep.Signing)
		if err != nil {
			return Endpoint{}, err
		}
		expires := now.Add(e.cfg.KeyRotationOverlap)
		kept := ep.Keys[:0:0]
		for _, k := range ep.Keys {
			if k.ExpiresAt != nil && !now.Before(*k.ExpiresAt) {
				continue // already expired: drop it
			}
			if k.ExpiresAt == nil || k.ExpiresAt.After(expires) {
				k.ExpiresAt = &expires
			}
			kept = append(kept, k)
		}
		ep.Keys = append(kept, EndpointKey{Key: key, CreatedAt: now})
	}
	disabling, enabling := false, false
	if p.Disabled != nil && *p.Disabled != ep.Disabled {
		ep.Disabled = *p.Disabled
		if ep.Disabled {
			disabling = true
			ep.DisabledReason = "disabled via API at " + now.UTC().Format(time.RFC3339)
		} else {
			enabling = true
			ep.DisabledReason = ""
		}
	}
	ep.UpdatedAt = now
	if err := e.store.PutEndpoint(ctx, ep); err != nil {
		return Endpoint{}, err
	}
	e.mu.Lock()
	l := e.laneLocked(ep)
	if enabling {
		l.breaker = NewBreaker(e.cfg.Breaker)
	}
	e.mu.Unlock()
	if disabling {
		e.disableEndpoint(ep.ID, ep.DisabledReason)
	}
	e.signal()
	return ep, nil
}

// DeleteEndpoint removes an endpoint and drops its deliveries.
func (e *Engine) DeleteEndpoint(ctx context.Context, id string) error {
	if err := e.store.DeleteEndpoint(ctx, id); err != nil {
		return err
	}
	e.mu.Lock()
	e.removeLaneLocked(id)
	e.mu.Unlock()
	return nil
}
