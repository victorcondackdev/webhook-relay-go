// Package signature signs and verifies webhook deliveries using a scheme
// compatible with the Standard Webhooks specification
// (https://www.standardwebhooks.com).
//
// Every delivery carries three headers:
//
//	webhook-id:        msg_2b6f...            (stable across retries; use it to deduplicate)
//	webhook-timestamp: 1767225600             (unix seconds of this attempt)
//	webhook-signature: v1,K5oZfzN95Z9UVu1Ef... (space-separated list of signatures)
//
// The signed content is the byte string
//
//	<webhook-id> "." <webhook-timestamp> "." <raw request body>
//
// A "v1" signature is the standard base64 encoding of HMAC-SHA256 over that
// content, keyed with the decoded bytes of a "whsec_" secret. A "v1a"
// signature is an ed25519 signature over the same content, verified with a
// "whpk_" public key; it lets receivers verify deliveries without holding a
// secret that could also be used to forge them.
//
// The header may contain several signatures. A sender rotating secrets signs
// with both the old and the new secret for an overlap window; a receiver
// accepts the delivery if any signature matches any secret it trusts. This
// gives zero-downtime rotation on both sides.
//
// Receivers import this package directly:
//
//	v, err := signature.NewVerifier("whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw")
//	...
//	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
//	if err := v.Verify(r.Header, body); err != nil {
//		http.Error(w, "invalid signature", http.StatusUnauthorized)
//		return
//	}
package signature

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Header names defined by the Standard Webhooks specification.
const (
	HeaderID        = "webhook-id"
	HeaderTimestamp = "webhook-timestamp"
	HeaderSignature = "webhook-signature"
)

// Key prefixes and signature version identifiers.
const (
	SecretPrefix     = "whsec_"
	SigningKeyPrefix = "whsk_"
	PublicKeyPrefix  = "whpk_"

	VersionHMAC    = "v1"
	VersionEd25519 = "v1a"
)

// DefaultTolerance is the maximum accepted distance between the
// webhook-timestamp header and the receiver's clock, in either direction.
const DefaultTolerance = 5 * time.Minute

// Verification and parsing errors. Verify wraps them, so use errors.Is.
var (
	ErrMissingHeaders    = errors.New("signature: missing webhook headers")
	ErrInvalidTimestamp  = errors.New("signature: invalid webhook-timestamp")
	ErrTimestampTooOld   = errors.New("signature: timestamp too old")
	ErrTimestampTooNew   = errors.New("signature: timestamp too far in the future")
	ErrNoMatch           = errors.New("signature: no matching signature")
	ErrInvalidKey        = errors.New("signature: invalid key")
	ErrNoKeys            = errors.New("signature: verifier has no keys")
	ErrPayloadTooLarge   = errors.New("signature: payload too large")
	errMalformedSigEntry = errors.New("signature: malformed signature entry")
)

// secretBytes is the length of generated HMAC secrets (192 bits, as in the
// reference implementations; the specification allows 24 to 64 bytes).
const secretBytes = 24

// Secret is a symmetric HMAC-SHA256 key.
type Secret struct {
	key []byte
}

// GenerateSecret returns a new random secret.
func GenerateSecret() (Secret, error) {
	b := make([]byte, secretBytes)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return Secret{}, err
	}
	return Secret{key: b}, nil
}

// ParseSecret decodes a "whsec_<base64>" secret. The prefix is optional, for
// compatibility with dashboards that display the bare base64 value.
func ParseSecret(s string) (Secret, error) {
	raw, err := decodeB64(strings.TrimPrefix(strings.TrimSpace(s), SecretPrefix))
	if err != nil || len(raw) < 16 || len(raw) > 128 {
		return Secret{}, fmt.Errorf("%w: secret must be whsec_ followed by 16-128 base64-encoded bytes", ErrInvalidKey)
	}
	return Secret{key: raw}, nil
}

// MustParseSecret is like ParseSecret but panics on error. Use it for
// constants in tests and examples.
func MustParseSecret(s string) Secret {
	sec, err := ParseSecret(s)
	if err != nil {
		panic(err)
	}
	return sec
}

// String returns the "whsec_" encoding of the secret.
func (s Secret) String() string { return SecretPrefix + base64.StdEncoding.EncodeToString(s.key) }

// IsZero reports whether s holds no key.
func (s Secret) IsZero() bool { return len(s.key) == 0 }

func (s Secret) sign(content []byte) []byte {
	m := hmac.New(sha256.New, s.key)
	m.Write(content)
	return m.Sum(nil)
}

// SigningKey is an ed25519 private key used for "v1a" signatures.
type SigningKey struct {
	priv ed25519.PrivateKey
}

// VerifyingKey is an ed25519 public key used to check "v1a" signatures.
type VerifyingKey struct {
	pub ed25519.PublicKey
}

// GenerateSigningKey returns a new ed25519 key pair.
func GenerateSigningKey() (SigningKey, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return SigningKey{}, err
	}
	return SigningKey{priv: priv}, nil
}

// ParseSigningKey decodes a "whsk_<base64>" key. Both the 32-byte seed and the
// 64-byte seed||public-key forms are accepted.
func ParseSigningKey(s string) (SigningKey, error) {
	raw, err := decodeB64(strings.TrimPrefix(strings.TrimSpace(s), SigningKeyPrefix))
	if err != nil {
		return SigningKey{}, fmt.Errorf("%w: %v", ErrInvalidKey, err)
	}
	switch len(raw) {
	case ed25519.SeedSize:
		return SigningKey{priv: ed25519.NewKeyFromSeed(raw)}, nil
	case ed25519.PrivateKeySize:
		k := ed25519.NewKeyFromSeed(raw[:ed25519.SeedSize])
		if !hmac.Equal(k, raw) {
			return SigningKey{}, fmt.Errorf("%w: public half does not match seed", ErrInvalidKey)
		}
		return SigningKey{priv: k}, nil
	default:
		return SigningKey{}, fmt.Errorf("%w: ed25519 key must be 32 or 64 bytes", ErrInvalidKey)
	}
}

// String returns the "whsk_" encoding of the 64-byte private key.
func (k SigningKey) String() string {
	return SigningKeyPrefix + base64.StdEncoding.EncodeToString(k.priv)
}

// IsZero reports whether k holds no key.
func (k SigningKey) IsZero() bool { return len(k.priv) == 0 }

// Public returns the verifying half of k.
func (k SigningKey) Public() VerifyingKey {
	return VerifyingKey{pub: k.priv.Public().(ed25519.PublicKey)}
}

// ParseVerifyingKey decodes a "whpk_<base64>" public key.
func ParseVerifyingKey(s string) (VerifyingKey, error) {
	raw, err := decodeB64(strings.TrimPrefix(strings.TrimSpace(s), PublicKeyPrefix))
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return VerifyingKey{}, fmt.Errorf("%w: public key must be whpk_ followed by 32 base64-encoded bytes", ErrInvalidKey)
	}
	return VerifyingKey{pub: raw}, nil
}

// String returns the "whpk_" encoding of the key.
func (k VerifyingKey) String() string {
	return PublicKeyPrefix + base64.StdEncoding.EncodeToString(k.pub)
}

// Signer produces webhook-signature header values. Every configured secret
// and key contributes one signature, so a Signer holding the old and the new
// secret during rotation emits two v1 entries.
type Signer struct {
	Secrets []Secret
	Keys    []SigningKey
}

// Sign returns the webhook-signature header value for the given message id,
// timestamp and body.
func (s Signer) Sign(id string, ts time.Time, body []byte) string {
	content := signedContent(id, ts.Unix(), body)
	parts := make([]string, 0, len(s.Secrets)+len(s.Keys))
	for _, sec := range s.Secrets {
		if sec.IsZero() {
			continue
		}
		parts = append(parts, VersionHMAC+","+base64.StdEncoding.EncodeToString(sec.sign(content)))
	}
	for _, k := range s.Keys {
		if k.IsZero() {
			continue
		}
		parts = append(parts, VersionEd25519+","+base64.StdEncoding.EncodeToString(ed25519.Sign(k.priv, content)))
	}
	return strings.Join(parts, " ")
}

// SetHeaders sets the three Standard Webhooks headers on h.
func (s Signer) SetHeaders(h http.Header, id string, ts time.Time, body []byte) {
	h.Set(HeaderID, id)
	h.Set(HeaderTimestamp, strconv.FormatInt(ts.Unix(), 10))
	h.Set(HeaderSignature, s.Sign(id, ts, body))
}

// Verifier checks deliveries against a set of trusted secrets and public
// keys. The zero Tolerance means DefaultTolerance; a nil Now means time.Now.
type Verifier struct {
	Secrets    []Secret
	PublicKeys []VerifyingKey
	Tolerance  time.Duration
	Now        func() time.Time
}

// NewVerifier builds a Verifier from encoded keys: "whsec_" secrets and
// "whpk_" public keys may be mixed. Pass the old and new secret during a
// rotation.
func NewVerifier(keys ...string) (*Verifier, error) {
	v := &Verifier{}
	for _, k := range keys {
		if strings.HasPrefix(k, PublicKeyPrefix) {
			pk, err := ParseVerifyingKey(k)
			if err != nil {
				return nil, err
			}
			v.PublicKeys = append(v.PublicKeys, pk)
			continue
		}
		sec, err := ParseSecret(k)
		if err != nil {
			return nil, err
		}
		v.Secrets = append(v.Secrets, sec)
	}
	if len(v.Secrets)+len(v.PublicKeys) == 0 {
		return nil, ErrNoKeys
	}
	return v, nil
}

// Verify checks the Standard Webhooks headers in h against body.
func (v *Verifier) Verify(h http.Header, body []byte) error {
	return v.VerifyValues(h.Get(HeaderID), h.Get(HeaderTimestamp), h.Get(HeaderSignature), body)
}

// VerifyValues checks raw header values against body. It returns nil if the
// timestamp is within tolerance and at least one signature matches at least
// one trusted key. Comparison of HMAC values is constant-time.
func (v *Verifier) VerifyValues(id, timestamp, sigHeader string, body []byte) error {
	if id == "" || timestamp == "" || sigHeader == "" {
		return ErrMissingHeaders
	}
	if len(v.Secrets)+len(v.PublicKeys) == 0 {
		return ErrNoKeys
	}
	ts, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil || ts < 0 {
		return ErrInvalidTimestamp
	}
	tol := v.Tolerance
	if tol <= 0 {
		tol = DefaultTolerance
	}
	now := time.Now
	if v.Now != nil {
		now = v.Now
	}
	nowUnix := now().Unix()
	switch {
	case ts < nowUnix-int64(tol/time.Second):
		return ErrTimestampTooOld
	case ts > nowUnix+int64(tol/time.Second):
		return ErrTimestampTooNew
	}

	content := signedContent(id, ts, body)
	var macs [][]byte // computed lazily, once per secret
	for _, entry := range strings.Fields(sigHeader) {
		version, sig, err := splitEntry(entry)
		if err != nil {
			continue // unknown or malformed entries are skipped, per spec
		}
		switch version {
		case VersionHMAC:
			if macs == nil {
				macs = make([][]byte, len(v.Secrets))
				for i, sec := range v.Secrets {
					macs[i] = sec.sign(content)
				}
			}
			for _, m := range macs {
				if hmac.Equal(m, sig) {
					return nil
				}
			}
		case VersionEd25519:
			for _, pk := range v.PublicKeys {
				if len(sig) == ed25519.SignatureSize && ed25519.Verify(pk.pub, content, sig) {
					return nil
				}
			}
		}
	}
	return ErrNoMatch
}

// Middleware returns an http.Handler that verifies every request before
// passing it to next, rejecting failures with 401. The body is read in full
// (up to maxBody bytes; larger bodies get 413) and replaced with an
// in-memory copy, so next can read it again.
func (v *Verifier) Middleware(maxBody int64, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, maxBody+1))
		if err != nil {
			http.Error(w, "read error", http.StatusBadRequest)
			return
		}
		if int64(len(body)) > maxBody {
			http.Error(w, ErrPayloadTooLarge.Error(), http.StatusRequestEntityTooLarge)
			return
		}
		if err := v.Verify(r.Header, body); err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		next.ServeHTTP(w, r)
	})
}

func signedContent(id string, ts int64, body []byte) []byte {
	tsStr := strconv.FormatInt(ts, 10)
	b := make([]byte, 0, len(id)+len(tsStr)+len(body)+2)
	b = append(b, id...)
	b = append(b, '.')
	b = append(b, tsStr...)
	b = append(b, '.')
	return append(b, body...)
}

func splitEntry(entry string) (version string, sig []byte, err error) {
	version, enc, ok := strings.Cut(entry, ",")
	if !ok || version == "" || enc == "" {
		return "", nil, errMalformedSigEntry
	}
	sig, err = base64.StdEncoding.DecodeString(enc)
	if err != nil {
		return "", nil, errMalformedSigEntry
	}
	return version, sig, nil
}

// decodeB64 accepts standard base64 with or without padding.
func decodeB64(s string) ([]byte, error) {
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.RawStdEncoding.DecodeString(s)
}
