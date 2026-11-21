package signature

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Published example vector used by Standard Webhooks reference libraries.
const (
	vecSecret  = "whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw"
	vecID      = "msg_p5jXN8AQM9LWM0D4loKWxJek"
	vecTS      = 1614265330
	vecPayload = `{"test": 2432232314}`
	vecSig     = "v1,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE="
)

func TestReferenceVector(t *testing.T) {
	s := Signer{Secrets: []Secret{MustParseSecret(vecSecret)}}
	got := s.Sign(vecID, time.Unix(vecTS, 0), []byte(vecPayload))
	if got != vecSig {
		t.Fatalf("Sign = %q, want %q", got, vecSig)
	}
	v, _ := NewVerifier(vecSecret)
	v.Now = func() time.Time { return time.Unix(vecTS+10, 0) }
	if err := v.VerifyValues(vecID, strconv.Itoa(vecTS), vecSig, []byte(vecPayload)); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyTable(t *testing.T) {
	sec := MustParseSecret(vecSecret)
	other, _ := GenerateSecret()
	key, _ := GenerateSigningKey()
	now := time.Unix(1_800_000_000, 0)
	body := []byte(`{"type":"pix.received"}`)
	good := Signer{Secrets: []Secret{sec}}.Sign("msg_1", now, body)
	asym := Signer{Keys: []SigningKey{key}}.Sign("msg_1", now, body)
	ts := strconv.FormatInt(now.Unix(), 10)

	tests := []struct {
		name    string
		id, ts  string
		sig     string
		body    []byte
		keys    []string
		nowOff  time.Duration
		wantErr error
	}{
		{"valid", "msg_1", ts, good, body, []string{vecSecret}, 0, nil},
		{"valid within tolerance (past)", "msg_1", ts, good, body, []string{vecSecret}, 4 * time.Minute, nil},
		{"valid within tolerance (future)", "msg_1", ts, good, body, []string{vecSecret}, -4 * time.Minute, nil},
		{"too old", "msg_1", ts, good, body, []string{vecSecret}, 6 * time.Minute, ErrTimestampTooOld},
		{"too new", "msg_1", ts, good, body, []string{vecSecret}, -6 * time.Minute, ErrTimestampTooNew},
		{"tampered body", "msg_1", ts, good, []byte(`{"type":"pix.refunded"}`), []string{vecSecret}, 0, ErrNoMatch},
		{"tampered id", "msg_2", ts, good, body, []string{vecSecret}, 0, ErrNoMatch},
		{"wrong secret", "msg_1", ts, good, body, []string{other.String()}, 0, ErrNoMatch},
		{"rotation: old and new trusted", "msg_1", ts, good, body, []string{other.String(), vecSecret}, 0, nil},
		{"multiple sigs, second matches", "msg_1", ts, "v1,AAAA " + good, body, []string{vecSecret}, 0, nil},
		{"unknown version skipped", "msg_1", ts, "v9,abc " + good, body, []string{vecSecret}, 0, nil},
		{"malformed entries only", "msg_1", ts, "garbage v1, v1,!!!", body, []string{vecSecret}, 0, ErrNoMatch},
		{"missing id", "", ts, good, body, []string{vecSecret}, 0, ErrMissingHeaders},
		{"missing sig", "msg_1", ts, "", body, []string{vecSecret}, 0, ErrMissingHeaders},
		{"bad timestamp", "msg_1", "12a", good, body, []string{vecSecret}, 0, ErrInvalidTimestamp},
		{"negative timestamp", "msg_1", "-5", good, body, []string{vecSecret}, 0, ErrInvalidTimestamp},
		{"ed25519 valid", "msg_1", ts, asym, body, []string{key.Public().String()}, 0, nil},
		{"ed25519 tampered", "msg_1", ts, asym, []byte("x"), []string{key.Public().String()}, 0, ErrNoMatch},
		{"ed25519 sig against hmac secret", "msg_1", ts, asym, body, []string{vecSecret}, 0, ErrNoMatch},
		{"v1a with wrong length", "msg_1", ts, "v1a,AAAA", body, []string{key.Public().String()}, 0, ErrNoMatch},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v, err := NewVerifier(tt.keys...)
			if err != nil {
				t.Fatal(err)
			}
			v.Now = func() time.Time { return now.Add(tt.nowOff) }
			err = v.VerifyValues(tt.id, tt.ts, tt.sig, tt.body)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("err = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestSignerEmitsOneEntryPerKey(t *testing.T) {
	a, _ := GenerateSecret()
	b, _ := GenerateSecret()
	k, _ := GenerateSigningKey()
	h := Signer{Secrets: []Secret{a, b, {}}, Keys: []SigningKey{k, {}}}.Sign("m", time.Unix(1, 0), nil)
	entries := strings.Fields(h)
	if len(entries) != 3 || !strings.HasPrefix(entries[0], "v1,") || !strings.HasPrefix(entries[2], "v1a,") {
		t.Fatalf("unexpected header %q", h)
	}
}

func TestParseKeys(t *testing.T) {
	sec, _ := GenerateSecret()
	if got := MustParseSecret(sec.String()); got.String() != sec.String() {
		t.Fatal("secret round trip")
	}
	bare := strings.TrimPrefix(sec.String(), SecretPrefix)
	if _, err := ParseSecret(bare); err != nil {
		t.Fatalf("bare base64 secret: %v", err)
	}
	if _, err := ParseSecret(strings.TrimRight(sec.String(), "=")); err != nil {
		t.Fatalf("unpadded secret: %v", err)
	}
	for _, bad := range []string{"", "whsec_", "whsec_!!!!", "whsec_AAAA"} {
		if _, err := ParseSecret(bad); !errors.Is(err, ErrInvalidKey) {
			t.Errorf("ParseSecret(%q) err = %v", bad, err)
		}
	}
	func() {
		defer func() {
			if recover() == nil {
				t.Error("MustParseSecret did not panic")
			}
		}()
		MustParseSecret("nope")
	}()

	k, _ := GenerateSigningKey()
	k2, err := ParseSigningKey(k.String())
	if err != nil || k2.String() != k.String() {
		t.Fatalf("signing key round trip: %v", err)
	}
	seed := k.priv.Seed()
	k3, err := ParseSigningKey(SigningKeyPrefix + b64(seed))
	if err != nil || k3.Public().String() != k.Public().String() {
		t.Fatalf("seed form: %v", err)
	}
	mismatched := append(append([]byte{}, seed...), make([]byte, 32)...)
	for _, bad := range []string{"whsk_!!", "whsk_AAAA", SigningKeyPrefix + b64(mismatched)} {
		if _, err := ParseSigningKey(bad); !errors.Is(err, ErrInvalidKey) {
			t.Errorf("ParseSigningKey(%q) err = %v", bad, err)
		}
	}
	pk, err := ParseVerifyingKey(k.Public().String())
	if err != nil || pk.String() != k.Public().String() {
		t.Fatalf("public key round trip: %v", err)
	}
	if _, err := ParseVerifyingKey("whpk_AAAA"); !errors.Is(err, ErrInvalidKey) {
		t.Error("short public key accepted")
	}
	if _, err := NewVerifier(); !errors.Is(err, ErrNoKeys) {
		t.Error("empty verifier accepted")
	}
	if _, err := NewVerifier("whpk_x"); err == nil {
		t.Error("bad public key accepted")
	}
	if _, err := NewVerifier("whsec_x"); err == nil {
		t.Error("bad secret accepted")
	}
	if err := (&Verifier{}).VerifyValues("a", "1", "v1,x", nil); !errors.Is(err, ErrNoKeys) {
		t.Errorf("keyless verify err = %v", err)
	}
}

func TestDefaultsUseWallClock(t *testing.T) {
	sec, _ := GenerateSecret()
	h := http.Header{}
	Signer{Secrets: []Secret{sec}}.SetHeaders(h, "msg_x", time.Now(), []byte("{}"))
	v := &Verifier{Secrets: []Secret{sec}}
	if err := v.Verify(h, []byte("{}")); err != nil {
		t.Fatal(err)
	}
}

func TestMiddleware(t *testing.T) {
	sec, _ := GenerateSecret()
	v := &Verifier{Secrets: []Secret{sec}}
	var seen string
	h := v.Middleware(64, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b := make([]byte, 100)
		n, _ := r.Body.Read(b)
		seen = string(b[:n])
		w.WriteHeader(http.StatusNoContent)
	}))
	send := func(body string, sign bool) int {
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
		if sign {
			Signer{Secrets: []Secret{sec}}.SetHeaders(req.Header, "msg_1", time.Now(), []byte(body))
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	if c := send(`{"ok":true}`, true); c != http.StatusNoContent || seen != `{"ok":true}` {
		t.Fatalf("signed: code %d body %q", c, seen)
	}
	if c := send(`{}`, false); c != http.StatusUnauthorized {
		t.Fatalf("unsigned: code %d", c)
	}
	if c := send(strings.Repeat("x", 65), true); c != http.StatusRequestEntityTooLarge {
		t.Fatalf("large: code %d", c)
	}
	req := httptest.NewRequest(http.MethodPost, "/", errReader{})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("read error: code %d", rec.Code)
	}
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("boom") }

func b64(b []byte) string { return Secret{key: b}.String()[len(SecretPrefix):] }

func BenchmarkVerify(b *testing.B) {
	sec := MustParseSecret(vecSecret)
	body := []byte(strings.Repeat(`{"amount":1000}`, 64))
	now := time.Unix(1_800_000_000, 0)
	sig := Signer{Secrets: []Secret{sec}}.Sign("msg_1", now, body)
	v := &Verifier{Secrets: []Secret{sec}, Now: func() time.Time { return now }}
	ts := strconv.FormatInt(now.Unix(), 10)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if err := v.VerifyValues("msg_1", ts, sig, body); err != nil {
			b.Fatal(err)
		}
	}
}

// FuzzVerifyValues checks that arbitrary header values never panic the
// verifier and never verify without the secret.
func FuzzVerifyValues(f *testing.F) {
	f.Add(vecID, strconv.Itoa(vecTS), vecSig, []byte(vecPayload))
	f.Add("msg", "0", "v1a,AAAA v1,", []byte{})
	f.Add("", "", "", []byte(nil))
	sec := MustParseSecret(vecSecret)
	k, _ := GenerateSigningKey()
	v := &Verifier{Secrets: []Secret{sec}, PublicKeys: []VerifyingKey{k.Public()}, Tolerance: 1 << 62, Now: func() time.Time { return time.Unix(vecTS, 0) }}
	f.Fuzz(func(t *testing.T, id, ts, sig string, body []byte) {
		err := v.VerifyValues(id, ts, sig, body)
		if err == nil {
			// Only a header produced with the real keys may verify.
			n, perr := strconv.ParseInt(ts, 10, 64)
			if perr != nil {
				t.Fatalf("verified with unparseable timestamp %q", ts)
			}
			want := Signer{Secrets: []Secret{sec}}.Sign(id, time.Unix(n, 0), body)
			if !strings.Contains(sig, strings.TrimPrefix(want, "v1,")) && !strings.Contains(sig, "v1a,") {
				t.Fatalf("forged signature accepted: %q", sig)
			}
		}
	})
}
