package signature_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"time"

	"github.com/victorcondackdev/webhook-relay-go/signature"
)

// Signing is deterministic for a given secret, message id, timestamp and body.
func ExampleSigner_Sign() {
	secret := signature.MustParseSecret("whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw")
	s := signature.Signer{Secrets: []signature.Secret{secret}}
	fmt.Println(s.Sign("msg_p5jXN8AQM9LWM0D4loKWxJek", time.Unix(1614265330, 0), []byte(`{"test": 2432232314}`)))
	// Output:
	// v1,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE=
}

// A receiver verifies the headers against the raw body before parsing it.
func ExampleVerifier_Verify() {
	const secret = "whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw"
	now := time.Unix(1_800_000_000, 0)
	body := []byte(`{"type":"pix.received","data":{"amount":1500}}`)

	h := http.Header{}
	signature.Signer{Secrets: []signature.Secret{signature.MustParseSecret(secret)}}.
		SetHeaders(h, "msg_01", now, body)

	v, _ := signature.NewVerifier(secret)
	v.Now = func() time.Time { return now.Add(30 * time.Second) }
	fmt.Println(v.Verify(h, body))
	fmt.Println(v.Verify(h, []byte(`{"type":"pix.received","data":{"amount":9999}}`)))

	v.Now = func() time.Time { return now.Add(10 * time.Minute) }
	fmt.Println(v.Verify(h, body))
	// Output:
	// <nil>
	// signature: no matching signature
	// signature: timestamp too old
}

// During a rotation the sender signs with both secrets, so receivers that
// still only know the old one keep working until they are updated.
func ExampleSigner_rotation() {
	oldSecret := signature.MustParseSecret("whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw")
	newSecret := signature.MustParseSecret("whsec_C2FVsBQIhrscChlQIMV+b5sSYspob7oD")
	now := time.Unix(1_800_000_000, 0)
	body := []byte(`{}`)

	h := http.Header{}
	signature.Signer{Secrets: []signature.Secret{newSecret, oldSecret}}.SetHeaders(h, "msg_01", now, body)
	fmt.Println(len(strings.Fields(h.Get(signature.HeaderSignature))), "signatures")

	for _, trusted := range []signature.Secret{oldSecret, newSecret} {
		v := &signature.Verifier{Secrets: []signature.Secret{trusted}, Now: func() time.Time { return now }}
		fmt.Println(v.Verify(h, body))
	}
	// Output:
	// 2 signatures
	// <nil>
	// <nil>
}

// Asymmetric v1a signatures let receivers verify with a public key only.
func ExampleSigningKey() {
	key, _ := signature.GenerateSigningKey()
	now := time.Now()
	body := []byte(`{"type":"charge.paid"}`)

	h := http.Header{}
	signature.Signer{Keys: []signature.SigningKey{key}}.SetHeaders(h, "msg_01", now, body)
	fmt.Println(strings.HasPrefix(h.Get(signature.HeaderSignature), "v1a,"))

	v, _ := signature.NewVerifier(key.Public().String())
	fmt.Println(v.Verify(h, body))
	// Output:
	// true
	// <nil>
}

// Middleware wraps a handler with verification.
func ExampleVerifier_Middleware() {
	sec, _ := signature.GenerateSecret()
	v := &signature.Verifier{Secrets: []signature.Secret{sec}}
	h := v.Middleware(1<<20, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	body := `{"type":"pix.received"}`
	req := httptest.NewRequest(http.MethodPost, "/webhooks", strings.NewReader(body))
	signature.Signer{Secrets: []signature.Secret{sec}}.SetHeaders(req.Header, "msg_01", time.Now(), []byte(body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	fmt.Println(rec.Code)
	// Output:
	// 204
}
