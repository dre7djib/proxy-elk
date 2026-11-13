package idtoken

import (
	"crypto/rand"
	"crypto/rsa"
	"strings"
	"testing"
	"time"
)

func genKey(t *testing.T, kid string) Key {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return Key{KID: kid, Private: k}
}

func setup(t *testing.T, keys ...Key) (*Issuer, *Verifier) {
	t.Helper()
	iss, err := NewIssuer("proxy", "engine", 10*time.Minute, keys)
	if err != nil {
		t.Fatal(err)
	}
	return iss, verifierFor(t, iss, "proxy", "engine")
}

func verifierFor(t *testing.T, iss *Issuer, issuer, aud string) *Verifier {
	t.Helper()
	jwks, _ := iss.JWKS()
	v, err := NewVerifier(issuer, aud, 0, jwks)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestSignVerify(t *testing.T) {
	iss, v := setup(t, genKey(t, "a"))
	tok, _ := iss.Sign("alice", []string{"g1"})
	c, err := v.Verify(tok)
	if err != nil || c.Subject != "alice" || len(c.Groups) != 1 || c.Groups[0] != "g1" {
		t.Fatalf("c=%+v err=%v", c, err)
	}
}

func TestExpiry(t *testing.T) {
	iss, v := setup(t, genKey(t, "a"))
	tok, _ := iss.Sign("alice", nil)
	now := time.Now()
	v.now = func() time.Time { return now.Add(10*time.Minute + 30*time.Second) } // within skew
	if _, err := v.Verify(tok); err != nil {
		t.Fatalf("within skew: %v", err)
	}
	v.now = func() time.Time { return now.Add(10*time.Minute + 2*time.Minute) }
	if _, err := v.Verify(tok); err == nil {
		t.Fatal("expired beyond skew accepted")
	}
}

func TestRefused(t *testing.T) {
	iss, v := setup(t, genKey(t, "a"))
	tok, _ := iss.Sign("alice", nil)

	other := genKey(t, "a") // same kid, different key
	forger, _ := NewIssuer("proxy", "engine", 10*time.Minute, []Key{other})
	forged, _ := forger.Sign("alice", nil)
	if _, err := v.Verify(forged); err == nil {
		t.Fatal("bad signature accepted")
	}
	if _, err := verifierFor(t, iss, "proxy", "other").Verify(tok); err == nil {
		t.Fatal("wrong aud accepted")
	}
	if _, err := verifierFor(t, iss, "other", "engine").Verify(tok); err == nil {
		t.Fatal("wrong iss accepted")
	}
	p := strings.Split(tok, ".")
	none := b64.EncodeToString([]byte(`{"alg":"none","kid":"a"}`)) + "." + p[1] + "."
	hs := b64.EncodeToString([]byte(`{"alg":"HS256","kid":"a"}`)) + "." + p[1] + "." + p[2]
	for _, bad := range []string{none, hs, "x.y", ""} {
		if _, err := v.Verify(bad); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
}

func TestRotation(t *testing.T) {
	oldK, newK := genKey(t, "old"), genKey(t, "new")
	oldIss, _ := setup(t, oldK)
	oldTok, _ := oldIss.Sign("alice", nil)

	both, vBoth := setup(t, newK, oldK) // new signs, both verify
	if _, err := vBoth.Verify(oldTok); err != nil {
		t.Fatalf("previous key refused: %v", err)
	}
	newTok, _ := both.Sign("alice", nil)
	if _, err := vBoth.Verify(newTok); err != nil {
		t.Fatal(err)
	}
	_, vNew := setup(t, newK) // old key retired
	if _, err := vNew.Verify(oldTok); err == nil {
		t.Fatal("retired key accepted")
	}
}

func TestJWKSPublicOnly(t *testing.T) {
	iss, _ := setup(t, genKey(t, "a"))
	b, _ := iss.JWKS()
	for _, f := range []string{`"d"`, `"p"`, `"q"`, `"dp"`, `"dq"`, `"qi"`} {
		if strings.Contains(string(b), f) {
			t.Fatalf("JWKS leaks %s", f)
		}
	}
}

func TestIssuerValidation(t *testing.T) {
	k := genKey(t, "a")
	for _, ttl := range []time.Duration{time.Minute, time.Hour} {
		if _, err := NewIssuer("p", "e", ttl, []Key{k}); err == nil {
			t.Fatalf("ttl %s accepted", ttl)
		}
	}
	if _, err := NewIssuer("p", "e", 10*time.Minute, nil); err == nil {
		t.Fatal("zero keys accepted")
	}
	if _, err := NewIssuer("p", "e", 10*time.Minute, []Key{k, {KID: "b", Private: k.Private}, {KID: "c", Private: k.Private}}); err == nil {
		t.Fatal("3 keys accepted")
	}
}
