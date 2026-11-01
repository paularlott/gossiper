package auth

import (
	"errors"
	"testing"
	"time"
)

func FuzzAccessVerify(f *testing.F) {
	k := keyFor(f, "HS256")
	clock := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	v, err := newAccessVerifier(AccessConfig{
		Audience: atAud,
		Issuers:  []Issuer{{Issuer: atIss, Key: k.pem}},
	}, internalOpts{now: clock.Now})
	if err != nil {
		f.Fatal(err)
	}
	defer v.Close()

	seeds := []string{
		atMint(f, k, atClaims(clock, atIss, nil), nil),
		atMint(f, k, atClaims(clock, atIss, map[string]any{"aud": []string{"x", atAud}}), nil),
		atMint(f, k, atClaims(clock, atIss, map[string]any{"authorization_details": []any{
			atDetail([]any{"publish", "x"}, atTopic("*", ""), atTopic("https://a/:b", "urlpattern")),
			map[string]any{"type": "other"},
		}}), nil),
		atMint(f, k, atClaims(clock, atIss, map[string]any{"authorization_details": []any{map[string]any{"type": DetailType}}}), nil),
		atMint(f, k, atClaims(clock, atIss, nil), map[string]any{"typ": "application/AT+JWT", "kid": "x"}),
		"", "a.b.c", "..", rawToken(`{"alg":"none"}`, `{}`, ""),
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, token string) {
		c, err := v.Verify(ctx(), token)
		if err != nil {
			if c != nil {
				t.Fatal("claims returned with an error")
			}
			if errors.Is(err, ErrMalformed) == errors.Is(err, ErrInvalid) {
				t.Fatalf("error must wrap exactly one kind: %v", err)
			}
			return
		}
		if c.Issuer != atIss || c.Expiry.IsZero() || !c.Expiry.After(clock.Now()) {
			t.Fatalf("bad claims %+v", c)
		}
		found := false
		for _, a := range c.Audience {
			found = found || a == atAud
		}
		if !found {
			t.Fatalf("audience %v", c.Audience)
		}
		for _, d := range c.Details {
			if len(d.Actions) == 0 || len(d.Topics) == 0 {
				t.Fatalf("empty detail %+v", d)
			}
			for _, m := range d.Topics {
				if m.Match == "" || (m.MatchType != "exact" && m.MatchType != "urlpattern") {
					t.Fatalf("bad matcher %+v", m)
				}
			}
		}
		_ = IsAccessToken(token)
	})
}
