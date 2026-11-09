// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package router

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"go.ate.dev/substrate/internal/apiconfig"
	"go.ate.dev/substrate/internal/oidcjwt"
)

type staticKeys []*oidcjwt.KeyAndID

func (k staticKeys) Keys(context.Context) ([]*oidcjwt.KeyAndID, error) { return k, nil }

// signES256 returns a compact JWT over claims, signed with key under kid.
func signES256(t *testing.T, key *ecdsa.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	enc := func(v any) string {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return base64.RawURLEncoding.EncodeToString(b)
	}
	signed := enc(map[string]string{"alg": "ES256", "typ": "JWT", "kid": kid}) + "." + enc(claims)
	digest := sha256.Sum256([]byte(signed))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return signed + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// TestVerifyToken checks the ingress token check against two providers, as
// --ingress-authentication-config configures them.
func TestVerifyToken(t *testing.T) {
	const (
		issuerA = "https://login.example.com"
		issuerB = "https://idp.example.org"
	)
	keyA, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyB, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	verify := verifyToken([]*oidcjwt.Verifier{
		oidcjwt.NewVerifier(issuerA, []string{"ate-api"}, staticKeys{{KeyID: "a", PublicKey: &keyA.PublicKey}}),
		oidcjwt.NewVerifier(issuerB, []string{"ate-api"}, staticKeys{{KeyID: "b", PublicKey: &keyB.PublicKey}}),
	})
	now := time.Now()
	claims := func(iss, aud string, exp time.Time) map[string]any {
		return map[string]any{"iss": iss, "aud": aud, "sub": "alice", "iat": now.Add(-time.Minute).Unix(), "exp": exp.Unix()}
	}

	for _, tc := range []struct {
		name    string
		token   string
		wantErr bool
	}{
		{name: "first provider", token: signES256(t, keyA, "a", claims(issuerA, "ate-api", now.Add(time.Hour)))},
		{name: "second provider", token: signES256(t, keyB, "b", claims(issuerB, "ate-api", now.Add(time.Hour)))},
		{name: "expired", token: signES256(t, keyA, "a", claims(issuerA, "ate-api", now.Add(-time.Hour))), wantErr: true},
		{name: "wrong audience", token: signES256(t, keyA, "a", claims(issuerA, "other", now.Add(time.Hour))), wantErr: true},
		{name: "untrusted issuer", token: signES256(t, keyA, "a", claims("https://evil.example.net", "ate-api", now.Add(time.Hour))), wantErr: true},
		{name: "one issuer's claim signed by another's key", token: signES256(t, keyB, "a", claims(issuerA, "ate-api", now.Add(time.Hour))), wantErr: true},
		{name: "malformed", token: "not-a-jwt", wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			subject, err := verify(context.Background(), tc.token)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("verify accepted the token as %q, want an error", subject)
				}
				return
			}
			if err != nil {
				t.Fatalf("verify: %v", err)
			}
			if subject != "alice" {
				t.Errorf("subject = %q, want alice", subject)
			}
		})
	}
}

// TestIngressVerifiersClaimValidationRules checks that the ingress applies a
// provider's claim validation rules from --ingress-authentication-config.
func TestIngressVerifiersClaimValidationRules(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var issuer string
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"issuer": issuer, "jwks_uri": issuer + "/jwks"})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
			"kty": "EC",
			"crv": "P-256",
			"kid": "a",
			"x":   base64.RawURLEncoding.EncodeToString(key.X.FillBytes(make([]byte, 32))),
			"y":   base64.RawURLEncoding.EncodeToString(key.Y.FillBytes(make([]byte, 32))),
		}}})
	})
	srv := httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)
	issuer = srv.URL
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := apiconfig.ParseAuthenticationConfig([]byte("jwtProviders:\n- name: test\n  issuer: " + issuer +
		"\n  audiences: [ate-api]\n  certificateAuthorityFile: " + caFile +
		"\n  claimValidationRules:\n  - {claim: azp, requiredValue: cli}\n  - {claim: tenant, requiredValue: acme}\n"))
	if err != nil {
		t.Fatal(err)
	}
	verifiers, err := ingressVerifiers(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	verify := verifyToken(verifiers)
	now := time.Now()

	for _, tc := range []struct {
		name        string
		azp, tenant string
		wantErr     bool
	}{
		{name: "both claims match", azp: "cli", tenant: "acme"},
		{name: "azp differs", azp: "web", tenant: "acme", wantErr: true},
		{name: "tenant differs", azp: "cli", tenant: "other", wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			token := signES256(t, key, "a", map[string]any{"iss": issuer, "aud": "ate-api", "sub": "alice",
				"azp": tc.azp, "tenant": tc.tenant, "iat": now.Add(-time.Minute).Unix(), "exp": now.Add(time.Hour).Unix()})
			subject, err := verify(context.Background(), token)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("verify accepted the token as %q, want an error", subject)
				}
				return
			}
			if err != nil || subject != "alice" {
				t.Fatalf("verify = %q, %v, want alice", subject, err)
			}
		})
	}
}
