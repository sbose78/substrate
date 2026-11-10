// Copyright 2026 The Agent Substrate Authors
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

package main

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"go.ate.dev/substrate/internal/apiconfig"
)

func TestBuildJWTProvidersClaimValidationRules(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
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
			"kty": "RSA",
			"kid": "k1",
			"n":   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
			"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
		}}})
	})
	srv := httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)
	issuer = srv.URL
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}

	mint := func(azp string) string {
		now := time.Now()
		enc := func(v any) string {
			b, err := json.Marshal(v)
			if err != nil {
				t.Fatal(err)
			}
			return base64.RawURLEncoding.EncodeToString(b)
		}
		signed := enc(map[string]string{"alg": "RS256", "typ": "JWT", "kid": "k1"}) + "." + enc(map[string]any{
			"iss": issuer,
			"sub": "alice",
			"aud": "api",
			"azp": azp,
			"iat": now.Add(-time.Minute).Unix(),
			"exp": now.Add(time.Hour).Unix(),
		})
		digest := sha256.Sum256([]byte(signed))
		sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
		if err != nil {
			t.Fatal(err)
		}
		return signed + "." + base64.RawURLEncoding.EncodeToString(sig)
	}

	provider := "jwtProviders:\n- name: test\n  issuer: " + issuer + "\n  audiences: [api]\n  certificateAuthorityFile: " + caFile + "\n"
	withRule := provider + "  claimValidationRules:\n  - {claim: azp, requiredValue: cli}\n"
	for _, tc := range []struct {
		name   string
		config string
		azp    string
		ok     bool
	}{
		{"no rule", provider, "web", true},
		{"rule, required value", withRule, "cli", true},
		{"rule, other value", withRule, "web", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := apiconfig.ParseAuthenticationConfig([]byte(tc.config))
			if err != nil {
				t.Fatalf("ParseAuthenticationConfig() error = %v", err)
			}
			serverCfg, err := buildJWTProviders(context.Background(), cfg)
			if err != nil {
				t.Fatalf("buildJWTProviders() error = %v", err)
			}
			sub, err := serverCfg.JWTProviders[0].Verify(context.Background(), mint(tc.azp))
			if tc.ok && (err != nil || sub != "alice") {
				t.Fatalf("Verify() = %q, %v, want alice", sub, err)
			}
			if !tc.ok && err == nil {
				t.Fatalf("Verify() = %q, want an error", sub)
			}
		})
	}
}
