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
	"errors"
	"fmt"
	"log/slog"
	"time"

	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"google.golang.org/grpc"

	"go.ate.dev/substrate/api/ateapi/v1"
	"go.ate.dev/substrate/cmd/atenet/internal/router/ingress"
	"go.ate.dev/substrate/internal/apiconfig"
	"go.ate.dev/substrate/internal/ateapiauth"
	"go.ate.dev/substrate/internal/oidcjwt"
)

// newIngressTokenAuth loads the JWT providers from
// --ingress-authentication-config, as ate-api-server does from
// --authentication-config, and dials ateapi without a client certificate for
// the calls the router makes as the caller.
func (s *RouterServer) newIngressTokenAuth(ctx context.Context) (*ingress.TokenAuth, error) {
	authCfg, err := apiconfig.LoadAuthenticationConfig(s.cfg.IngressAuth.AuthenticationConfigFile)
	if err != nil {
		return nil, fmt.Errorf("--ingress-authentication-config: %w", err)
	}
	verifiers, err := ingressVerifiers(ctx, authCfg)
	if err != nil {
		return nil, err
	}

	dialOpts, err := ateapiauth.DialOptions(ateapiauth.ClientConfig{
		K8sClient:         s.clientset,
		CAFile:            s.cfg.Auth.AteapiCAFile,
		ServerName:        s.cfg.Auth.AteapiServerName,
		WithoutClientCert: true,
	})
	if err != nil {
		return nil, fmt.Errorf("building ateapi dial options for token callers: %w", err)
	}
	dialOpts = append(dialOpts, grpc.WithStatsHandler(otelgrpc.NewClientHandler()))
	conn, err := grpc.NewClient(s.cfg.AteapiAddr, dialOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed to establish grpc channel to ateapi for token callers: %w", err)
	}

	return &ingress.TokenAuth{
		AllowedSPIFFEIDs: s.cfg.IngressAuth.AllowedSPIFFEIDs,
		Verify:           verifyToken(verifiers),
		Client:           ateapi.NewControlClient(conn),
	}, nil
}

// ingressVerifiers builds a verifier for each JWT provider in cfg, as
// ate-api-server's buildJWTProviders does.
func ingressVerifiers(ctx context.Context, cfg *apiconfig.AuthenticationConfig) ([]*oidcjwt.Verifier, error) {
	var verifiers []*oidcjwt.Verifier
	for _, p := range cfg.JWTProviders {
		httpClient, err := oidcjwt.NewHTTPClient(p.Issuer, p.CertificateAuthorityFile, p.DiscoveryTokenFile)
		if err != nil {
			return nil, fmt.Errorf("initialize JWT provider %q: %w", p.Name, err)
		}
		verifiers = append(verifiers, oidcjwt.NewVerifier(p.Issuer, p.Audiences, oidcjwt.HTTPKeySource(p.Issuer, httpClient),
			oidcjwt.WithRequiredClaims(p.RequiredClaims())))
		slog.InfoContext(ctx, "Configured ingress JWT provider", slog.String("name", p.Name), slog.String("issuer", p.Issuer))
	}
	return verifiers, nil
}

// verifyToken returns the subject of a token one of verifiers accepts. Each
// verifier checks the issuer before fetching keys, so the others cost little.
func verifyToken(verifiers []*oidcjwt.Verifier) func(context.Context, string) (string, error) {
	return func(ctx context.Context, token string) (string, error) {
		var errs []error
		for _, v := range verifiers {
			claims, err := v.Verify(ctx, token, time.Now())
			if err == nil {
				return claims.Subject, nil
			}
			errs = append(errs, err)
		}
		return "", errors.Join(errs...)
	}
}
