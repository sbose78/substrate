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

package ingress

import (
	"context"
	"log/slog"
	"slices"
	"strings"

	envoy_type "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"go.ate.dev/substrate/api/ateapi/v1"
	"go.ate.dev/substrate/cmd/atenet/internal/router/extproc"
	"go.ate.dev/substrate/internal/resources"
)

// authorizationHeader carries the caller's bearer token.
const authorizationHeader = "authorization"

// TokenAuth admits ingress callers without an allowed client certificate on a
// bearer token. The caller may reach an actor only if ateapi lets it resume
// that actor.
type TokenAuth struct {
	// AllowedSPIFFEIDs are the client certificate identities that need no
	// token. The listeners verify the certificate; see
	// extproc.IngressPeerFilterStateKey.
	AllowedSPIFFEIDs []string
	// Verify checks a bearer token and returns its subject.
	Verify func(ctx context.Context, token string) (string, error)
	// Client reaches ateapi without a client certificate. ateapi prefers a
	// certificate identity to a bearer token, so the router's own connection
	// would authorize the router instead of the caller.
	Client ateapi.ControlClient
}

// Option configures a Handler.
type Option func(*Handler)

// WithTokenAuth makes the handler require a bearer token from callers without
// an allowed client certificate.
func WithTokenAuth(a *TokenAuth) Option {
	return func(h *Handler) { h.tokenAuth = a }
}

// authenticate returns the verified bearer token of a caller without an
// allowed client certificate, or "" for a caller with one. fromHeader reports
// that the token came from this request's own Authorization header, which must
// not reach the actor.
func (a *TokenAuth) authenticate(ctx context.Context, md *extproc.RequestMetadata) (token string, fromHeader bool, err error) {
	if slices.Contains(a.AllowedSPIFFEIDs, md.Attribute(extproc.IngressPeerFilterStateAttribute)) {
		return "", false, nil
	}
	// A request that arrived through a CONNECT tunnel carries headers from
	// inside the tunnel. Only the outer CONNECT's token counts.
	authorization, fromHeader := md.Header(authorizationHeader), true
	if md.Attribute(extproc.ConnectAuthorityFilterStateAttribute) != "" {
		authorization, fromHeader = md.Attribute(extproc.IngressAuthorizationFilterStateAttribute), false
	}
	token, ok := strings.CutPrefix(authorization, "Bearer ")
	if token = strings.TrimSpace(token); !ok || token == "" {
		return "", false, extproc.NewReqError(envoy_type.StatusCode_Unauthorized, "bearer token required")
	}
	subject, err := a.Verify(ctx, token)
	if err != nil {
		slog.DebugContext(ctx, "Bearer token verification failed", slog.Any("err", err))
		return "", false, extproc.NewReqError(envoy_type.StatusCode_Unauthorized, "invalid bearer token")
	}
	slog.InfoContext(ctx, "Ingress caller authenticated", slog.String("principal", "user:"+subject))
	return token, fromHeader, nil
}

// authorize resumes actorRef as the caller, so ateapi checks the caller's
// permission before the router resumes the actor as itself.
func (a *TokenAuth) authorize(ctx context.Context, actorRef resources.ActorRef, token string) error {
	ctx = metadata.AppendToOutgoingContext(ctx, authorizationHeader, "Bearer "+token)
	_, err := a.Client.ResumeActor(ctx, &ateapi.ResumeActorRequest{Actor: actorRef.ToObjectRef()})
	switch status.Code(err) {
	case codes.OK, codes.ResourceExhausted, codes.Aborted, codes.FailedPrecondition:
		// ateapi authorizes before the handler runs, so these errors come
		// from a resume it allowed. The router's own resume retries them.
		return nil
	}
	return mapResumeError(actorRef, err)
}
