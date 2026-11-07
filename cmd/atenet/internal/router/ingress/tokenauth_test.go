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

package ingress

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"slices"
	"strings"
	"testing"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_type "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"

	"go.ate.dev/substrate/api/ateapi/v1"
	"go.ate.dev/substrate/cmd/atenet/internal/router/extproc"
	"go.ate.dev/substrate/internal/atenet"
)

func TestHandleRequestHeadersTokenAuth(t *testing.T) {
	const (
		allowedID = "spiffe://cluster.local/ns/ate-system/sa/atenet-client"
		goodToken = "good-token-do-not-log"
	)
	// httpsRequest builds a request on the HTTPS listener, where the
	// Authorization header is the caller's own.
	httpsRequest := func(peer, authorization string) *extproc.RequestMetadata {
		headers := []*corev3.HeaderValue{{Key: atenet.TargetActorHeader, Value: "team-a/actor-1"}}
		if authorization != "" {
			headers = append(headers, &corev3.HeaderValue{Key: "authorization", Value: authorization})
		}
		return extproc.NewRequestMetadata(headers, map[string]*structpb.Struct{
			"envoy.filters.http.ext_proc": {Fields: map[string]*structpb.Value{
				extproc.TargetActorFilterStateAttribute: structpb.NewStringValue("team-a/actor-1"),
				extproc.IngressPeerFilterStateAttribute: structpb.NewStringValue(peer),
			}},
		})
	}
	// tunneledRequest builds a request inside a CONNECT tunnel: outer is the
	// CONNECT's Authorization, inner the tunneled request's own.
	tunneledRequest := func(outer, inner string) *extproc.RequestMetadata {
		var headers []*corev3.HeaderValue
		if inner != "" {
			headers = append(headers, &corev3.HeaderValue{Key: "authorization", Value: inner})
		}
		return extproc.NewRequestMetadata(headers, map[string]*structpb.Struct{
			"envoy.filters.http.ext_proc": {Fields: map[string]*structpb.Value{
				extproc.TargetActorFilterStateAttribute:          structpb.NewStringValue("team-a/actor-1"),
				extproc.ConnectAuthorityFilterStateAttribute:     structpb.NewStringValue("actor-1:7681"),
				extproc.IngressPeerFilterStateAttribute:          structpb.NewStringValue("-"),
				extproc.IngressAuthorizationFilterStateAttribute: structpb.NewStringValue(outer),
			}},
		})
	}

	tests := []struct {
		name string
		md   *extproc.RequestMetadata
		// callerErr is ateapi's answer to the resume made as the caller.
		callerErr error
		// wantStatus is the denial; 0 means routed.
		wantStatus         envoy_type.StatusCode
		wantCallerResume   bool
		wantRemoveAuthz    bool
		wantVerifiedTokens []string
	}{
		{
			name:       "no certificate and no token",
			md:         httpsRequest("-", ""),
			wantStatus: envoy_type.StatusCode_Unauthorized,
		},
		{
			name:       "not a bearer token",
			md:         httpsRequest("-", "Basic dXNlcjpwYXNz"),
			wantStatus: envoy_type.StatusCode_Unauthorized,
		},
		{
			name:               "invalid token",
			md:                 httpsRequest("-", "Bearer forged"),
			wantStatus:         envoy_type.StatusCode_Unauthorized,
			wantVerifiedTokens: []string{"forged"},
		},
		{
			name:               "valid token without permission on the actor",
			md:                 httpsRequest("-", "Bearer "+goodToken),
			callerErr:          status.Error(codes.PermissionDenied, "permission denied"),
			wantStatus:         envoy_type.StatusCode_Forbidden,
			wantCallerResume:   true,
			wantVerifiedTokens: []string{goodToken},
		},
		{
			name:               "token ateapi does not accept",
			md:                 httpsRequest("-", "Bearer "+goodToken),
			callerErr:          status.Error(codes.Unauthenticated, "invalid bearer token"),
			wantStatus:         envoy_type.StatusCode_Unauthorized,
			wantCallerResume:   true,
			wantVerifiedTokens: []string{goodToken},
		},
		{
			name:               "ateapi unreachable",
			md:                 httpsRequest("-", "Bearer "+goodToken),
			callerErr:          status.Error(codes.Unavailable, "connection refused"),
			wantStatus:         envoy_type.StatusCode_ServiceUnavailable,
			wantCallerResume:   true,
			wantVerifiedTokens: []string{goodToken},
		},
		{
			name:               "valid token with permission",
			md:                 httpsRequest("-", "Bearer "+goodToken),
			wantCallerResume:   true,
			wantRemoveAuthz:    true,
			wantVerifiedTokens: []string{goodToken},
		},
		{
			name:               "permitted caller's resume finds no room",
			md:                 httpsRequest("-", "Bearer "+goodToken),
			callerErr:          status.Error(codes.ResourceExhausted, "no worker has room"),
			wantCallerResume:   true,
			wantRemoveAuthz:    true,
			wantVerifiedTokens: []string{goodToken},
		},
		{
			name: "allowed certificate needs no token",
			md:   httpsRequest(allowedID, "Basic dXNlcjpwYXNz"),
		},
		{
			name:       "certificate outside the allowlist needs a token",
			md:         httpsRequest("spiffe://cluster.local/ns/demo/sa/other", ""),
			wantStatus: envoy_type.StatusCode_Unauthorized,
		},
		{
			name:       "token only inside the tunnel",
			md:         tunneledRequest("-", "Bearer "+goodToken),
			wantStatus: envoy_type.StatusCode_Unauthorized,
		},
		{
			name:               "token on the CONNECT",
			md:                 tunneledRequest("Bearer "+goodToken, "Basic dXNlcjpwYXNz"),
			wantCallerResume:   true,
			wantVerifiedTokens: []string{goodToken},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			prev := slog.Default()
			slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
			t.Cleanup(func() { slog.SetDefault(prev) })

			var routerResumes, callerResumes int
			router := &mockClient{
				resumeFn: func(ctx context.Context, _ *ateapi.ResumeActorRequest, _ ...grpc.CallOption) (*ateapi.ResumeActorResponse, error) {
					routerResumes++
					if md, _ := metadata.FromOutgoingContext(ctx); len(md.Get("authorization")) != 0 {
						t.Errorf("router resume carries the caller's token")
					}
					return &ateapi.ResumeActorResponse{Actor: &ateapi.Actor{
						Status: &ateapi.ActorStatus{WorkerAssignment: &ateapi.WorkerAssignment{WorkerSpiffeId: testWorkerSPIFFEID, WorkerPodIps: []string{"10.0.0.52"}}},
					}}, nil
				},
			}
			caller := &mockClient{
				resumeFn: func(ctx context.Context, in *ateapi.ResumeActorRequest, _ ...grpc.CallOption) (*ateapi.ResumeActorResponse, error) {
					callerResumes++
					md, _ := metadata.FromOutgoingContext(ctx)
					if got, want := md.Get("authorization"), []string{"Bearer " + goodToken}; !slices.Equal(got, want) {
						t.Errorf("caller resume authorization = %q, want %q", got, want)
					}
					if got := in.GetActor().GetAtespace() + "/" + in.GetActor().GetName(); got != "team-a/actor-1" {
						t.Errorf("caller resume actor = %q, want team-a/actor-1", got)
					}
					return &ateapi.ResumeActorResponse{}, tc.callerErr
				},
			}
			var verified []string
			h := New(router, ParkedRequestConfig{}, nil, WithTokenAuth(&TokenAuth{
				AllowedSPIFFEIDs: []string{allowedID},
				Verify: func(_ context.Context, token string) (string, error) {
					verified = append(verified, token)
					if token != goodToken {
						return "", errors.New("bad signature")
					}
					return "alice", nil
				},
				Client: caller,
			}))

			res, err := h.HandleRequestHeaders(context.Background(), tc.md)

			if tc.wantStatus != 0 {
				var reqErr *extproc.ReqError
				if !errors.As(err, &reqErr) {
					t.Fatalf("error = %v, want *extproc.ReqError with status %d", err, tc.wantStatus)
				}
				if reqErr.StatusCode != int(tc.wantStatus) {
					t.Errorf("StatusCode = %d, want %d", reqErr.StatusCode, tc.wantStatus)
				}
				if routerResumes != 0 {
					t.Errorf("router resumed the actor %d times for a refused caller, want 0", routerResumes)
				}
			} else {
				if err != nil {
					t.Fatalf("HandleRequestHeaders() error = %v", err)
				}
				if routerResumes != 1 {
					t.Errorf("router resumed the actor %d times, want 1", routerResumes)
				}
				removed := res.Response.GetResponse().GetHeaderMutation().GetRemoveHeaders()
				if got := slices.Contains(removed, "authorization"); got != tc.wantRemoveAuthz {
					t.Errorf("removes authorization = %v, want %v", got, tc.wantRemoveAuthz)
				}
			}
			if got := callerResumes == 1; got != tc.wantCallerResume {
				t.Errorf("resumed as the caller %d times, want %v", callerResumes, tc.wantCallerResume)
			}
			if !slices.Equal(verified, tc.wantVerifiedTokens) {
				t.Errorf("verified tokens %q, want %q", verified, tc.wantVerifiedTokens)
			}
			if out := buf.String(); strings.Contains(out, goodToken) {
				t.Errorf("router log leaked the token: %s", out)
			}
		})
	}
}
