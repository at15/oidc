package op_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
	"github.com/zitadel/oidc/v3/pkg/op/mock"
)

type audienceRequest struct{}

func (audienceRequest) GetSubject() string    { return "sub" }
func (audienceRequest) GetAudience() []string { return []string{"client1"} }
func (audienceRequest) GetScopes() []string   { return []string{oidc.ScopeOpenID} }

type accessTokenAudienceRequest struct{ audienceRequest }

func (accessTokenAudienceRequest) GetAccessTokenAudience() []string {
	return []string{"client1", "api"}
}

type audienceClient struct{}

func (audienceClient) GetID() string                { return "client1" }
func (audienceClient) ClockSkew() time.Duration     { return 0 }
func (audienceClient) GrantTypes() []oidc.GrantType { return nil }
func (audienceClient) RestrictAdditionalAccessTokenScopes() func([]string) []string {
	return func(s []string) []string { return s }
}

type audienceKey struct{ key *ecdsa.PrivateKey }

func (audienceKey) SignatureAlgorithm() jose.SignatureAlgorithm { return jose.ES256 }
func (k audienceKey) Key() any                                  { return k.key }
func (audienceKey) ID() string                                  { return "k1" }

func TestAccessTokenAudience(t *testing.T) {
	assert.Equal(t, []string{"client1"}, op.AccessTokenAudience(audienceRequest{}))
	assert.Equal(t, []string{"client1", "api"}, op.AccessTokenAudience(accessTokenAudienceRequest{}))
}

func TestCreateJWTAccessTokenAudience(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tests := []struct {
		name    string
		request op.TokenRequest
		want    []string
	}{
		{"GetAudience without the interface", audienceRequest{}, []string{"client1"}},
		{"GetAccessTokenAudience with it", accessTokenAudienceRequest{}, []string{"client1", "api"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			storage := mock.NewMockStorage(gomock.NewController(t))
			storage.EXPECT().GetPrivateClaimsFromScopes(gomock.Any(), "sub", "client1", gomock.Any()).Return(nil, nil)
			storage.EXPECT().SigningKey(gomock.Any()).Return(audienceKey{key}, nil)

			token, err := op.CreateJWT(context.Background(), "https://issuer.example.com", tt.request,
				time.Now().Add(time.Minute), "id1", audienceClient{}, storage)
			require.NoError(t, err)
			var claims oidc.AccessTokenClaims
			_, err = oidc.ParseToken(token, &claims)
			require.NoError(t, err)
			assert.Equal(t, oidc.Audience(tt.want), claims.Audience)
		})
	}
}
