package auth

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestClaimsExpression(t *testing.T) {
	expr, err := parseClaimsExpression("Equals(`grp`, `admin`) && Contains(`scope`, `write`)")
	require.NoError(t, err)

	claims := tokenClaims{
		idToken: map[string]any{
			"grp":   "admin",
			"scope": "read write",
		},
	}

	require.True(t, expr.Eval(claims))
}

func TestClaimsExpressionAccessTokenPrefix(t *testing.T) {
	expr, err := parseClaimsExpression("Prefix(`access_token.referrer`, `http://example.com`)")
	require.NoError(t, err)

	claims := tokenClaims{
		accessToken: map[string]any{
			"referrer": "http://example.com/path",
		},
	}

	require.True(t, expr.Eval(claims))
	require.True(t, expr.NeedsAccessToken())
}
