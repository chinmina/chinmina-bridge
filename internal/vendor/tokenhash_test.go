package vendor_test

import (
	"testing"

	"github.com/chinmina/chinmina-bridge/internal/vendor"
	"github.com/stretchr/testify/assert"
)

func TestHashToken(t *testing.T) {
	tests := []struct {
		name  string
		token string
		want  string
	}{
		{
			name:  "empty string",
			token: "",
			want:  "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=",
		},
		{
			name:  "ghs_ prefixed token",
			token: "ghs_abc123",
			want:  "gbNg+iyvVNtuHmQVEASBeW9hb3NUAhqqFLiopXZ5R38=",
		},
		{
			name:  "typical vended token value",
			token: "vended-token-value",
			want:  "5y3Ls0riv+szOLDcjNJl69dFVXzURdy38ersG+Bv3Zs=",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, vendor.HashToken(tt.token))
		})
	}
}
