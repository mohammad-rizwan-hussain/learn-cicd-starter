package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name        string
		headerValue string
		expectedKey string
		expectedErr error
	}{
		{
			name:        "valid API key",
			headerValue: "ApiKey abc123",
			expectedKey: "abc123",
			expectedErr: nil,
		},
		{
			name:        "missing authorization header",
			headerValue: "",
			expectedKey: "",
			expectedErr: ErrNoAuthHeaderIncluded,
		},
		{
			name:        "wrong auth scheme",
			headerValue: "Bearer abc123",
			expectedKey: "",
			expectedErr: errors.New("malformed authorization header"),
		},
		{
			name:        "only ApiKey keyword",
			headerValue: "ApiKey",
			expectedKey: "",
			expectedErr: errors.New("malformed authorization header"),
		},
		{
			name:        "empty api key",
			headerValue: "ApiKey ",
			expectedKey: "",
			expectedErr: nil,
		},
		{
			name:        "lowercase apikey",
			headerValue: "apikey abc123",
			expectedKey: "",
			expectedErr: errors.New("malformed authorization header"),
		},
		{
			name:        "extra spaces",
			headerValue: "ApiKey   abc123",
			expectedKey: "",
			expectedErr: nil, // current implementation returns ""
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			headers := http.Header{}

			if tt.headerValue != "" {
				headers.Set("Authorization", tt.headerValue)
			}

			key, err := GetAPIKey(headers)

			if tt.expectedErr == nil {
				if err != nil {
					t.Fatalf("expected no error, got %v", err)
				}
				if key != tt.expectedKey {
					t.Fatalf("expected key %q, got %q", tt.expectedKey, key)
				}
				return
			}

			if err == nil {
				t.Fatalf("expected error %v, got nil", tt.expectedErr)
			}

			if err.Error() != tt.expectedErr.Error() {
				t.Fatalf("expected error %q, got %q",
					tt.expectedErr.Error(),
					err.Error())
			}
		})
	}
}
