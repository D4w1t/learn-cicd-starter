package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name          string
		headers       http.Header
		expectedKey   string
		expectedErr   error
		expectErrText string
	}{
		{
			name:        "Valid ApiKey header",
			headers:     http.Header{"Authorization": []string{"ApiKey secret123"}},
			expectedKey: "secret123",
			expectedErr: nil,
		},
		{
			name:        "No Authorization header",
			headers:     http.Header{},
			expectedKey: "",
			expectedErr: ErrNoAuthHeaderIncluded,
		},
		{
			name:          "Malformed header - wrong prefix",
			headers:       http.Header{"Authorization": []string{"Bearer secret123"}},
			expectedKey:   "",
			expectErrText: "malformed authorization header",
		},
		{
			name:          "Malformed header - missing key",
			headers:       http.Header{"Authorization": []string{"ApiKey"}},
			expectedKey:   "",
			expectErrText: "malformed authorization header",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := GetAPIKey(tt.headers)
			if tt.expectedErr != nil {
				if !errors.Is(err, tt.expectedErr) {
					t.Errorf("expected error %v, got %v", tt.expectedErr, err)
				}
			} else if tt.expectErrText != "" {
				if err == nil || err.Error() != tt.expectErrText {
					t.Errorf("expected error text %q, got %v", tt.expectErrText, err)
				}
			} else if err != nil {
				t.Errorf("unexpected error: %v", err)
			}

			if key != tt.expectedKey {
				t.Errorf("expected key %q, got %q", tt.expectedKey, key)
			}
		})
	}
}
