package main

import "testing"

func TestValidateProductionBuildRequirement(t *testing.T) {
	tests := []struct {
		name      string
		envValue  string
		isDev     bool
		wantError bool
	}{
		{
			name:      "guard disabled allows dev build",
			envValue:  "",
			isDev:     true,
			wantError: false,
		},
		{
			name:      "guard enabled allows prod build",
			envValue:  "true",
			isDev:     false,
			wantError: false,
		},
		{
			name:      "guard enabled blocks dev build",
			envValue:  "true",
			isDev:     true,
			wantError: true,
		},
		{
			name:      "non true value does not enable guard",
			envValue:  "1",
			isDev:     true,
			wantError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateProductionBuildRequirement(func(key string) string {
				if key == "SECRETR_REQUIRE_PROD_BUILD" {
					return tt.envValue
				}
				return ""
			}, func() bool {
				return tt.isDev
			})

			if tt.wantError && err == nil {
				t.Fatalf("expected error, got nil")
			}

			if !tt.wantError && err != nil {
				t.Fatalf("expected nil error, got %v", err)
			}
		})
	}
}
