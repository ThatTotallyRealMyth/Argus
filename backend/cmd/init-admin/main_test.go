package main

import "testing"

func TestValidatePasswordRejectsPlaceholders(t *testing.T) {
	for _, value := range []string{"short", "replace-with-a-long-password", "change-me-to-a-long-password"} {
		if err := validatePassword(value); err == nil {
			t.Errorf("unsafe administrator password accepted: %q", value)
		}
	}
	if err := validatePassword("correct-horse-battery-staple"); err != nil {
		t.Fatalf("strong administrator password rejected: %v", err)
	}
}

func TestAdminPasswordEnvironmentSupportsNonInteractiveReset(t *testing.T) {
	t.Setenv("ADMIN_PASSWORD", "correct-horse-battery-staple")
	if err := validatePassword("correct-horse-battery-staple"); err != nil {
		t.Fatalf("deployment administrator password rejected: %v", err)
	}
}
