package config

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestLoadOrCreateHexSecretPersistsWithPrivatePermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "jwt-secret")
	t.Setenv("TEST_SECRET_FILE", path)

	first, err := loadOrCreateHexSecret("TEST_SECRET_FILE", "unused", 32)
	if err != nil {
		t.Fatal(err)
	}
	second, err := loadOrCreateHexSecret("TEST_SECRET_FILE", "unused", 32)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatal("secret changed between reads")
	}
	if len(first) != 64 {
		t.Fatalf("unexpected secret length: %d", len(first))
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("unexpected permissions: %o", info.Mode().Perm())
	}
}

func TestLoadOrCreateHexSecretIsConcurrentSafe(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret")
	t.Setenv("TEST_CONCURRENT_SECRET_FILE", path)
	const workers = 12
	values := make(chan string, workers)
	errors := make(chan error, workers)
	var group sync.WaitGroup
	for i := 0; i < workers; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			value, err := loadOrCreateHexSecret("TEST_CONCURRENT_SECRET_FILE", "unused", 32)
			if err != nil {
				errors <- err
				return
			}
			values <- value
		}()
	}
	group.Wait()
	close(values)
	close(errors)
	for err := range errors {
		t.Fatal(err)
	}
	var expected string
	for value := range values {
		if expected == "" {
			expected = value
		}
		if value != expected {
			t.Fatal("concurrent callers received different secrets")
		}
	}
}

func TestLoadOrCreateHexSecretRepairsPermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret")
	secret := "0123456789abcdef0123456789abcdef"
	if err := os.WriteFile(path, []byte(secret), 0644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TEST_PERMISSION_SECRET_FILE", path)
	if _, err := loadOrCreateHexSecret("TEST_PERMISSION_SECRET_FILE", "unused", 16); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("permissions were not repaired: %o", info.Mode().Perm())
	}
}
