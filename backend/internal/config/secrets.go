package config

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

var errSecretNotReady = errors.New("secret not ready")

func loadOrCreateHexSecret(pathEnv, defaultPath string, randomBytes int) (string, error) {
	path := strings.TrimSpace(os.Getenv(pathEnv))
	if path == "" {
		path = defaultPath
	}
	expectedLength := randomBytes * 2

	readExisting := func() (string, error) {
		info, err := os.Lstat(path)
		if err != nil {
			return "", err
		}
		if !info.Mode().IsRegular() {
			return "", fmt.Errorf("secret file %s must be a regular file", path)
		}
		if info.Mode().Perm() != 0600 {
			if err := os.Chmod(path, 0600); err != nil {
				return "", fmt.Errorf("secure secret file permissions: %w", err)
			}
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return "", err
		}
		secret := strings.TrimSpace(string(content))
		if len(secret) != expectedLength {
			return "", errSecretNotReady
		}
		return secret, nil
	}

	waitForReady := func() (string, error) {
		var lastErr error
		for attempt := 0; attempt < 20; attempt++ {
			secret, err := readExisting()
			if err == nil {
				return secret, nil
			}
			if errors.Is(err, errSecretNotReady) {
				lastErr = err
				time.Sleep(10 * time.Millisecond)
				continue
			}
			return "", err
		}
		if lastErr != nil {
			return "", fmt.Errorf("secret file %s has invalid length", path)
		}
		return "", fmt.Errorf("secret file %s is not ready", path)
	}

	if secret, err := readExisting(); err == nil {
		return secret, nil
	} else if errors.Is(err, errSecretNotReady) {
		return waitForReady()
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}

	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return "", fmt.Errorf("create secret directory: %w", err)
	}
	random := make([]byte, randomBytes)
	if _, err := rand.Read(random); err != nil {
		return "", fmt.Errorf("generate secret: %w", err)
	}
	secret := hex.EncodeToString(random)

	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if errors.Is(err, os.ErrExist) {
		if secret, readErr := waitForReady(); readErr == nil {
			return secret, nil
		} else {
			return "", fmt.Errorf("read concurrently-created secret: %w", readErr)
		}
	}
	if err != nil {
		return "", fmt.Errorf("create secret file: %w", err)
	}
	complete := false
	defer func() {
		if !complete {
			_ = os.Remove(path)
		}
	}()
	if _, err := file.WriteString(secret + "\n"); err != nil {
		file.Close()
		return "", fmt.Errorf("write secret file: %w", err)
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return "", fmt.Errorf("sync secret file: %w", err)
	}
	if err := file.Close(); err != nil {
		return "", err
	}
	complete = true
	return secret, nil
}
