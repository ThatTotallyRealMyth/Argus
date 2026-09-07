package mcpserver

import (
	"path/filepath"
	"testing"
)

func TestValidateDictionaryContent(t *testing.T) {
	count, err := validateDictionaryContent("domain", "# comment\nwww\napi\n")
	if err != nil || count != 2 {
		t.Fatalf("unexpected domain dictionary validation: count=%d err=%v", count, err)
	}
	count, err = validateDictionaryContent("file_leak", ".env\n/admin\n")
	if err != nil || count != 2 {
		t.Fatalf("unexpected file leak dictionary validation: count=%d err=%v", count, err)
	}
	if _, err := validateDictionaryContent("file_leak", "https://example.test/admin\n"); err == nil {
		t.Fatal("file leak dictionary accepted a remote URL")
	}
}

func TestDictionaryPathWithinRoot(t *testing.T) {
	inside := filepath.Join(dictionaryRootDirectory, "domain", "mcp-test.dict")
	if !dictionaryPathWithinRoot(inside) {
		t.Fatalf("dictionary root rejected safe path %q", inside)
	}
	if dictionaryPathWithinRoot(filepath.Join(dictionaryRootDirectory, "..", "outside.dict")) {
		t.Fatal("dictionary root accepted path traversal")
	}
}

func TestProxySpecValidationAndPasswordClearing(t *testing.T) {
	name, scheme, host, username, password := "local", "SOCKS5", "127.0.0.1", "user", "secret"
	port := 1080
	value, err := proxyFromSpec(ProxySpec{Name: &name, Scheme: &scheme, Host: &host, Port: &port, Username: &username, Password: &password})
	if err != nil {
		t.Fatal(err)
	}
	if value.Scheme != "socks5" || value.Password != password {
		t.Fatalf("unexpected normalized proxy: %#v", value)
	}
	empty := ""
	if !applyProxySpec(value, ProxySpec{Username: &empty}) || value.Password != "" {
		t.Fatal("clearing proxy username did not clear password or address state")
	}
	invalidHost := "https://example.test"
	if _, err := proxyFromSpec(ProxySpec{Name: &name, Scheme: &scheme, Host: &invalidHost, Port: &port}); err == nil {
		t.Fatal("proxy accepted a URL as host")
	}
}

func TestProxyInputIDsDeduplicatesAndLimits(t *testing.T) {
	ids, err := proxyInputIDs("a", []string{"a", "b"}, 3)
	if err != nil || len(ids) != 2 {
		t.Fatalf("unexpected normalized proxy ids: %#v err=%v", ids, err)
	}
	if _, err := proxyInputIDs("", []string{"a", "b"}, 1); err == nil {
		t.Fatal("proxy id limit was not enforced")
	}
}
