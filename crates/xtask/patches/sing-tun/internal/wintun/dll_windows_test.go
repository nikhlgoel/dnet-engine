// Tests for the DNet Engine patch to the adapter DLL loader. Run by
// `cargo xtask fetch-vendor` against the official vendored DLL, whose path it passes in
// DNET_WINTUN_DLL. Deliberately fails, rather than skips, without it: a skipped test
// would let the patch ship unexercised.

package wintun

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func officialDLL(t *testing.T) string {
	t.Helper()
	path := os.Getenv("DNET_WINTUN_DLL")
	if path == "" {
		t.Fatal("DNET_WINTUN_DLL must name the official vendored DLL")
	}
	return path
}

func TestPinnedOfficialDLLLoadsAndExportsThePermittedAPI(t *testing.T) {
	module, err := loadVerified(officialDLL(t), dllSHA256)
	if err != nil {
		t.Fatalf("official DLL was rejected: %v", err)
	}
	defer windows.FreeLibrary(module)
	for _, export := range []string{"WintunCreateAdapter", "WintunStartSession"} {
		if _, err := windows.GetProcAddress(module, export); err != nil {
			t.Fatalf("%s not exported: %v", export, err)
		}
	}
}

func TestTamperedDLLIsRejectedBeforeLoading(t *testing.T) {
	bytes, err := os.ReadFile(officialDLL(t))
	if err != nil {
		t.Fatal(err)
	}
	bytes[len(bytes)-1] ^= 0xff
	tampered := filepath.Join(t.TempDir(), "wintun.dll")
	if err := os.WriteFile(tampered, bytes, 0o644); err != nil {
		t.Fatal(err)
	}

	_, err = loadVerified(tampered, dllSHA256)
	if err == nil || !strings.Contains(err.Error(), "pinned digest") {
		t.Fatalf("tampered DLL must fail the digest check, got %v", err)
	}
}

func TestMissingDLLIsAnError(t *testing.T) {
	_, err := loadVerified(filepath.Join(t.TempDir(), "wintun.dll"), dllSHA256)
	if err == nil {
		t.Fatal("a missing DLL must not load")
	}
}

func TestRelativePathIsRefused(t *testing.T) {
	_, err := loadVerified("wintun.dll", dllSHA256)
	if err == nil || !strings.Contains(err.Error(), "relative") {
		t.Fatalf("a bare DLL name must be refused, got %v", err)
	}
}

func TestDLLIsResolvedBesideTheExecutable(t *testing.T) {
	path, err := dllPath("wintun.dll")
	if err != nil {
		t.Fatal(err)
	}
	exe, _ := os.Executable()
	if !filepath.IsAbs(path) || filepath.Dir(path) != filepath.Dir(exe) {
		t.Fatalf("expected an absolute path beside %s, got %s", exe, path)
	}
}
