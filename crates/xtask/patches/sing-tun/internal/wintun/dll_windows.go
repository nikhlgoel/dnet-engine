/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2021 WireGuard LLC. All Rights Reserved.
 *
 * Modified by the DNet Engine project (patch applied by `cargo xtask fetch-vendor`):
 * the upstream loader mapped a copy of the adapter DLL that was compiled into the
 * executable. This replacement embeds nothing. It loads the vendor-signed prebuilt DLL,
 * shipped as a separate file beside the executable, by absolute path, and only after
 * its SHA-256 matches the pin for this architecture (dll_digest_windows_<arch>.go).
 */

package wintun

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"unsafe"

	"golang.org/x/sys/windows"
)

func (d *lazyDLL) NewProc(name string) *lazyProc {
	return &lazyProc{dll: d, Name: name}
}

type lazyProc struct {
	Name string
	mu   sync.Mutex
	dll  *lazyDLL
	addr uintptr
}

func (p *lazyProc) Find() error {
	if atomic.LoadPointer((*unsafe.Pointer)(unsafe.Pointer(&p.addr))) != nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.addr != 0 {
		return nil
	}

	err := p.dll.Load()
	if err != nil {
		return fmt.Errorf("error loading DLL: %s, MODULE: %s, error: %w", p.dll.Name, p.Name, err)
	}
	addr, err := windows.GetProcAddress(p.dll.module, p.Name)
	if err != nil {
		return fmt.Errorf("error getting %s address: %w", p.Name, err)
	}

	atomic.StorePointer((*unsafe.Pointer)(unsafe.Pointer(&p.addr)), unsafe.Pointer(addr))
	return nil
}

func (p *lazyProc) Addr() uintptr {
	err := p.Find()
	if err != nil {
		panic(err)
	}
	return p.addr
}

func (p *lazyProc) Load() error {
	return p.dll.Load()
}

type lazyDLL struct {
	Name   string
	Base   windows.Handle
	mu     sync.Mutex
	module windows.Handle
}

func newLazyDLL(name string) *lazyDLL {
	return &lazyDLL{Name: name}
}

func (d *lazyDLL) Load() error {
	if atomic.LoadPointer((*unsafe.Pointer)(unsafe.Pointer(&d.module))) != nil {
		return nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.module != 0 {
		return nil
	}

	path, err := dllPath(d.Name)
	if err != nil {
		return fmt.Errorf("unable to load library: %w", err)
	}
	module, err := loadVerified(path, dllSHA256)
	if err != nil {
		return fmt.Errorf("unable to load library: %w", err)
	}
	d.Base = module

	atomic.StorePointer((*unsafe.Pointer)(unsafe.Pointer(&d.module)), unsafe.Pointer(module))
	return nil
}

// dllPath is the DLL's absolute path beside the running executable. Never a bare name:
// a bare name would let the loader's search order pick up a planted copy.
func dllPath(name string) (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("locate executable: %w", err)
	}
	return filepath.Join(filepath.Dir(exe), name), nil
}

// loadVerified loads the DLL at path only if its bytes hash to wantSHA256.
//
// The file is held open with read-only sharing from before the hash until after the
// load, so nothing can write, replace, or rename it between the check and the load.
func loadVerified(path, wantSHA256 string) (windows.Handle, error) {
	if !filepath.IsAbs(path) {
		return 0, fmt.Errorf("%s: refusing a relative DLL path", path)
	}
	if wantSHA256 == "" {
		return 0, errors.New("no pinned DLL digest for this architecture")
	}
	path16, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}
	handle, err := windows.CreateFile(path16, windows.GENERIC_READ, windows.FILE_SHARE_READ,
		nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return 0, fmt.Errorf("open %s: %w", path, err)
	}
	file := os.NewFile(uintptr(handle), path)
	defer file.Close()

	digest := sha256.New()
	if _, err := io.Copy(digest, file); err != nil {
		return 0, fmt.Errorf("read %s: %w", path, err)
	}
	if got := hex.EncodeToString(digest.Sum(nil)); got != wantSHA256 {
		return 0, fmt.Errorf("%s does not match the pinned digest (got %s)", path, got)
	}

	// An absolute path names the file itself; SEARCH_SYSTEM32 confines the search for
	// its own imports to System32.
	module, err := windows.LoadLibraryEx(path, 0, windows.LOAD_LIBRARY_SEARCH_SYSTEM32)
	if err != nil {
		return 0, fmt.Errorf("load %s: %w", path, err)
	}
	return module, nil
}
