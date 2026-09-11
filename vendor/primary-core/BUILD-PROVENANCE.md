# Build provenance

repository:  https://github.com/SagerNet/sing-box
version:     v1.14.0
commit:      0b8995879f29a9b98ee027bc17b75e101445b238
package:     ./cmd/sing-box
build tags:  with_quic,with_utls,with_clash_api,with_gvisor,with_external_windivert
patches:     github.com/sagernet/sing-tun v0.9.0-beta.4 patched from crates/xtask/patches/sing-tun (sha256 e5be002b37cac650e5aecabe0ed8094e29cd1556e77bc20d27f7f0a2ecfe1391)
binary:      primary-core.exe (43097600 bytes)
built by:    cargo xtask fetch-vendor

fingerprint: 0b8995879f29a9b98ee027bc17b75e101445b238 tags=with_quic,with_utls,with_clash_api,with_gvisor,with_external_windivert patch=github.com/sagernet/sing-tun@v0.9.0-beta.4+e5be002b37cac650e5aecabe0ed8094e29cd1556e77bc20d27f7f0a2ecfe1391

This binary was built from the exact commit above, with the patches listed. See
`docs/adr/0004-vendored-binary-pins.md` and `THIRD-PARTY-NOTICES.md`.
