# Build provenance

repository:  https://github.com/SagerNet/sing-box
version:     v1.14.4
commit:      c005f35300ce76427dc285481ec5695f5b179cd2
package:     ./cmd/sing-box
build tags:  with_quic,with_utls,with_clash_api,with_gvisor,with_wireguard,with_external_windivert
patches:     github.com/sagernet/sing-tun v0.9.7-0.20261023115432-040db71fcd33 patched from crates/xtask/patches/sing-tun (sha256 e5be002b37cac650e5aecabe0ed8094e29cd1556e77bc20d27f7f0a2ecfe1391)
binary:      primary-core.exe (44060672 bytes)
built by:    cargo xtask fetch-vendor

fingerprint: c005f35300ce76427dc285481ec5695f5b179cd2 tags=with_quic,with_utls,with_clash_api,with_gvisor,with_wireguard,with_external_windivert patch=github.com/sagernet/sing-tun@v0.9.7-0.20261023115432-040db71fcd33+e5be002b37cac650e5aecabe0ed8094e29cd1556e77bc20d27f7f0a2ecfe1391

This binary was built from the exact commit above, with the patches listed. See
`docs/adr/0004-vendored-binary-pins.md` and `THIRD-PARTY-NOTICES.md`.
