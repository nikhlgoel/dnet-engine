// DNet Engine patch: SHA-256 of bin/amd64/wintun.dll in the official 0.14.1 distribution
// zip. Must equal the pin in crates/xtask/src/pins.rs (a unit test there checks it).

package wintun

const dllSHA256 = "e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce"
