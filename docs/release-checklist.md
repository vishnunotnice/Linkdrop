# Release checklist

## Build and test

- [x] Rust format, check, strict Clippy, and workspace tests pass on the current local commit.
- [x] Frontend type-check, lint, and production build pass.
- [ ] Tauri production build succeeds on macOS and Windows. (macOS arm64 DMG built locally; Windows pending.)
- [ ] Two-Mac pairing and bidirectional checksum validation pass.
- [ ] macOS↔Windows and Windows↔Windows validation pass.

## macOS

- [ ] Apple Developer signing certificate is available outside the repository.
- [ ] `APPLE_SIGNING_IDENTITY`, notarization credentials, and hardened-runtime configuration are supplied through secure CI secrets.
- [ ] DMG is signed, notarized, stapled, installed, and launch-tested on a clean Mac.

## Windows

- [ ] MSI/NSIS package is built on Windows.
- [ ] Authenticode certificate is supplied through secure CI secrets; no private key is committed.
- [ ] Installer, uninstall, Windows Firewall prompt, discovery, pairing, and transfers are tested on a clean Windows machine.

## Release blockers at repository state

- Two-device physical validation has not been recorded.
- Windows build and runtime validation have not been recorded.
- Code signing and Apple notarization credentials are not available in this repository.
- In-session pause/resume is implemented; restart-resume checkpoints are not.
- The local macOS package is ad-hoc signed only; it has not been installed or notarized.
