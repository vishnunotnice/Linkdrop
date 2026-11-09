# Linkdrop

**Your files. Any device. No cloud.**

Linkdrop is a local-first desktop file-sharing application for macOS and Windows. It discovers nearby devices on a LAN, pairs devices through an explicit verification-code ceremony, and transfers approved files over pinned mutual-TLS QUIC connections.

## Current status

The codebase includes discovery, pairing, trusted-device management, and streaming file transfer with receiver approval, progress, in-session pause/resume/cancel controls, safe duplicate filenames, and BLAKE3 integrity verification.

Two-Mac end-to-end validation and Windows validation are still required before calling any build a production release. Linkdrop is not audited security software.

## Quick start

Requirements: Rust stable, Node.js 20+, pnpm 9+, and platform build tools.

```sh
pnpm install
pnpm --filter @linkdrop/desktop tauri dev
```

Run the desktop app on two devices on the same LAN. Enable Discoverability on both, pair from Home, compare the six-digit code on both screens, and explicitly trust only if the codes match.

## Checks

```sh
cargo fmt --all -- --check
cargo check --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
pnpm --filter @linkdrop/desktop typecheck
pnpm --filter @linkdrop/desktop lint
pnpm --filter @linkdrop/desktop build
```

See [development](docs/development.md), [architecture](docs/architecture.md), [protocol](docs/protocol.md), [security model](docs/security.md), and the [release checklist](docs/release-checklist.md).

## License

MIT. See [LICENSE](LICENSE).
