# Development

## Requirements

- Rust stable (including `rustfmt` and `clippy`)
- Node.js 20 or later
- pnpm 9 or later
- macOS: Xcode Command Line Tools; Windows: Microsoft C++ Build Tools and WebView2

## Commands

```sh
pnpm install
pnpm dev                 # Vite web preview
pnpm --filter @linkdrop/desktop tauri dev
pnpm typecheck
pnpm lint
pnpm build
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

The Tauri dialog plugin limits the frontend to user-mediated file selection. Settings, trusted peers, and transfer history are persisted locally. Private identity material stays in the platform credential store.

## Two-Mac validation

Run the same commit on both Macs. Enable Discoverability, wait for devices to appear, then click Pair only once. Both apps must display the same code before either user trusts the peer. Send in both directions, approve each transfer, and compare source/received checksums using `shasum -a 256`.

## Windows packaging and firewall

On Windows, install Rust stable, Node.js 20+, pnpm 9+, Microsoft C++ Build Tools, and WebView2. Build unsigned development installers from a Windows checkout:

```powershell
pnpm install --frozen-lockfile
pnpm --filter @linkdrop/desktop tauri build
```

Tauri emits MSI and/or NSIS artifacts under `target\release\bundle`. Allow Linkdrop through Windows Defender Firewall on **Private** networks only. Linkdrop needs local UDP for QUIC and mDNS; discovery will not work on client-isolated networks or where multicast DNS is blocked.

## Known limitations

Multi-file batch manifests and restart-resumable transfers are not yet implemented. In-session pause/resume/cancel, persistent history, safe retries, integrity checks, and strict trusted-peer transport are implemented.
