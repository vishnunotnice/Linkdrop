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
pnpm --dir apps/desktop tauri dev  # desktop application
pnpm typecheck
pnpm lint
pnpm build
cargo fmt --check
cargo clippy --workspace -- -D warnings
cargo test --workspace
```

The Tauri dialog plugin limits the frontend to user-mediated file or folder selection. It does not expose arbitrary filesystem reads. Settings are persisted in the app's local store. Desktop commands expose application information and settings only.

## Known limitations

There is no mDNS discovery, peer pairing, QUIC, TLS session, transfer, history persistence, or SQLite database yet. The Transfers development preview uses a conspicuous demo label and is not live activity.

## Phase 2 discovery

Run Linkdrop on two macOS or Windows devices on the same LAN with `pnpm --dir apps/desktop tauri dev`. Enable Discoverability in Settings on both. Nearby devices should appear automatically through `_linkdrop._udp.local.`. If they do not, disable VPN/virtual adapters temporarily, check Wi-Fi client isolation, and allow multicast UDP/mDNS through macOS or Windows Defender Firewall. Discovery has no transfer listener and does not authenticate peers.
