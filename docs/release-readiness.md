# Release readiness report

## Implemented

- Ed25519 identities stored by the desktop adapter in the platform credential store.
- Identity-bound certificates, TLS 1.3, pinned mutual QUIC authentication, and blocked-peer rejection.
- mDNS discovery as an untrusted locator.
- Explicit signed pairing-envelope exchange with a 15-second timeout and matching-code regression test.
- Receiver-approved, bounded streaming transfers with BLAKE3 integrity verification, safe paths, cleanup, and duplicate-name protection.
- Trusted-device list, block, unblock, and remove controls.
- In-session transfer pause, resume, and cancellation controls.

## Verified evidence

At this repository revision, `cargo fmt --all -- --check`, `cargo check --workspace`, `cargo clippy --workspace --all-targets -- -D warnings`, and `cargo test --workspace` pass. The workspace test count is 28. Frontend type-check, ESLint, and production build pass.

## Pending physical validation

- Two-Mac discovery, code confirmation, trust persistence, and bidirectional checksum-verified transfers.
- macOS ↔ Windows, Windows ↔ macOS, and Windows ↔ Windows testing.
- 1 KB, 10 MB, 100 MB, and 1 GB physical transfer scenarios.
- Installer launch/uninstall testing.

## Security findings and limitations

No permissive TLS fallback was introduced. Pairing and normal transport use distinct ALPN values. Restart-resume checkpoints, transfer persistence, formal resource quotas, signing, notarization, and an independent security audit remain outstanding.

## Exact next actions

1. On both Macs, update to the same revision and run `pnpm --filter @linkdrop/desktop tauri dev`.
2. Pair only once from one Mac, compare the code on both screens, and trust both sides.
3. Send files in both directions, approve each offer, and compare `shasum -a 256` output.
4. Build a macOS package with `pnpm --filter @linkdrop/desktop tauri build`.
5. Run the same validation on Windows before publishing any release.
