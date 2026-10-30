# Architecture

Linkdrop is a Tauri 2 desktop application: React/TypeScript renders the interface and Rust owns identity, protocol boundaries, and platform integration. The root Cargo workspace keeps networking, storage, identity, transfer state, and shared models independently testable.

| Crate | Responsibility |
| --- | --- |
| `linkdrop-core` | Serialized device and transfer domain types |
| `linkdrop-identity` | Ed25519 identity creation and public-key-derived device IDs |
| `linkdrop-discovery` | mDNS discovery interface (disabled in Phase 1) |
| `linkdrop-protocol` | Future authenticated QUIC protocol boundary |
| `linkdrop-transfer` | Transfer state-machine rules |
| `linkdrop-storage` | Settings storage contract |

The TypeScript types at `apps/desktop/src/types/models.ts` mirror the Rust serde wire names. Changes to either contract must update the other and its tests; code generation is planned once protocol schemas stabilize.

In Phase 2, `linkdrop-discovery` owns a cross-platform `mdns-sd` daemon, advertises a discovery-only `_linkdrop._udp.local.` record, validates TXT records, deduplicates by device ID, expires stale records, and emits typed changes. The Tauri layer forwards these as `discovery-event` events; React renders snapshots and real-time changes without direct network access.
