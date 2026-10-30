# Linkdrop

**Your files. Any device. No cloud.**

Linkdrop is an open-source, local-first file sharing app. Phase 1 supplies a Tauri desktop shell, persistent preferences, a secure identity foundation, and deliberately non-functional discovery/transfer placeholders.

## Quick start

Install Rust (stable), Node.js 20+, and pnpm. Then:

```sh
pnpm install
pnpm --dir apps/desktop tauri dev
```

For checks, run `pnpm typecheck`, `pnpm lint`, `pnpm build`, `cargo test --workspace`, `cargo clippy --workspace -- -D warnings`, and `cargo fmt --check`.

## License

MIT. It is short, permissive, and suitable for broad open-source adoption. See [LICENSE](LICENSE).

## Status

Discovery and network transfer are **not implemented** in Phase 1. See `docs/` for the architecture, security assumptions, and roadmap.
