<!-- OPENSPEC:START -->
# OpenSpec Instructions

These instructions are for AI assistants working in this project.

Always open `@/openspec/AGENTS.md` when the request:
- Mentions planning or proposals (words like proposal, spec, change, plan)
- Introduces new capabilities, breaking changes, architecture shifts, or big performance/security work
- Sounds ambiguous and you need the authoritative spec before coding

Use `@/openspec/AGENTS.md` to learn:
- How to create and apply change proposals
- Spec format and conventions
- Project structure and guidelines

Keep this managed block so 'openspec update' can refresh the instructions.

<!-- OPENSPEC:END -->

# Repository Guidelines

## Project Structure & Module Organization
The workspace centers on the `sig-agg` crate (`Cargo.toml` at repo root) that will expose aggregation logic through `src/lib.rs`. The `src/jolt` directory hosts a standalone Rust binary used to benchmark XMSS verification inside the Jolt zkVM; it contains a `guest/` crate compiled into the zk program and a `src/main.rs` orchestrator that caches benchmark data under `tmp/`. Shared formatting configs live in `rustfmt.toml` files, and generated artifacts should stay in `target/` or `/tmp/jolt-guest-targets`.

## Build, Test, and Development Commands
- `cargo fmt` — format all Rust crates using the repo `rustfmt.toml` settings.
- `cargo clippy --all-targets --all-features` — run lint checks with the stricter workspace configuration defined in `Cargo.toml`.
- `cargo test` — execute unit tests for the root crate; use `cargo test --manifest-path src/jolt/Cargo.toml` for the host and guest crates.
- `cargo run --manifest-path src/jolt/Cargo.toml --release` — build the Jolt benchmark binary and produce/verify the zk proof, reusing cached data when available.
- Set `PHONY_KEYS=1` (or pass `--phony-keys`) to generate benchmark datasets with phony Merkle paths. This mode is **benchmark-only**; never use it for production proofs. Real and phony batches maintain separate caches under `tmp/`.

## Coding Style & Naming Conventions
Rust code follows `rustfmt` defaults with 4-space indentation and trailing commas for multi-line literals. Prefer `snake_case` for functions/modules, `CamelCase` for types, and avoid abbreviations that obscure meaning. Leverage explicit type aliases when wrapping Jolt SDK primitives. Keep imports grouped by crate and enable Clippy to guard against unhandled `Result` values (note `unused_must_use = deny`).

## Testing Guidelines
Favor unit tests colocated via `mod tests` blocks and integration tests under `tests/` if cross-module coverage is needed. Ensure host-side tests reset or stub `/tmp` cache usage to remain deterministic. Run both `cargo test` commands before submitting changes, and add regression coverage whenever touching signature verification or serialization logic.

## Commit & Pull Request Guidelines
Follow the existing history by using short, imperative subject lines (e.g., `Add XMSS batch helper`). Reference related issues in the body and note any external data files required. PRs should include a brief summary, highlight performance impacts, and confirm `cargo fmt`, `cargo clippy`, and both test suites have been run. Attach logs or benchmarks when modifying the Jolt pipeline.
