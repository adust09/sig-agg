## Overview
Benchmarks currently call into the same XMSS key generation path as production flows, so creating a 100-signature dataset forces us to generate full Merkle trees. We will introduce a strategy abstraction that lets the benchmark switch between the current “real” path and a new “phony” implementation inspired by leanMultisig: generate a true WOTS key pair, then walk up the Merkle levels using randomly sampled sibling hashes.

## Key Decisions
1. **Strategy enum** – encapsulate key creation/signing differences behind a `KeyMaterialStrategy` so host CLI simply requests data via the enum without duplicating logic.
2. **Phony path storage** – precompute the random sibling hashes for each epoch so signing just replays them, matching leanMultisig’s deterministic behavior per seed.
3. **Cache separation** – include the strategy label in cache filenames and metadata to prevent accidentally loading real batches inside benchmark runs (or vice versa).
4. **User safeguards** – default remains `Real`; CLI/env flag is opt-in and prints a warning banner whenever phony mode is used; docs underline that it is unsafe for production proofs.

## Open Questions / Assumptions
- `openspec/project.md` has not been populated yet, so naming/style rules are based on existing repo conventions plus AGENTS.md guidance.
- leanMultisig’s `PhonyXmssSecretKey` treats each signature independently; we will assume similar behavior (one fake Merkle path per item) is acceptable because benchmarks already regenerate data per batch.
