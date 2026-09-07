# Development phase 1 — Portable executable and generated contracts

Status: active. Phase 0 was accepted by (omkarmohanta09) on 07-09-2026. [Issue 1.1 (#24)](https://github.com/vegastack/vegastack-labs/issues/24) and [Issue 1.2 (#25)](https://github.com/vegastack/vegastack-labs/issues/25) are merged with their integrated public checks passing. [Issue 1.3 (#28)](https://github.com/vegastack/vegastack-labs/issues/28) owns the remaining Phase 1 release-manifest and offline-verification slice. Phase acceptance still requires Issue 1.3's reviewed merge, an integrated check, the combined demonstration below and explicit operator acceptance.

## Outcome

Deliver the provider-neutral public-contract foundation and the first portable `vsk-labs` executable. Operators and later API, Console, and agent clients receive one generated command vocabulary, one versioned machine-result envelope, stable error/exit mappings, deterministic help, truthful unavailable-command behavior, and local release inspection and verification without introducing server, database, provider, credential, installation or infrastructure authority.

Issue #24 establishes the metadata source and generated artifacts. Issue #25 consumes those artifacts to build the executable and portable client boundaries. Issue #28 extends the same graph and executable with strict local release contracts and an in-process offline verifier. The order is deliberate: runtime commands must not create a handwritten command tree that competes with their public contract.

## Requirements and boundaries

- Typed Go under `internal/metadata` is the only editable source for command, flag, schema, help, error, and exit metadata. The developer-only generator adds no second shipped executable.
- Generated Go, JSON Schema, registry JSON, and Markdown help are checked into Git for review. A non-writing check compares exact bytes and fails on missing, stale, or manually edited output.
- `help`, `version`, `release inspect` and `release verify` are the available Phase 1 commands. Other command paths already fixed in [Automation and agents](../../automation-and-agents.md#command-surface) remain visible but unavailable, risk-unassigned placeholders and carry no invented command-specific runtime behavior.
- The machine-result envelope preserves schema major `1`, the documented required fields, ordered errors, and exit codes `0` and `2` through `9`. JSON stdout, human stderr, and secret-free output remain binding for the executable implementation.
- Generation is deterministic UTF-8 with LF line endings and stable ordering. This artifact guarantee does not define the canonical JSON or digest algorithm for future immutable plans; Phase 4 owns that compatibility contract.
- Platform-core metadata contains no provider or VegaStack Labs deployment value. No work in this phase opens SQLite, starts `server run`, resolves credentials, contacts a provider, executes a plan, publishes a release, or changes live infrastructure.
- Cross-compilation in Issue #25 proves portable build seams only. It does not prove installation, OS credential stores, service management, signing, notarization, or the supported release matrix.

## Generated-contract workflow

The contract flow is:

```text
internal/metadata (edit here)
        |
        v
developer-only Go generator
        |
        +--> internal/generated/contracts_gen.go
        +--> schemas/v1/*.json
        +--> docs/generated/command-registry.md
        |
        v
read-only drift check in the public lane
```

Contributors run `corepack pnpm generate:contracts`, review both the metadata and generated diff, and then run `corepack pnpm check:contracts`. The complete `corepack pnpm check` includes the same non-writing drift check, the portable CLI boundary and temporary target cross-build check, then Go vet, tests, and build.

## Ordered issue index

| Issue ID | Outcome and required proof | Dependencies | GitHub link |
|---|---|---|---|
| **1.1** | One typed metadata graph generates byte-stable Go, JSON/schema, and help artifacts; validation rejects drift, duplicate contracts, unsafe paths, wrong error/exit mappings, unsupported majors, speculative planned-command details, and secret-bearing diagnostics. | Phase 0 accepted; approved Brief v2 and Plan v1. | [1.1 (#24)](https://github.com/vegastack/vegastack-labs/issues/24) |
| **1.2** | One `vsk-labs` executable consumes the generated graph for help, version, errors, exits, and explicit unavailable-command behavior while preserving portable paths, opaque credential references, and direct argument-array transports. | 1.1 merged and re-grounded; separately approved Plan v1. | [1.2 (#25)](https://github.com/vegastack/vegastack-labs/issues/25) |
| **1.3** | Strict local manifests and a supplied trust policy drive offline, exact-identity Sigstore verification of an authenticated manifest and explicitly selected assets without installation, execution or network access. | 1.1 and 1.2 merged; approved Brief v2 and Plan v1. | [1.3 (#28)](https://github.com/vegastack/vegastack-labs/issues/28) |

Issue #28 is the Phase 1 acceptance owner because it completes the release slice and must demonstrate Issues #24, #25 and #28 together. Dependency order remains explicit and sequential even though capability ownership crosses multiple modules.

## Cross-module Phase 1 delivery

Modules are capability ownership maps; Phase 1 is the delivery slice. The following matrix prevents either structure from becoming a second execution order.

| Capability parent | Phase 1 contribution | Delivery issue | State after Issue 1.3 merges |
|---|---|---|---|
| [Module 1 — Platform Core (#7)](https://github.com/vegastack/vegastack-labs/issues/7) | Generated provider-neutral command/schema/error graph and one executable consuming it. | [#24](https://github.com/vegastack/vegastack-labs/issues/24), [#25](https://github.com/vegastack/vegastack-labs/issues/25), [#28](https://github.com/vegastack/vegastack-labs/issues/28) | Phase 1 slice complete; database, server, plans, policy and execution remain later work. |
| [Module 4 — Source control, CI and releases (#10)](https://github.com/vegastack/vegastack-labs/issues/10) | Release manifest, compatibility model and offline verification against supplied policy. | [#28](https://github.com/vegastack/vegastack-labs/issues/28) | Phase 1 slice complete; actual SCM/CI, signing, publication and official distribution remain Phases 9 and 11. |
| [Module 6 — Secrets and credential lifecycle (#12)](https://github.com/vegastack/vegastack-labs/issues/12) | Secret-safe public errors, opaque credential references and no-reveal transport boundaries. | [#24](https://github.com/vegastack/vegastack-labs/issues/24), [#25](https://github.com/vegastack/vegastack-labs/issues/25) | Phase 1 slice complete; resolution, delivery, rotation and recovery remain later work. |
| [Module 9 — Operator experience (#15)](https://github.com/vegastack/vegastack-labs/issues/15) | Generated help, stable human/JSON output and explicit supplied-policy verification wording. | [#24](https://github.com/vegastack/vegastack-labs/issues/24), [#25](https://github.com/vegastack/vegastack-labs/issues/25), [#28](https://github.com/vegastack/vegastack-labs/issues/28) | Phase 1 slice complete; Console, skills, runbooks and native-client qualification remain later work. |

## Interim trust policy

Phase 1 accepts an explicitly supplied local policy containing an exact certificate identity, exact OIDC issuer and local trusted-root material. Every successful verification reports `verified-against-supplied-policy` and the SHA-256 of the policy's raw bytes. Synthetic public fixtures prove behavior only; they do not identify or verify an official VegaStack release.

This decision is temporary and must not become the installation trust model. After `G-017` establishes the real release repository, workflow identity, OIDC policy, feed URLs and successful verification of actual assets, Phase 11 must independently pin that real policy. Official installation and update paths must reject arbitrary adjacent policy files and must not trust policy material delivered only by the untrusted release being checked.

## Verification and exit demonstration

Each issue runs its focused Go/tooling tests first, then the complete credential-free public lane and a temporary clean-checkout comparison at the exact candidate commit. Fresh independent review covers contract completeness, generated ownership, path safety, deterministic serialization, stdout/stderr, secret-safe failure, portable argument/path behavior, and accidental provider or authorization coupling.

The integrated Phase 1 demonstration must show all of the following from one reviewed commit on `main`:

1. `vsk-labs help` and `vsk-labs version` are generated-contract consumers in human and JSON modes.
2. A documented planned command returns the approved explicit unavailable error and exit without prompting or starting work.
3. A deliberate generated-file edit makes `check:contracts` and the complete public lane fail while leaving the worktree unchanged; regeneration restores exact output.
4. Unknown commands, flags, output/schema majors, and private-value canaries follow the stable error, exit, and stream boundaries.
5. Linux, macOS, and Windows target builds compile to isolated temporary outputs, with the documented distinction between cross-build proof and real-platform qualification.
6. No second executable, server runtime, writable database, provider call, credential reveal, release, or live operation exists.
7. `release inspect` reports compatibility and asset metadata while explicitly stating that cryptographic verification was not performed.
8. `release verify` authenticates the raw manifest first, then only explicit `--asset` selections or explicit `--all`, and reports the supplied-policy status and fingerprint.
9. Valid, tampered, wrong-identity, missing, incompatible, path-race and cancellation cases produce the documented stable results without network access, artifact execution or private-path disclosure.

Phase 1 closes only after all three issues are merged, their integrated checks pass, Issue #28 posts the combined evidence, and the operator accepts the phase exit. `G-017` remains open because no real release identity, feed or actual asset has been established. `G-018` also remains open after this foundation: later owning issues must extend the same graph until every command in the first mutating release has complete generated coverage.

Issues #25 and #28 implement only the foundation demonstration: generated command dispatch, exact human/JSON stream behavior, explicit unavailable-command failure, portable path calculation, logical credential metadata verification, direct-argument transport and local supplied-policy release verification. They add no server, SQLite owner, authentication, secret resolver, real executor, provider adapter, release publication, installation or infrastructure authority. Linux, macOS and Windows cross-builds are development evidence rather than native OS qualification.

## Effort and approvals

Issue #24 estimated 45 agent minutes with a 90-minute checkpoint, about 8 minutes of operator review, and public CI as its only external wait. Issue #25 uses a parallel implementation schedule: 45–50 expected elapsed agent minutes, a 100-minute checkpoint, about 10 minutes of operator review and public CI as its only external wait. Approximately 65–75 aggregate agent-minutes are distributed across the coordinator and isolated path, credential and transport workers; aggregate work is not elapsed waiting time.

Approval record: (omkarmohanta09) approved the briefs for Issues #24 and #25 on 07-09-2026, approved Plan v1 for Issue #24 on 07-09-2026, and approved Plan v1 plus parallel implementation for Issue #25 on 07-09-2026. The operator approved Brief v1, all three recommended trust/selection/dependency choices, Brief v2, Plan v1 and parallel go-dark implementation for Issue #28 on 07-09-2026 and 08-09-2026. This development authority covers each named issue's branch, commits, tests, documentation, issue comments, and fresh review. Pull-request creation, merge, Phase 1 exit acceptance, release, repository administration, credentials, providers, hosts, networks, databases, and every live infrastructure action remain separately gated.
