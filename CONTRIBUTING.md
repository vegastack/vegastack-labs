# Contributing

VegaStack Labs uses a credential-free public development lane. Read [AGENTS.md](AGENTS.md) and the [development mandate](docs/development/operating-mandate.md) before changing code.

## Toolchain

- Go 1.27.0
- Node.js 24.20.0
- pnpm 11.24.0 through Corepack

Use the exact versions recorded in `go.mod`, `.node-version`, and the root `packageManager` field. Do not replace system-wide tools merely to work on this repository; a verified official distribution in a temporary tool directory is sufficient.

The Phase 0.2 dependency proof supports macOS ARM64 development and Ubuntu 24.04 x64 GNU CI. The lockfile retains only those exact MPL-covered `lightningcss` platform binaries; adding another development platform requires a separate license review before changing that set. The orchestration itself remains shell-free and uses portable argument arrays so later platform lanes can extend the matrix deliberately.

## Public checks

```text
corepack pnpm install --frozen-lockfile
corepack pnpm check
```

After the frozen install, the checks need no private registry or VegaStack credential. They verify repository safety, local documentation links and JSON, dependency provenance and licenses, historical artifacts, Go packages, tooling tests, and the static web export.

For focused executable work, build and smoke-test the only shipped command directly:

```text
go build -o <temporary-output-path> ./cmd/vsk-labs
go run ./cmd/vsk-labs help
go run ./cmd/vsk-labs version --output json --schema-version 1
```

Use a disposable output path and remove it with the host platform's normal file operation after the smoke test. Run `corepack pnpm check:cli` to enforce the single-executable, generated-registry, no-SQLite and no-shell-dispatch boundaries and to cross-build the supported development targets into automatically removed temporary outputs. Cross-build success is not real-platform or release qualification.

The public scaffold does not contain private design-system registry components. `web/components.json` documents the optional authenticated registry shape for a future approved maintainer lane, but public checks never contact it.

## Generated platform contracts

The typed Go graph under `internal/metadata` is the only editable source for platform command, schema, help, error, and exit metadata. To update it:

```text
corepack pnpm generate:contracts
corepack pnpm check:contracts
```

Review the metadata change together with the resulting files under `internal/generated`, `schemas/v1`, and `docs/generated`. Never edit a generated contract directly; the non-writing contract check is part of `corepack pnpm check` and rejects missing or stale output. Generation uses public local tooling only and does not contact a service or require a credential.

## Registry credentials

Do not commit credentials. After the ignore rules in this repository are present, a maintainer may put the following values in `web/.env.local` for a separately approved registry operation:

```text
CF_ACCESS_CLIENT_ID=
CF_ACCESS_CLIENT_SECRET=
```

The checked-in `web/.env.example` contains names only. GitHub automation must use separately approved protected environment secrets; ordinary public CI and forks receive none.

## Delivery

Development branches use the issue type: `feat/`, `fix/`, or `chore/`, followed by the development issue ID and short outcome. Never use an agent-name prefix. Run the narrow affected checks before `pnpm check`, keep generated provenance current through its documented generator, and include current evidence in the PR and issue implementation summary.
