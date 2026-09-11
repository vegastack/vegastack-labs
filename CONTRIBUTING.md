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

After the frozen install, the checks need no private registry or VegaStack credential. They verify repository safety, local documentation links and JSON, dependency provenance and licenses, the pinned Design System source, historical artifacts, Go packages, tooling tests, the static web export, and Chromium browser behavior.

For focused executable work, build and smoke-test the only shipped command directly:

```text
go build -o <temporary-output-path> ./cmd/vsk-labs
go run ./cmd/vsk-labs help
go run ./cmd/vsk-labs version --output json --schema-version 1
go run ./cmd/vsk-labs release inspect --manifest <local-manifest-path>
go run ./cmd/vsk-labs release verify --manifest <local-manifest-path> --policy <local-policy-path> --asset <asset-id>
```

Use a disposable output path and remove it with the host platform's normal file operation after the smoke test. Release inputs must be local public test material; do not use the command to install or execute an artifact. A successful Phase 1 verification means only `verified-against-supplied-policy` and reports that policy's SHA-256. It is not proof of an official VegaStack release; the later `G-017`/Phase 11 path must independently pin the real policy rather than accepting arbitrary release-adjacent policy material.

Run `corepack pnpm check:cli` to enforce the single-executable, generated-registry, no-SQLite, no-shell-dispatch, offline-release and no-artifact-execution boundaries and to cross-build the supported development targets into automatically removed temporary outputs. Run `corepack pnpm check:go-dependencies` after any Go module change; its reviewed inventory and notice seal cannot be regenerated as an approval shortcut. Cross-build success is not real-platform or release qualification.

For local control-service development on a supported isolated Linux fixture, use explicit protected configuration:

```bash
go run ./cmd/vsk-labs server run --config fixture/server-profile.json
go run ./cmd/vsk-labs server status --config fixture/server-profile.json --output json
```

Server-profile schema `1.1.0` always includes the complete remote-read object. Keep the development fixture disabled unless the test explicitly owns an isolated TLS listener and identity fixture:

```json
{
  "remoteRead": {
    "enabled": false,
    "bindAddress": null,
    "publicOrigin": null,
    "tlsCertificatePath": null,
    "tlsPrivateKeyPath": null,
    "identityAdapter": null,
    "identityConfigPath": null
  }
}
```

Refresh the committed embedded Console only from the pinned static build, then verify that the source output, manifest, and embedded bytes agree:

```text
corepack pnpm --filter @vegastack/labs-web build
node tooling/console-assets.mjs --write
node tooling/console-assets.mjs --check
go test ./internal/consoleassets ./internal/server
```

The write step intentionally changes generated files under `internal/consoleassets/`; inspect that complete diff before committing it. Ordinary Go build and server execution use those embedded files and require no Node.js process. Do not point this workflow at a live Console, real certificate, real adapter profile, or inventory fleet.

The profile is protected non-secret configuration: it contains local socket facts and UID-to-principal bindings, but no permissions, authorization grants, credential values, or private inventory. Use synthetic fixtures only and no real operational data. Never commit a machine-specific profile, real UID mapping, private path, fleet row, credential, or provider response. `corepack pnpm check:server` enforces the one-service, Unix-only, authenticated-context, no-SQLite and supported-platform boundaries.

With an isolated protected test server and explicit synthetic input, exercise the Issue #36 client surface through the same API:

```text
go run ./cmd/vsk-labs status --config fixture/server-profile.json --output json
go run ./cmd/vsk-labs database status --config fixture/server-profile.json --output json
go run ./cmd/vsk-labs inventory import --config fixture/server-profile.json --file fixture/inventory.json --format typed-json --source-revision synthetic-1 --captured-at 2026-09-10T06:00:00Z --idempotency-key synthetic-request-1 --output json
go run ./cmd/vsk-labs inventory diff --config fixture/server-profile.json --draft-id <synthetic-draft-id> --draft-revision 1 --output json
go run ./cmd/vsk-labs inventory export --config fixture/server-profile.json --draft-id <synthetic-draft-id> --draft-revision 1 --output json
```

The fixture server must grant only the synthetic test principal and use a disposable database/export root. Production composition intentionally has no signer, so export should return `PREREQUISITE_BLOCKED`; never add a private key merely to make a development smoke test pass. Do not use real inventory, source Sheet rows, machine paths, UIDs, credentials, provider responses, or signer material in a fixture, log, golden, issue, or commit. Redirected JSON stdout is only a client-side response record, not the verified server artifact.

The repository contains the approved `provider` and `dashboard-01` Design System `0.6.0` source closure. Ordinary builds verify its checked-in integrity lock and never contact the authenticated registry.

For an approved component refresh, put `CF_ACCESS_CLIENT_ID` and `CF_ACCESS_CLIENT_SECRET` in the gitignored root `.env.local`, then run:

```text
corepack pnpm refresh:design-system
corepack pnpm check:design-system
git diff -- tooling/design-system-lock.json web/components web/app/dashboard
```

Review the complete source and dependency diff before accepting an owned dashboard block with `node tooling/design-system.mjs --accept-owned-block --approve-version 0.6.0`. Run `corepack pnpm generate:provenance` only after reviewing the new exact dependency and license set, then run the full public check without credential variables. Roll back a rejected refresh through a normal Git revert; never paste registry responses or credentials into a commit, issue, log, screenshot, or artifact.

Build and preview the generated static Console on loopback with:

```text
corepack pnpm --filter @vegastack/labs-web build
corepack pnpm --filter @vegastack/labs-web preview
corepack pnpm --filter @vegastack/labs-web test:e2e
```

The preview serves only `web/out` on `127.0.0.1`. It is development tooling, not a production application server.

The embedded Console generator preserves the exact verified Next.js bytes. Some minified chunks contain intentional trailing spaces, so `.gitattributes` disables Git's whitespace diagnosis only for `internal/consoleassets/dist/**`; the manifest SHA-256 check, not whitespace rewriting, protects those generated files.

## Generated platform contracts

The typed Go graph under `internal/metadata` is the only editable source for platform command, schema, help, error, and exit metadata. To update it:

```text
corepack pnpm generate:contracts
corepack pnpm check:contracts
```

Review the metadata change together with the resulting files under `internal/generated`, `schemas/v1`, and `docs/generated`. Never edit a generated contract directly; the non-writing contract check is part of `corepack pnpm check` and rejects missing or stale output. Generation uses public local tooling only and does not contact a service or require a credential.

## Registry credentials

Do not commit credentials. A maintainer may put the following values in the root `.env.local` only for a separately approved registry refresh:

```text
CF_ACCESS_CLIENT_ID=
CF_ACCESS_CLIENT_SECRET=
```

The checked-in examples contain names only. Ordinary public CI and forks receive no registry secret; a future automated refresh would require a separately approved protected maintainer environment.

## Delivery

Development branches use the issue type: `feat/`, `fix/`, or `chore/`, followed by the development issue ID and short outcome. Never use an agent-name prefix. Run the narrow affected checks before `pnpm check`, keep generated provenance current through its documented generator, and include current evidence in the PR and issue implementation summary.
