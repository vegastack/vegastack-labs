# Development phase 3 — Secure read Console and operator access

Status: accepted by (omkarmohanta09) on 12-09-2026 at exact `main` commit `a0a07a425d6396703d8bec438634d9ec2c2ae980`. [Main run 34703617111](https://github.com/vegastack/vegastack-labs/actions/runs/34703617111) passed the complete Phase 3 exit on the authorized disposable Debian runner with evidence digest `sha256:b051c6f0a81498c09a159c14e16999b7cc3b02cd9ed758376684d31022587f1f`. Issue 3.9 (#58) records the explicit operator words: “Accept Phase 3 at a0a07a425d6396703d8bec438634d9ec2c2ae980”.

## Outcome and authority boundary

Phase 3 embeds the statically exported VegaStack Design System Console in the single `vsk-labs server run` process. The Console uses the generated same-origin read client to show implemented core state, truthful source freshness, and explicit unavailable or partial states. A provider-neutral identity adapter and short-lived, revocable browser sessions protect remote reads. The local Unix-socket CLI recovery path remains independent of remote identity and browser availability.

This phase does not add declarations, plans, approvals, execution, infrastructure mutation, a Node.js production server, direct browser access to SQLite or providers, a live Cloudflare/Workspace configuration, a release, a deployment, or a fleet qualification. Status-only People, Services, Backups, and Providers screens do not invent records that their later owning phases have not implemented. All integrated product proof below uses public synthetic fixtures.

## Ordered issue index and waves

| Issue ID | Outcome and required proof | Wave and dependencies | GitHub link |
|---|---|---|---|
| **3.1** | Establish the static Console, pinned VegaStack Design System source, local preview, and Playwright evidence foundation. | Wave A; Phase 2 read contracts. | [Issue 3.1 (#50)](https://github.com/vegastack/vegastack-labs/issues/50) |
| **3.2** | Generate a strict browser-safe client for only the implemented read API, including pagination, cancellation, and event resume. | Wave A; Phase 2 endpoint and schema metadata. | [Issue 3.2 (#51)](https://github.com/vegastack/vegastack-labs/issues/51) |
| **3.3** | Expose provider-neutral health, freshness, source-state, filtering, and summary contracts without pretending missing providers are healthy. | Wave A; Phase 2 authorization and read API. | [Issue 3.3 (#52)](https://github.com/vegastack/vegastack-labs/issues/52) |
| **3.4** | Embed verified Console assets in `vsk-labs server run` and serve protected same-origin static and read routes while preserving local recovery. | Wave B; 3.1 and 3.2. | [Issue 3.4 (#53)](https://github.com/vegastack/vegastack-labs/issues/53) |
| **3.5** | Authenticate external identity, create and renew short browser sessions, and fail closed on logout, expiry, revocation, recovery change, wrong host/origin, or denied scope. | Wave B; integrates after 3.2 and consumes 3.3 source contracts. | [Issue 3.5 (#54)](https://github.com/vegastack/vegastack-labs/issues/54) |
| **3.6** | Build generated-client-only Overview, Nodes, and Gates reads with pagination, details, focus recovery, and honest loading/empty/stale/partial/denied/error states. | Wave B; 3.1 through 3.3. | [Issue 3.6 (#55)](https://github.com/vegastack/vegastack-labs/issues/55) |
| **3.7** | Build status-only People, Services, Backups, and Providers screens that expose source truth and defer real records to later phases. | Wave B; 3.1 through 3.3 and selected after 3.6. | [Issue 3.7 (#56)](https://github.com/vegastack/vegastack-labs/issues/56) |
| **3.8** | Drive the actual built server over loopback TLS in pinned Chromium and prove browser security, accessibility, responsive behavior, outage handling, local recovery, and sanitized results. | Wave C; 3.4 through 3.7. | [Issue 3.8 (#57)](https://github.com/vegastack/vegastack-labs/issues/57) |
| **3.9** | Bind every Phase 3 requirement and child result to one exact clean commit, rerun the complete fixture lane, and ask the operator to accept or reject the phase. | Wave D; 3.1 through 3.8 merged with green post-merge checks. | [Issue 3.9 (#58)](https://github.com/vegastack/vegastack-labs/issues/58) |

```text
Wave A: 3.1 + 3.2 + 3.3
                    |
Wave B: 3.4 + 3.5 + 3.6 -> 3.7
                    |
Wave C:             3.8
                    |
Wave D:             3.9
```

The waves record implementation dependencies, not authority. Parallel work still used isolated issue branches, and every merge retained its own checks, evidence, and fresh review.

## Frozen Phase 3 boundaries

### Generated browser client

- Browser code calls only generated, fixed same-origin `/api/v1` read routes. It cannot construct arbitrary URLs, open SQLite, call providers, import Go internals, or expose a mutation route.
- Closed schemas strictly decode versioned envelopes and keep stable API failures distinct from malformed data, cancellation, cursor expiry, and network loss.
- Bounded pagination, response/frame sizes, cancellation, and supported event resume are part of the generated contract. Generation drift fails the public check.

### Source truth and freshness

- `database`, `nodes`, `gates`, `people`, `services`, `backups`, and `providers` report only `healthy`, `stale`, `unknown`, `unavailable`, or `failed`, with bounded safe reasons and known timestamps.
- Summary reads report source counts and the worst state. Missing or disabled optional providers remain visibly unavailable; an optional-source failure cannot disable local reads.
- Source filters, grants, cursors, evaluation time, revision, recovery epoch, and expiry remain bound together. The browser cannot relabel omitted or rejected source data as healthy.

### Same-origin embedded server

- The one Go server owns the verified static asset bundle and protected reads. Production has no Node.js server and serves no unverified or drifted Console build.
- Remote browser service is disabled by default. When configured, it requires TLS 1.3, the exact host, bounded connections, security headers and CSP, and authentication before downstream route or query parsing.
- Remote bind, configuration, identity, or Console failure does not remove the independently authenticated local Unix-socket service and CLI recovery route.

### Browser session

- The provider-neutral identity seam verifies the selected fixture JWT signature, issuer, audience, expiry, and key rotation before mapping a subject to a principal. An email header never establishes identity.
- Session records retain irreversible digests and short lifetimes. Every read rechecks principal state, exact grant, grant revision, recovery epoch, session lifetime, and the current provider assertion.
- Logout, expiry, suspension/revocation, recovery invalidation, wrong Host, wrong Origin, and missing authorization fail closed. Unsafe session requests require exact Origin; safe same-origin requests use the recorded browser Fetch Metadata rule.

### Read-only status experience

- Overview, Nodes, and Gates consume implemented generated reads. Nodes uses server pagination and typed details; Gates reports capability, not invented activation evidence.
- People, Services, Backups, and Providers intentionally show only source status in Phase 3. Their real records and operations remain with their later owning phases.
- Every view distinguishes loading, empty, stale, partial, unknown, unavailable, denied, malformed, and error states where applicable. Privacy fixtures prove that private backing records do not cross the authorized response boundary.
- Keyboard access, focus restoration, named landmarks, unique titles, mobile reflow/targets, light and dark themes, reduced motion, and serious accessibility violations are covered by repeatable browser assertions.

### Browser evidence and sanitation

- `pnpm check:phase-3` builds a temporary race-enabled `vsk-labs`, launches its actual `server run` command over loopback TLS, and drives the embedded Console in repository-pinned Chromium desktop and mobile contexts.
- Synthetic assertion material is attached only to the exact fixture origin; every external HTTP(S) request is blocked before dispatch.
- The lane disables screenshots and traces, captures output, scans the actual temporary artifact directory for private or credential-shaped material, and deletes it. Its public result contains only the stable pass envelope or a stable allowlisted failure stage.
- The exact manual keyboard and browser-version procedure remains in [Phase 3 browser evidence](../phase-3-browser-evidence.md#manual-keyboard-and-browser-version-check).

## Integrated child evidence

The checked [Phase 3 evidence definition](../../../tooling/phase-3-evidence.json) maps these merged children to stable requirements, executable proofs, acceptance commands, runtime-digested artifacts, and truthful limitations. Issue #58 creates the final runtime envelope only while testing an exact clean commit; `sourceCommit`, clean-tree facts, command results, artifact digests, and the evidence digest are not self-referential tracked-file fields.

| Delivered issue | Integrated PR and merge | Implementation evidence | Fresh child review |
|---|---|---|---|
| Issue 3.1 (#50) | [PR #59](https://github.com/vegastack/vegastack-labs/pull/59), `8bc4e69` | [evidence](https://github.com/vegastack/vegastack-labs/issues/50#issuecomment-5623084179) | [review](https://github.com/vegastack/vegastack-labs/issues/50#issuecomment-5623083205) |
| Issue 3.2 (#51) | [PR #60](https://github.com/vegastack/vegastack-labs/pull/60), `64225ae` | [evidence](https://github.com/vegastack/vegastack-labs/issues/51#issuecomment-5617148376) | [review](https://github.com/vegastack/vegastack-labs/issues/51#issuecomment-5630668657) |
| Issue 3.3 (#52) | [PR #61](https://github.com/vegastack/vegastack-labs/pull/61), `81c875f` | [evidence](https://github.com/vegastack/vegastack-labs/issues/52#issuecomment-5630855928) | [review](https://github.com/vegastack/vegastack-labs/issues/52#issuecomment-5617495894) |
| Issue 3.4 (#53) | [PR #63](https://github.com/vegastack/vegastack-labs/pull/63), `b142359` | [evidence](https://github.com/vegastack/vegastack-labs/issues/53#issuecomment-5633286695) | [review](https://github.com/vegastack/vegastack-labs/issues/53#issuecomment-5635121993) |
| Issue 3.5 (#54) | [PR #62](https://github.com/vegastack/vegastack-labs/pull/62), `b621b22` | [evidence](https://github.com/vegastack/vegastack-labs/issues/54#issuecomment-5631040710) | [review](https://github.com/vegastack/vegastack-labs/issues/54#issuecomment-5618249787) |
| Issue 3.6 (#55) | [PR #64](https://github.com/vegastack/vegastack-labs/pull/64), `9d053b2` | [evidence](https://github.com/vegastack/vegastack-labs/issues/55#issuecomment-5634067489) | [review](https://github.com/vegastack/vegastack-labs/issues/55#issuecomment-5635286645) |
| Issue 3.7 (#56) | [PR #65](https://github.com/vegastack/vegastack-labs/pull/65), `92dc2c0` | [evidence](https://github.com/vegastack/vegastack-labs/issues/56#issuecomment-5634424565) | [review](https://github.com/vegastack/vegastack-labs/issues/56#issuecomment-5634357108) |
| Issue 3.8 (#57) | [PR #84](https://github.com/vegastack/vegastack-labs/pull/84), `156cf49` | [evidence](https://github.com/vegastack/vegastack-labs/issues/57#issuecomment-5646322625) | [review](https://github.com/vegastack/vegastack-labs/issues/57#issuecomment-5646595446) |

## Fixture versus live limitations

The checked proofs use synthetic identities, grants, source records, failures, and loopback endpoints. They prove the software boundary without credentials or private operational state. They do not prove live Cloudflare Access or Google Workspace policy, provider ingress, a Labs host, actual source records, a release, a deployment, workload admission, or any infrastructure mutation. Those claims remain with their deployment gates and later development owners.

The supported Phase 3 browser lane is repository-pinned Chromium with desktop and mobile emulation. Firefox, WebKit, packaged distributions, and the wider supported operating-system matrix remain Phase 11. Automated keyboard, focus, mobile, theme, and accessibility assertions are repeatable evidence; the subjective focus-comfort check and installed-browser-version record remain an operator review item.

## Verification and exact-commit acceptance

The checked static definition names the required proof but does not claim a current result. Issue #58's exit verifier must start and finish at the requested 40-character commit with an empty working tree, validate every child and requirement binding, run the complete public check catalog plus `go test -race -count=1 ./...`, and digest the checked definition, generated registries/client, and embedded-asset manifest. Any missing, skipped, failed, quarantined, dirty, stale, contradictory, or unsanitized proof blocks the result.

The runtime envelope binds only sanitized facts to the exact tested commit. It is published with the final Issue #58 evidence and matching CI run, not written back into the commit whose identity it records. The operator explicitly accepted the Phase 3 result at `a0a07a425d6396703d8bec438634d9ec2c2ae980`; the checked evidence definition preserves that accepted commit, run, digest, date, and operator identity as historical facts.

## Phase 4 handoff

Phase 4 may consume the accepted generated read client, embedded same-origin Console, source-state semantics, session authorization, local recovery, and status-view patterns. It must add declarations, immutable plans, acknowledgement policy, execution state, and typed adapter ownership through its own approved briefs and plans; it cannot turn a read route or status screen into an alternate mutation path.

Phase 3 acceptance did not itself approve later work. In the same 12-09-2026 instruction, (omkarmohanta09) separately directed Phase 4 to proceed in go-dark mode. Phase 4 still follows its own approved issue plans, dependency waves, checks, fresh reviews, and merge evidence; release, deployment, provider access, credentials, and fleet operation remain separately gated.
