# VegaStack Labs gap-closure report

Date: 2026-08-25
Scope: documentation and architecture specification only

## Outcome

Every item in the prior 23-item gap report has been acted on without pretending that documentation performed physical inspection, provider configuration, real-host testing or platform implementation.

- All 23 mechanisms now have a stable gate ID, accountable owner, exact evidence, deterministic acceptance rule and phase/capability effect.
- 20 gates are design-closed and await only real site/provider/host evidence.
- `G-018` is design-closed and correctly remains a future platform implementation test.
- `G-022` is conditional for each later service.
- `G-023` keeps Chaabi Prod deferred outside v1 and does not block v1.
- The cross-cutting coverage register now has 53 rows: 52 documentation-complete and one truthful implementation-artifact partial (`C025`, future Codex/Claude/Hermes skill files and tests).

The canonical implementation/evidence contract is `docs/implementation-gates.md` in the corrected VegaStack Labs output set. The regenerated machine register contains all 23 gates and current document hashes.

## Gap-by-gap disposition

| Gate | Prior gap | Correction now fixed in the specification | What must still happen outside documentation |
|---|---|---|---|
| `G-001` | serial/node-map conflict | deterministic physical-evidence and two-person correction procedure | inspect labels/firmware, correct the Sheet through its human owner and attach sanitized evidence |
| `G-002` | incomplete discovery | OS-neutral discovery bundle, qualification fields and fixed acceptance checks | collect facts and burn-in results on each real host |
| `G-003` | unknown LAN facts | exact sanitized observation schema and collision/reservation checks | collect the deployed HX510/subnet/DHCP facts locally |
| `G-004` | switch not yet received/verified | receipt, firmware, port-map and export/restore procedure | inspect and test the real ES216G |
| `G-005` | Mesh beta acceptance vague | 30-day, 100-reconnect, route/MTU/loss/throughput acceptance rules | run the real pilot with current account/client versions |
| `G-006` | runner controller/log sink undecided | selected built-in VegaStack Labs CI adapter, fixed groups/labels, one-job cleanup and external log contract | enroll explicit repositories and run hostile-job/cancellation/log tests |
| `G-007` | 1Password topology undecided | selected purpose-separated vault topology and least-privilege machine access | create/identify real vaults/items/accounts and prove positive/negative access plus recovery custody |
| `G-008` | backup engine/topology undecided | selected restic v2 local/off-site topology, retention, checks, pruning authority and restore cadence | identify repositories/keys/R2 lock, validate capacity and restore on a clean host |
| `G-009` | UPS facts absent | fixed load/runtime/shutdown/restart acceptance thresholds | measure the installed UPS and protected outlets |
| `G-010` | hardware/runtime thresholds vague | numeric thermal, memory, swap, disk, link, WAN and role-specific limits | supply measurements from qualified hosts |
| `G-011` | independent alert route absent | exact recipient/channel evidence form and failure/recovery test | name recipients and test a route independent of home control and GitHub |
| `G-012` | Tunnel connectors undecided | default candidates `vsk-node-02` and `vsk-node-08`, single-failure and separation rules | qualify both or approve a planned substitute |
| `G-013` | LAN TLS marker undecided | default marker `vsk-node-02`, pinned certificate lifecycle and fail-safe remote fallback | record the real fingerprint/expiry/owner and test fallback |
| `G-014` | Coolify version/bootstrap open | pinned `v4.3.10`, tag commit and verified installer digest; auto-update disabled; same-version restore | revalidate immediately before use and prove install/backup/restore/rollback on the host |
| `G-015` | Harbor migration facts absent | exact source/target inventory, capacity, backup, restore and cutover evidence contract | collect the existing Harbor facts and qualify placement |
| `G-016` | provider ownership/IaC undecided | selected direct typed Cloudflare/Coolify adapters, SQLite desired state, explicit import and no Terraform/OpenTofu state | name real owners, issue scoped credentials and pass positive/negative canaries |
| `G-017` | signing/feed/retention open | selected Sigstore keyless bundles and active plus two prior verified releases | bind the real repository/workflow/OIDC identity and feed URLs |
| `G-018` | command/schema registry not implemented | one metadata-graph contract, stable errors/exits and cross-platform golden/compatibility gates | implement and test it in the future platform source repository |
| `G-019` | first deployment identities unknown | exact team/resource/environment/token/lease tests | provide each real project's identity map and permission evidence |
| `G-020` | macOS runner fallback/limits open | selected `macos-15-intel` compatible fallback plus protected manual Apple-silicon lane | recheck preview status and test measured Mac limits |
| `G-021` | iMac Hermes limits open | concurrency fixed at one with numeric memory/swap/disk/thermal rules | run the real single-session soak |
| `G-022` | later-service contract absent | complete per-service admission template and blocking rule | supply it only when that service is proposed |
| `G-023` | Chaabi scope | explicitly deferred, prohibited from v1 mutation and non-blocking for v1 | separately authorize post-v1 discovery if desired |

## Selected mechanisms that no longer remain architecture questions

- One platform distribution with one executable, `vsk-labs`; its service entry point is `vsk-labs server run` under the OS service manager.
- SQLite is the only authoritative operational database. D1 is at most an optional one-way sanitized stale-status projection, never control or synchronization.
- R2 is encrypted off-site disaster recovery through restic, not live platform state.
- GitHub is a replaceable VegaStack Labs source/CI/release provider. No VegaStack-owned GitHub App is required for core or the default v1 prebuilt-image deployment path.
- Coolify receives an admitted Harbor image digest through a team-scoped API credential. Its optional source picker/PR-comment App is not installed by default.
- Harbor contains built OCI images only.
- Cloudflare and Coolify use direct typed adapters; there is no second infrastructure-state database.
- Sigstore bundles bind artifact digest, OIDC issuer and repository/workflow identity; three complete release sets are retained.

## Verification result

Final corrected output set:

- 10 Markdown files, 2,524 lines;
- 573 local links, zero broken;
- zero malformed Markdown tables;
- 2 JSON examples, both valid;
- 141 command-reference lines, zero stale command forms;
- 23 defined gates and 117 gate references, zero dangling;
- 187 transcript question references, zero dangling;
- zero dangling official-source or normalized-decision IDs;
- 10 of 10 Markdown digest/byte/line records match the machine register;
- 192 ordered user-evidence rows, 59 indexed question fragments, 43 separately classified assistant recommendations/facts and 100 normalized decisions;
- 25 GitHub dependency cases, 15 platform-support rows, 9 implementation-readiness subsystems and 53 coverage rows.

New implementation-sensitive official links for restic, Coolify, Cloudflare's Go SDK, Sigstore, 1Password and GitHub runners were re-opened on 2026-08-25; all 12 returned successful primary-document responses. Coolify `v4.3.10` was additionally bound to tag commit `83f1a2e50374c27125671084b445b2599815f114` and installer SHA-256 `8ef02dce49339208f5abc247bff0277c73d04538d7a36dcfd21331e314e0f2cd`.

Machine-register SHA-256: `029ace33951bcfa96504efd331ba1983b5a74a154fc2e82a3a362c4349e3eae2`.

## Scope and residual blockers

No infrastructure was deployed; no provider, Google Sheet, repository, message or production state was changed. The remaining items above are activation evidence or future platform implementation, not undocumented architecture choices. Fabricating those facts would weaken the result: the platform must keep the affected phase/capability blocked until the typed evidence passes.

The only coverage row not marked complete is `C025`: actual Codex/Claude/Hermes skill artifacts must be created and acceptance-tested in the future implementation repository. The documentation contract itself is complete and `G-018` prevents a mutating release without generated command/schema compatibility.

## Effort checkpoint

This closure pass was estimated at 90 agent-minutes with a 180-minute aggregate 2× checkpoint and 39 minutes of suggested review. It completed well inside the checkpoint; the exact end timestamp and actual elapsed agent clock are recorded in the audit log. Network evidence checks took about 11 seconds and there were no CI, deployment or other external waits.
