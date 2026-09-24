# Project chronicle

Entries dated before 10-09-2026 are reconstructed from approved milestones, merged issues, and their recorded evidence at the operator's request. New entries follow the `dev-chronicle` format and are added newest first.

## 24-09-2026 — One fenced control history can become the sole recovered authority ([#108](https://github.com/vegastack/vegastack-labs/issues/108))

- **What:** An infrastructure administrator can now bind one current verified recovery point to an exact human-approved restore, stage it into an isolated candidate, reconcile its audit history, prove every former-controller boundary denied, and promote it under a new instance and adjacent recovery epoch. Normal mutation stays blocked until an exact no-op, independent checkpoint, current-epoch backup and renewed former-writer denial all pass.
- **Why:** Restoring SQLite alone could revive stale plans, credentials or a second writer; disaster recovery needed one fail-closed route that preserves the former database and proves the replacement is the only authority.
- **How it went:** Integration with the completed backup, audit and independent-witness contracts exposed a circular pre-plan fence requirement, so qualification was split into stable source admission before planning and an exact plan-bound denial witness during execution. The final implementation needed separate qualified checkpoint and backup capabilities for the canary; no live source or infrastructure operation was used.
- **Changed:** Exact restore plan, run, verify and status contracts · local last-good and optional off-site source admission · audit suffix recovery or named accepted loss · isolated candidate and crash-safe startup promotion · former-controller fencing · one-time epoch and instance transition · qualified canary and recovery-required fail-closed state · human recovery procedures.
- **Decisions:** none; a live restore still requires independently enrolled fence, custody, checkpoint and backup capabilities, and this work does not close `G-008` by itself.

— approved by (omkarmohanta09) · built by Codex · branch feat/108-fenced-authority-restore-final

## 24-09-2026 — Off-site recovery generations can be retired without widening deletion authority ([#118](https://github.com/vegastack/vegastack-labs/issues/118))

- **What:** An infrastructure administrator can stage one exact sealed-generation retirement that names its five owned retention rules and every object. The destructive path uses separate lock-admin and retention identities, records every effect, stops before object deletion after any ambiguous rule result, and settles only after every survivor passes full-read and isolated-restore proof.
- **Why:** Independent off-site generations avoid shared restic dependencies, but they also need a bounded way to subtract their exact lock rules and reclaim their exact objects without granting a routine writer or scheduler broad deletion authority.
- **How it went:** The work initially paused on a missing producer catalog in issue #114. After that contract landed with exact rule and object rows, the branch rebuilt cleanly on main; fake R2 races, lost responses, incomplete ownership and failed survivor proofs all failed closed.
- **Changed:** Exact off-site retirement selection · append-only migration and journals · full-rule-set reread and subtraction · listed-key-only deletion · survivor recovery proof · destructive central-run contract · sanitized status and human fallback.
- **Decisions:** none; production registration remains unavailable until current live `G-008` evidence qualifies exclusive one-owner administration, real provider semantics, distinct credentials and recovery.

— approved by (omkarmohanta09) · built by Codex · branch feat/118-offsite-retirement

## 23-09-2026 — The native credential lifecycle has one complete software path ([#135](https://github.com/vegastack/vegastack-labs/issues/135))

- **What:** One exact plan/run path now composes inert import, staging, real native consumer verification, bounded-overlap rotation, named revocation and independently evidenced clean-host recovery without exposing credential material.
- **Why:** The individual lifecycle, consumer, host-authority and recovery components needed a final integrated proof before the native Phase 5 credential work could be considered software-complete.
- **How it went:** The first Linux run correctly rejected Docker's overlay filesystem. A disposable Debian 13 VM with ext4 then exposed that a rotation successor must be staged before rotation; the corrected full lifecycle passed with positive and denied consumer evidence, restart proof, one-use custody and final status checks.
- **Changed:** Integrated Linux lifecycle acceptance · final Phase 2 source seal · current lifecycle and gate documentation · identical human fallback and recovery procedure.
- **Decisions:** none; `G-007` remains evidence-required, the optional 1Password resolver remains unregistered, and production recovery still requires independently enrolled sources, qualified live adapters and current replacement authority.

— approved by (omkarmohanta09) · built by Codex · branch feat/135-f8-transition-api
## 23-09-2026 — Local backup repositories have a separate short-lived custodian ([#163](https://github.com/vegastack/vegastack-labs/issues/163))

- **What:** Backup creation and verification now request one bounded custody mode of the existing `vsk-labs` executable through an exact root-owned systemd template. The persistent controller, repository owner and pinned restic process run as three distinct UIDs and exchange only authenticated typed messages.
- **Why:** The earlier same-process REST boundary constrained operations but still left the controller able to open repository paths directly, so writer and verifier separation did not establish independent repository custody.
- **How it went:** A disposable Debian 13 ext4 fixture ran the actual controller as UID 21164, custody as UID 21163 and official restic 0.19.1 as UID 21165. It proved two writes and restoration of the older point while direct repository opens and forged unit, argument, path, identity and nonce requests failed. Integration with the merged native-authority work added a live effective-policy check before each exact unit start. Independent review then found that rejected or swapped exchange paths could still reach a root path-based ownership return; red regressions for `/`, `/etc` and deterministic symlink swaps led to retained `openat2`/`fstat`/`fchown` handles across the complete restic operation.
- **Changed:** Root-owned custody profile and finite supervisor · authenticated lease/journal IPC · distinct-UID restic execution · brokered inventory/capacity/results · direct-path and forged-request denial · analyzer and reviewed-source seals · human failure procedure.
- **Decisions:** none; the fixture installs no live account, unit, policy or storage, and does not close `G-008` or authorize pruning, retention changes or recovery cutover.

— approved by (omkarmohanta09) · built by Codex · branch feat/163-local-repository-custody

## 23-09-2026 — Affected checks understand Linux-only Go packages ([#169](https://github.com/vegastack/vegastack-labs/issues/169))

- **What:** Focused Go vet and test compilation now apply the supported Linux target when a changed package has no macOS-buildable files; Linux hosts run its tests normally.
- **Why:** The first local affected check after the Phase 5 CI correction selected the right native-credential package but ran it under macOS, where every production file is excluded by build constraints.
- **How it went:** A red package-selection regression reproduced the exact failure. The planner now carries an explicit target policy for the Linux-only package, preserves ordinary portable commands, cross-compiles its test binary on other hosts, and runs the real tests on Linux.
- **Changed:** Target-aware affected Go vet · host-runnable target test proof · Linux-only fixture and regression test.
- **Decisions:** none; unrecognized target-only topology still fails closed, and final native Linux acceptance remains separate.

— approved by (omkarmohanta09) · built by Codex · branch fix/169-linux-go-target

## 23-09-2026 — Phase 5 stopped starting CI for every landing ([#165](https://github.com/vegastack/vegastack-labs/issues/165))

- **What:** Intermediate Phase 5 changes now prove their exact current-main diff locally and do not start GitHub CI when a pull request opens or merges. Public CI is manual-only for the final full acceptance and named native lanes.
- **Why:** Even an affected automatic lane repeated setup and check work at branch, pull-request, and post-merge stages; the operator required one focused proof per intermediate change and one broad proof at the end.
- **How it went:** A follow-up correction removed the automatic triggers and hosted PR job, strengthened the workflow guard, and taught the local ship gate to bind the affected command to the clean pushed head and current remote base before and after it runs.
- **Changed:** Dispatch-only Public CI · exact local affected ship proof · future-session policy and deterministic guards.
- **Decisions:** none; unsafe affected classifications still fail closed locally, and named native acceptance remains explicit.

— approved by (omkarmohanta09) · built by Codex · branch chore/165-phase5-manual-only-ci

## 23-09-2026 — Clean-host recovery can compare the exact staged draft ([#144](https://github.com/vegastack/vegastack-labs/issues/144))

- **What:** A dormant server adapter can consume one exact protected recovery handoff, bind it to current replacement authority and the existing staged ciphertext, then decrypt and compare the opened inode through the native systemd credential path.
- **Why:** The recovery contract previously accepted typed custody and fence digests without composing them with proof that a clean replacement opened the exact already-staged draft rather than freshly encrypting substitute material.
- **How it went:** Red-first tests caught the missing state-revision binding. Disposable Linux acceptance then proved old-host ciphertext denial, exact existing-draft comparison, one-use custody, and rejection of changed draft, plan, lease, epoch, revision, fence and replay inputs. The adapter is deliberately not selected by production operations.
- **Changed:** Exact current-authority seam · protected-source loader · state-revision binding · native existing-draft comparison · composed disposable acceptance · fail-closed Phase 2 source seal.
- **Decisions:** none; #108 must supply current replacement authority, and a real independently enrolled source plus qualified denial adapters remain required before production selection or live `G-007`/`G-008` evidence.

— approved by (omkarmohanta09) · built by Codex · branch feat/144-clean-host-recovery-proof

## 23-09-2026 — Phase 5 checks run at the scope that changed ([#165](https://github.com/vegastack/vegastack-labs/issues/165))

- **What:** Intermediate Phase 5 branches can prove an exact base and head with affected policy groups and changed Go package tests, while the final integration or acceptance candidate has one explicit complete lane.
- **Why:** An implicit full manual check followed by PR and post-merge checks repeatedly exercised unchanged packages and browser acceptance, delaying a serial delivery chain without adding distinct evidence.
- **How it went:** The existing affected planner already protected unknown and dependency changes. The correction added package targets, fail-closed Go topology changes, and explicit manual affected/full inputs while retaining repository-wide compilation and hosted integration checks.
- **Changed:** Changed-package Go tests and vet · exact-base manual CI mode · explicit final full mode · exact-head ship proof policy.
- **Decisions:** none; issue-specific native acceptance and the final Phase 5 full integration proof remain required.

— approved by (omkarmohanta09) · built by Codex · branch chore/165-phase5-fast-batch

## 22-09-2026 — A clean replacement can inspect a protected recovery handoff ([#159](https://github.com/vegastack/vegastack-labs/issues/159))

- **What:** The software can read one administrator-installed public witness and encrypted envelope from protected files, match them to a signed manifest and a closed direct-denial verifier registration, and offer a one-use digest-only handoff to a later exact-inode comparator.
- **Why:** The prior witness and collector fixtures proved protocol shape but offered no protected production source reader or qualified adapter registration seam for a clean replacement.
- **How it went:** Red-first file tests caught both replaced inodes and same-size in-place rewrites. The ordinary production verifier registry remains empty; disposable endpoint and process tests prove software behavior only, not independent site enrollment.
- **Changed:** Protected package reader · signed exact-boundary registration · fresh direct-denial recheck · one-use custody handoff · human failure procedure.
- **Decisions:** none; #144 still needs an externally enrolled source and real endpoint qualification, while #108 owns current replacement authority. No live `G-007` or `G-008` evidence is claimed.

— approved by (omkarmohanta09) · built by Codex · branch feat/159-recovery-source-admission

## 22-09-2026 — Failed browser acceptance now names a safe diagnostic ([#161](https://github.com/vegastack/vegastack-labs/issues/161))

- **What:** A failed Phase 3 browser run now reports the public test and assertion line when Playwright supplies a trusted location. It also reports the sanitizer's fixed failure code, including when both checks fail.
- **Why:** The old runner deleted the browser report and returned only a generic sanitizer stage, so the first failed CI attempt could not be diagnosed.
- **How it went:** A controlled browser and private-canary fixture reproduced that loss before the fix. The new report stays in a private temporary directory and is reduced to closed fields before deletion; malformed or absent reports fail closed.
- **Changed:** Bounded browser and sanitizer diagnostics · private report cleanup · focused failure-path tests. No automatic retry or acceptance bypass was added.
- **Decisions:** none.

— approved by (omkarmohanta09) · built by Codex · branch fix/161-phase3-bounded-diagnostics

## 22-09-2026 — Local backup points can prove they are restorable ([#117](https://github.com/vegastack/vegastack-labs/issues/117))

- **What:** A pending encrypted local point can now be checked against its exact retained objects, read fully by pinned restic, and restored into an isolated SQLite inspection before it becomes current local last-good. The backup status and exact human-approved run and verify commands expose the result without giving the CLI a separate mutation path.
- **Why:** Creating a point was not enough to know it could recover the control database or preserve a trustworthy earlier point when verification failed.
- **How it went:** Native restic tests exposed immutable-pack and restore details; independent review found that capacity had been checked at creation but not again before live qualification. A red-first low-capacity test caught a false promotion, and the final verifier now preserves prior last-good with a sanitized failed attempt. Signature, config and image dependency trust remains unavailable until an independently pinned source is built.
- **Changed:** Revisioned full-read and functional cadence · point-bound read lease · exact manifest and dependency evidence · isolated restore · append-only verification attempts and last-good compare-and-swap · sanitized status and generated client commands.
- **Decisions:** none; [#115](https://github.com/vegastack/vegastack-labs/issues/115) still owns safe retirement and successor-pack lineage, [#154](https://github.com/vegastack/vegastack-labs/issues/154) owns the missing trusted dependency sources, and no off-site or live recovery gate is claimed.

— approved by (omkarmohanta09) · built by Codex · branch feat/117-integration-140

## 22-09-2026 — A durable run keeps its SSE cursor across same-run reads ([#156](https://github.com/vegastack/vegastack-labs/issues/156))

- **What:** The Console keeps `Last-Event-ID` while the same run's GET response changes, resets it for a new run ID, and Phase 4 CI reports a bounded test title, failing assertion location, status and descriptor.
- **Why:** A normal read could replace the cached response, restart the watcher and clear the cursor; the acceptance wrapper then hid the browser failure behind a stage code.
- **How it went:** A focused browser test forced a revision change after the first event and failed with an empty second cursor before the fix. A separate two-run test failed with the old cursor when the reset was removed. CI then required regeneration of the embedded Console bundle and a new Phase 2 reviewed source seal for those measured production bytes. No live run or private operational state was involved.
- **Changed:** Run watcher lifecycle · regenerated embedded Console assets · measured Phase 2 reviewed wave · deterministic SSE regression fixture · sanitized Phase 4 and exit diagnostics.
- **Decisions:** none.

— approved by (omkarmohanta09) · built by Codex · branch fix/156-phase4-browser-reconnect
## 22-09-2026 — A custodian can collect a bounded recovery witness on disposable endpoints ([#153](https://github.com/vegastack/vegastack-labs/issues/153))

- **What:** The single `vsk-labs` executable has a finite custodian-side command that reads a protected admin pin and two private descriptors, probes every declared former-controller boundary, signs one exact attempt, and encrypts the held material to the replacement recipient.
- **Why:** The verification protocol alone could check a witness artifact but did not collect it from an independently held source; a status bit or a copied controller secret cannot prove former-controller denial.
- **How it went:** Red-first result-binding and collector tests preceded a typed CLI route. An independent review found the ordinary request could omit a whole boundary kind and that only in-process tests could reach an adapter. The collector now takes its exact set from the administrator-signed manifest; a disposable-only binary runs the finite command as a separate Linux custodian identity and a replacement process rechecks the signed bundle and encrypted handoff. The production registry remains empty. The CLI analyzer pins the exact custodian source; changed source bytes fail closed.
- **Changed:** Typed challenge/result binding · finite collection and re-probe · bounded descriptor custody · generated JSON command/data contract · exact-source CLI analyzer guard · disposable endpoint acceptance and manual handback.
- **Decisions:** none; the production adapter registry is empty, no custodian or key was enrolled, and #144/#108 still require real clean-host composition and current-authority proof before any recovery gate can move.

— approved by (omkarmohanta09) · built by Codex · branch feat/153-custodian-witness-collection
## 22-09-2026 — Native credential delivery can be proven on a disposable host ([#141](https://github.com/vegastack/vegastack-labs/issues/141))

- **What:** The local Linux verifier can compare a planned encrypted credential with the exact systemd unit, running process, loaded credential file and denied reader set. It returns one complete typed proof only after every positive and denied probe agrees; server composition still leaves the production gate unavailable.
- **Why:** The earlier lifecycle engine had no trustworthy evidence that the intended service actually received the host-key credential or that other local identities could not read it.
- **How it went:** The first real Debian VM run exposed a root-owned credential file and mount-namespace observation that the synthetic tests had missed. The verifier was corrected to prove access under the service identity and use a root-owned namespace receipt, then a two-unit, two-denied-identity matrix passed with negative mutations and cleanup.
- **Changed:** Typed systemd D-Bus observation · exact process and inode binding · direct denied-reader probes · qualified local server composition · disposable Linux acceptance fixture · sealed CLI and Phase 2 source checks. No production authority or live G-007 proof was registered.
- **Decisions:** none; the separately reviewed [#140](https://github.com/vegastack/vegastack-labs/issues/140) reader map and [#143](https://github.com/vegastack/vegastack-labs/issues/143) OS authority must land before this composition is integrated.

— approved by (omkarmohanta09) · built by Codex · branch feat/141-native-credential-lifecycle

## 22-09-2026 — Local credential checks can use narrowly delegated host authority ([#143](https://github.com/vegastack/vegastack-labs/issues/143))

- **What:** The unprivileged server can request an exact enrolled service restart and a metadata-only credential access probe through a root-owned policy. The policy checks the current unit, process identity and allowed arguments; a broader host grant or changed identity blocks the result.
- **Why:** Native credential verification needed a real way to restart the intended service and test the actual reader identities without making the server root or trusting a simulated observer.
- **How it went:** The disposable self-hosted runner lacked required tools and its positive probe refused, so a fresh mount-free Debian VM supplied the full systemd, polkit and sudo allow/deny test. The VM passed and was deleted. Hosted CI also caught a Linux witness test fixture whose fixed expiry passed during development but expired at 06:30 AM IST; its acceptance test now pins expiry relative to the test clock.
- **Changed:** Exact restart and probe policy · Ansible role · local authority adapter · synthetic acceptance fixture · fail-closed analyzer and Phase 2 guards · human test route.
- **Decisions:** none; [#141](https://github.com/vegastack/vegastack-labs/issues/141) still owns native lifecycle composition, and live G-007 evidence remains separate.

— approved by (omkarmohanta09) · built by Codex · branch feat/143-native-credential-authority

## 22-09-2026 — Independent recovery evidence has a bounded software handback ([#146](https://github.com/vegastack/vegastack-labs/issues/146))

- **What:** A separately pinned witness can sign one exact recovery attempt, carry typed old-identity denial results, encrypt protected material to an authenticated replacement recipient, and consume a durable one-use receipt outside restored SQLite.
- **Why:** A restored database or controller status cannot prove that the old controller lost mutation authority or that recovery material was independently held.
- **How it went:** Red-first protocol and failure tests were followed by isolated Linux process identities and real synthetic endpoint denial probes. The tests prove the software shape only; no administrator enrolled a live witness and no production provider adapter was qualified.
- **Changed:** Canonical signed witness artifact · admin-signed manifest and fixed protected pin · typed direct-denial transcripts · bounded encrypted custody stream · protected recipient source · durable clean-host receipt · synthetic Linux acceptance · human handback procedure.
- **Decisions:** none; #144 still owns exact opened-ciphertext-inode comparison, #108 owns current authority and boundary derivation, and production recovery remains unavailable.

— approved by (omkarmohanta09) · built by Codex · branch feat/146-witness-recovery-contract

## 22-09-2026 — Local backups can create pending encrypted recovery points ([#106](https://github.com/vegastack/vegastack-labs/issues/106))

- **What:** The server can accept an inert backup-policy draft, bind it to an exact approved run, capture a consistent local source, and create an encrypted restic point in a protected standard or critical repository. It records a pending point with an immutable creation manifest, expected object and dependency inventory, and a typed receipt; the point is not yet recovery-qualified.
- **Why:** The later local verification and off-site flows need a trustworthy, policy-bound point whose source, repository, retained objects and execution authority can be checked without treating creation as proof of recoverability.
- **How it went:** Earlier review exposed false provenance from unregistered IDs, a repository-format assumption and capacity overflow; those were closed before native acceptance. Real restic revealed that its retained config is encrypted, so the preflight now authenticates and decrypts it through the pinned child. Linux acceptance proved two sequential points and a valid version-1 repository denial. A stale exact-source analyzer digest briefly blocked CI and was resealed without widening subprocess authority.
- **Changed:** Inert policy draft and exact run binding · registered source and repository identities · guarded local REST object writer and pinned restic child · consistent capture and append-only pending manifest/receipt · protected storage and bounded output · real Linux composition and denial checks.
- **Decisions:** none; [#117](https://github.com/vegastack/vegastack-labs/issues/117) owns isolated restore, integrity cadence and local last-good qualification. Pending creation alone does not satisfy a recovery or live gate.

— approved by (omkarmohanta09) · built by Claude and Codex · branch feat/106-pending-local-recovery-points

## 22-09-2026 — Recovery evidence can be checked without claiming a recovered host ([#134](https://github.com/vegastack/vegastack-labs/issues/134))

- **What:** The server can validate recovery evidence against the exact inert draft, prior and current epoch, and custody/fence digests. A typed verifier contract checks current metadata before asking an independent source for proof; production recovery remains unavailable.
- **Why:** Clean-host recovery must preserve old history and reject stale authority without letting a copied key, a local database digest or a test fixture stand in for independent custody and fencing.
- **How it went:** Code inspection showed that fresh systemd encryption creates a new ciphertext, so its fingerprint cannot be compared with the already-sealed draft. The repository also had no production independent custody/fence source. The original runtime plan was split: this issue binds evidence and stays closed, while #144 owns native replacement-host decryption and independent proof.
- **Changed:** Strict recovery-evidence constructor and store validator · exact draft/current-epoch proof contract · redacted missing-proof behavior · human fallback procedure.
- **Decisions:** none; #144 must qualify the production source before #135 can claim complete native lifecycle software, and G-007 remains evidence-required.

— approved by (omkarmohanta09) · built by Codex · branch feat/134-credential-recovery-custody

## 22-09-2026 — Credential evidence is bound and failures stay redacted ([#133](https://github.com/vegastack/vegastack-labs/issues/133))

- **What:** Credential lifecycle verification now checks strict evidence digests and exact positive and denied consumer sets. A verifier panic, cancellation or uncertain external effect is reported through a redacted recovery-required boundary.
- **Why:** An activation must not become authoritative from malformed evidence, a partial consumer set or an error message that could contain secret material.
- **How it went:** The implementation narrowed the issue to evidence hardening and registered-consumer enumeration after finding that real native service delivery and optional provider version proof require separate OS and provider work. Linux CI fixture failures exposed stale assumptions about denied observations and the new migration count; those fixtures were corrected and independently re-reviewed.
- **Changed:** Strict SHA-256 and reason validation · append-only SQLite evidence hardening · exact registered-consumer enumeration · panic and uncertain-effect redaction · live Phase 2 evidence reseal. Production lifecycle and recovery verifiers remain unavailable; production cannot activate a credential.
- **Decisions:** none; native delivery is tracked in [#140](https://github.com/vegastack/vegastack-labs/issues/140) and [#141](https://github.com/vegastack/vegastack-labs/issues/141), optional provider proof in [#139](https://github.com/vegastack/vegastack-labs/issues/139), and recovery in [#134](https://github.com/vegastack/vegastack-labs/issues/134).

— approved by (omkarmohanta09) · built by Codex · branch feat/133-credential-consumer-verifiers

## 22-09-2026 — An unchanged PR head can reuse its complete CI proof ([#138](https://github.com/vegastack/vegastack-labs/issues/138))

- **What:** The development PR guard accepts one successful manual full Public CI run bound to the exact clean local and pushed branch commit as the complete pre-PR proof, without launching another complete check.
- **Why:** The old guard repeated an expensive complete run at PR creation even after the unchanged head had already passed the complete lane.
- **How it went:** The workflow reused the existing full-plan CI result and checked its run, job, step and structured output identities. An exact-head full CI run exposed an older future-session assertion and AGENTS.md wording that still required a separate local command; both were aligned with the selected one-proof rule. The guard change is installed locally on this workstation; the repository profile alone does not update another machine's skill installation.
- **Changed:** Opt-in exact-head CI proof guard · focused fail-closed tests · repository agent contract, workflow profile, mandate and policy assertion. PR and post-merge checks remain separate.
- **Decisions:** none; no product, deployment, or repository protection policy changed.

— approved by (omkarmohanta09) · built by Codex · branch chore/138-reuse-exact-head-ci

## 21-09-2026 — Credential changes can be drafted without activating them ([#132](https://github.com/vegastack/vegastack-labs/issues/132))

- **What:** Operators can draft staging, activation, rotation, named revocation and recovery through the same server API and CLI. Drafts carry only metadata and derive the exact stored fingerprint and import identity on the server. Status changes still require a current immutable plan and independent human acknowledgement.
- **Why:** The execution core needed a usable authoring surface without creating a second approval or secret-access path.
- **How it went:** Re-grounding exposed that an import's original revision and a later execution revision describe different moments; the operator approved sealing both identities separately. Native acceptance then found the five actions absent from the closed risk table, so the operator approved their existing control-plane classification and exact action-scoped apply grants. Old test fixtures silently skipped invalid resolver metadata; those fixtures now fail visibly.
- **Changed:** Five inert draft commands · strict action semantics · exact import-origin seal · named-version verification · rotation overlap that preserves the prior status · control-plane risk and real action-scoped apply authorization · matching human procedure. Production consumer and clean-host recovery verifiers remain unavailable and fail closed.
- **Decisions:** none; approved corrections use existing internal identity and risk classes without changing public requests, roles, migrations or live authority.

— approved by (omkarmohanta09) · built by Codex · branch feat/132-credential-lifecycle-surface

## 18-09-2026 — Credential status changes have a human-authorized execution core ([#125](https://github.com/vegastack/vegastack-labs/issues/125))

- **What:** The server has an append-only credential lifecycle execution core with exact plan, run, lease and consumed human acknowledgement checks. Lifecycle commands and real consumer/recovery verifiers remain deferred and production fails closed.
- **Why:** Credential activation and recovery need the same authorization engine as other infrastructure changes, without storing or returning secret values.
- **How it went:** Claude built and parked the core; Codex resumed its integration after audit history landed, preserving that migration and guard wave and moving the unmerged credential migration to the next slot. Earlier review fixed acknowledgement enforcement and real append/denial tests; the remaining findings belong to the approved follow-ups.
- **Changed:** Metadata-only lifecycle contracts · inert binding storage · exact central execution dispatch · transactional acknowledgement proof · append-only evidence · combined audit and credential plan guards.
- **Decisions:** none; API/CLI surfaces, version/draft fixes, real verifiers, clean-host recovery and full lifecycle acceptance remain in the follow-up issues. No live gate or deployment is admitted.

— approved by (omkarmohanta09) · built by Claude and Codex · branch feat/125-credential-lifecycle-recovery

## 16-09-2026 — Audit history can expose a fork without choosing one ([#107](https://github.com/vegastack/vegastack-labs/issues/107))

- **What:** Every new canonical audit event now receives a serialized instance/epoch-bound hash-chain link in the same SQLite transaction. Operators can inspect sanitized checkpoints and verify local history against a separately read signed checkpoint; proven disagreement leaves reads available but blocks mutation in audit-incident mode.
- **Why:** Append-only rows alone cannot reveal privileged edits, restored lost suffixes or a returning old controller, and recovery must not silently bless whichever history is local.
- **How it went:** The preserved red-first branch rebased cleanly after its credential dependency landed. Linux ext4 checks caught one verification query typo and contract tests caught a v1.1 response-version mismatch; both were corrected without using a live signer, store, credential or host.
- **Changed:** Same-transaction audit chain and pre-anchor backfill · signed checkpoint lifecycle and separate writer/reader authority · local/independent verification and recovery-epoch genesis binding · sanitized API and CLI inspection · human recovery guidance.
- **Decisions:** none; production signer/export composition, retention proof and live independent-anchor evidence remain separately gated.

— approved by (omkarmohanta09) · built by Codex · branch feat/5.6-audit-history

## 16-09-2026 — Local credential material can be captured without becoming live authority ([#124](https://github.com/vegastack/vegastack-labs/issues/124))

- **What:** An authorized local OS-peer operator can now send a small credential value through standard input or an already-open descriptor. The server encrypts it with the qualified native host-key path, keeps only an inert append-only draft and sanitized metadata, and classifies exact retries or interrupted promotion without making the material resolvable.
- **Why:** Phase 5 needs a safe bridge from locally supplied private bytes to the later human-controlled credential lifecycle, while preserving the dormant boundary created in the foundation issue.
- **How it went:** The merged foundation lacked one helper the conditional plan expected, so this branch added that narrow ownership helper and recorded the ruling. The complete check also exposed exact read-API, CLI, server, generated-contract and historical guards that needed a separate narrowly sealed import wave; disposable Linux and a fresh systemd host key proved encryption, restart and recovery without any live credential, account, host or fleet target.
- **Changed:** Local stdin/open-descriptor import · generated binary-only local API contract · no-replace host-key encryption · append-only draft metadata · exact retry and conservative orphan recovery · CLI/API/process redaction · dormancy and historical source guards · human recovery limits.
- **Decisions:** none; activation, rotation, revocation, reconciliation and lifecycle recovery remain in dependent issue [#125](https://github.com/vegastack/vegastack-labs/issues/125), and import does not close G-007.

— approved by (omkarmohanta09) · built by Codex · branch feat/124-inert-local-encrypted-credential-draft

## 16-09-2026 — Credential handling has a fail-closed foundation without a live secret path ([#123](https://github.com/vegastack/vegastack-labs/issues/123))

- **What:** The server now has provider-neutral credential metadata, append-only exact-plan bindings, a Debian host-key encrypted primitive, an optional exact-ID 1Password resolver seam, and just-in-time run checks. Production still cannot import, activate, resolve, or execute a live secret-bearing step because no resolver or live proof verifier is registered.
- **Why:** Phase 5 needs a reviewed security boundary for later credential lifecycle work without letting partial software, fixtures, or provider SDK availability become live authority.
- **How it went:** The preserved implementation checkpoint replayed cleanly, while the completion wave added a second exact historical source seal and explicit dormancy proof. Disposable Linux verified the systemd host-key roundtrip and clean-host re-encryption; no live account, token, host key, vault, provider or fleet target was used.
- **Changed:** Versioned opaque credential contracts · append-only metadata and step bindings · host-key encrypted Debian primitive · pinned exact-ID 1Password SDK seam · fail-closed run ordering and memory cleanup · dormant production/source guards · explicit `G-007` limits.
- **Decisions:** none; plaintext import and the human-authorized activation, rotation, revocation and recovery lifecycle remain in dependent issues.

— approved by (omkarmohanta09) · built by Codex · branch feat/123-dormant-credential-foundation

## 16-09-2026 — Operators can see why gates remain blocked without closing them ([#104](https://github.com/vegastack/vegastack-labs/issues/104))

- **What:** The server now derives gate applicability and blocking reasons from generated definitions, an applied profile/policy binding, and append-only evidence; the CLI and read-only Console show the same versioned result. Operators can author bounded evidence and profile candidates, but these stay inert until an exact current human-approved plan runs.
- **Why:** Phase 5 needs gate readiness that comes from current, recovery-epoch-bound proof rather than a document, an agent assertion, or a privileged close shortcut.
- **How it went:** The first complete check found historical Phase 2, read-API, CLI, generated-contract, static Console, and Phase 3 proof guards that still described earlier behavior. Each was narrowed to the exact new gate wave while the old baseline stayed intact. The protected attachment store remains dormant and live proof stays blocked until a separately reviewed subject resolver, collector, and verifier exist.
- **Changed:** Generated gate evidence bindings and applicability · inert profile/evidence drafts · exact human-only plan effects · append-only SQLite records · typed gate API/CLI · read-only Console blockers · recovery and denial tests.
- **Decisions:** none; this is development software, not live gate acceptance or deployment authority.

— approved by (omkarmohanta09) · built by Codex · branch feat/5.3-derived-gate-readiness

## 15-09-2026 — Phase 5 safety contracts are generated without live authority ([#102](https://github.com/vegastack/vegastack-labs/issues/102))

- **What:** Evidence, credential references, backups, audit checkpoints, restore verification, and scheduled jobs now have versioned schemas and generated Go, CLI, and browser contract surfaces. The routes and commands remain planned; this work grants no runtime apply authority.
- **Why:** Later Phase 5 owners need one typed boundary that refuses fixture promotion, ambiguous restore identity, and scheduled-job widening before implementing provider or control-plane behavior.
- **How it went:** Focused tests exposed cross-field constraints that schemas alone could not safely imply, so generated validators and drift guards were added. The historical Phase 2 source seal requires a fresh review and deliberate reseal after these contract changes.
- **Changed:** Phase 5 metadata and transitions · generated contract artifacts and validators · hostile fixture tests · browser client types · documentation of the contract/runtime boundary.
- **Decisions:** none; deployment gates and live authority remain unchanged.

— approved by (omkarmohanta09) · built by Codex · branch feat/5.1-phase5-contracts

## 14-09-2026 — Phase 4 is proven and accepted at one exact commit ([#67](https://github.com/vegastack/vegastack-labs/issues/67))

- **What:** Inert declarations, immutable plans, current authorization, Slack human acknowledgement, durable central and external execution, and matching CLI/Console change workflows now form one accepted Phase 4 result. A strict exit command binds every requirement and child result to one exact clean `main` commit.
- **Why:** The complete change path needed one proof that safe planning, approval, execution, interruption handling, and privacy boundaries still work together before later phases build on it.
- **How it went:** Focused implementation and hostile tests found Linux socket limits, durable-recovery edges, browser reload and dropped-response gaps, external-worker ordering and lease faults, stale evidence links, and proof-binding errors. Each owner issue was corrected and independently reviewed. The merged result then passed twice on unchanged Debian `main` with the same digest before the operator accepted it.
- **Changed:** Nine integrated Phase 4 child outcomes · closed 34-scenario hostile suite · exact child review/merge/run bindings · Linux and trusted-main exit guard · two matching Debian proofs · explicit operator acceptance record.
- **Decisions:** none; the acceptance covers credential-free fixture software at `6bbb81231644c84ef34c8633e9de5671a4186180`, not Phase 5, a release, deployment, provider access, credentials, onboarding, or live fleet operation.

— approved by (omkarmohanta09) · built by Codex · branch chore/4.10-phase4-acceptance

## 13-09-2026 — One hostile suite now guards the complete Phase 4 change path ([#80](https://github.com/vegastack/vegastack-labs/issues/80))

- **What:** One command now checks the built executable, authoritative SQLite service, generated CLI and browser clients, Slack fixture, typed local adapter, and external executor simulator together. It covers exact success, denial, interruption, restart, partial recovery, replay, lease loss, client reconnect, and private-data exclusion with a closed list of required scenarios.
- **Why:** The individual Phase 4 features needed one deterministic guard that fails when their safety boundaries stop working together.
- **How it went:** Most hostile cases already had strong focused tests, so the work composed them under one strict scenario manifest and added only the missing real-boundary acceptance joins. The Console dependency had already created the Phase 4 command and CI catalog entry; this issue safely expanded those existing hooks instead of adding a second lane.
- **Changed:** Closed 34-scenario acceptance definition · exact built-Linux and real-SQLite join · authorization and executor theft checks · browser plan/privacy proof · race, generated, CLI, static, Chromium, and artifact-sanitizer orchestration · deterministic commit-and-scenario result.
- **Decisions:** none; all adapters, identities, providers, hosts, credentials, releases, deployment, and fleet access remain fixtures or separately gated.

— approved by (omkarmohanta09) · built by Codex · branch chore/4.9-phase4-acceptance

## 13-09-2026 — Operators can complete a safe change from the Console ([#79](https://github.com/vegastack/vegastack-labs/issues/79))

- **What:** The embedded Console now has one Changes workspace for saving a declaration, preparing and reviewing its exact plan, requesting Slack approval, applying it, and recovering an interrupted run. Approval and run views show only the safe status needed for the next operator action.
- **Why:** Browser operators needed the same declaration, plan, approval, and durable-run workflow already owned by the Go server and CLI, without creating a second policy engine or exposing private proof material.
- **How it went:** Real Linux, SQLite, TLS, and Chromium testing exposed that an empty declaration extension list became JSON `null` during plan commit and that a protected plain-404 route needed a denial-specific probe instead of the normal JSON response helper. Independent review then found that approval observation did not survive reload, a dropped apply response lost the durable run handle, terminal event streams stayed open, and the accessibility proof covered only the final state. The correction persists only safe plan/idempotency handles, resolves a committed run through one server-owned read without repeating apply, restores approval observation and keyboard focus after reload/revision changes, closes terminal streams, and exercises every named state across both themes and desktop/mobile 200% reflow. The complete dropped-response resume/cancel loop passed over real TLS with the race detector on native Linux/arm64.
- **Changed:** Changes workspace · generated declaration/plan/run client · server-owned Slack approval request and safe status projection · browser-safe run projection · exact remote mutation allowlist · inspect-only run resolution after transport loss · reload-safe approval/run state · interrupted-run recovery dialog · complete state/accessibility/theme/reflow matrix · static, Chromium, and native Linux acceptance proof.
- **Decisions:** none; policy, acknowledgement proof, human and authority identity, nonce, authorization correlation, executor binding, claims, receipts, SQLite, and provider access remain server-only.

— approved by (omkarmohanta09) · built by Codex · branch feat/4.8-console-change-workflow

## 13-09-2026 — Operators can plan, apply, and recover runs from one CLI ([#78](https://github.com/vegastack/vegastack-labs/issues/78))

- **What:** `vsk-labs` now creates an inert immutable plan from one exact declaration revision, applies one named plan, and inspects, cancels, or resumes one durable run through the server API. Human output and raw JSON carry the same plan digest, targets, approval requirement, run progress, verification, rollback, and next safe action without prompting.
- **Why:** Operators and agents needed the Phase 4 safety engine through the same stable executable without opening SQLite, contacting providers directly, replacing Slack acknowledgement, or guessing whether a disconnected apply failed.
- **How it went:** The original two-field plan command lacked the server-owned observation facts needed for an exact plan request, and a disconnected submit did not yet know which run to inspect. A narrow authorized preparation read and one shared deterministic run-ID helper closed those gaps without adding a client state machine. Independent review then caught client-inferred recovery advice, incomplete unknown-outcome guidance and process coverage, and a source-regex network guard. The correction moved run presentation into a generated server-owned view, added typed inspect-only uncertainty, exercised the complete protected-socket outcome matrix, and replaced the regex with typed Go dependency analysis plus a sealed, value-only HTTP-over-Unix transport. Further adversarial review closed dependency-laundering variants by isolating all local networking in a digest-sealed transport, sealing the executable composition root, and rejecting every network-capable dependency outside that reviewed boundary. The final remote-path review found that raw HTTP over SSH did not implement the accepted framing contract, valid group-protected local server profiles were rejected too early, and ambient SSH/host-key state was not sealed. The correction added strict `vegastack-labs.api-ssh` `1.0.0` frames, exact request correlation, measured length/digest checks, a generated allowlisted forced-command entry, server-owned principal/device/epoch verification, protected profile and known-host inspection, and a fixed noninteractive SSH invocation. Focused race tests and Debian built-process fixtures proved exact request bytes, hostile path handling, one submit, one recovery read, no resubmission, and framed local/remote parity.
- **Changed:** Generated available plan/apply/run commands · exact plan-preparation read · server-owned durable run presentation · thin Unix-socket and constrained-SSH client methods · deterministic durable run IDs · typed disconnect inspection without retry · human/JSON parity · stable server error exits · protected-socket outcome matrix · versioned API-over-SSH framing and forced-command allowlist · protected host trust and deterministic SSH arguments · sealed value-only transports · complete CLI dependency-closure denial · portable target builds and typed CLI boundary guards.
- **Decisions:** none; plan creation still revalidates current state, the server remains the sole policy and run-state owner, and no provider, credential, executor, fleet, shell, arbitrary network, or direct-database path was added.

— approved by (omkarmohanta09) · built by Codex · branch feat/4.7-cli-plan-apply-runs

## 13-09-2026 — External workers receive one short, exact work lease ([#69](https://github.com/vegastack/vegastack-labs/issues/69))

- **What:** A policy-bound external worker can claim only the server-selected next operation of one current durable run, renew that exact lease every 20 seconds within its fixed 60-second lifetime, and return an untrusted receipt for independent adapter verification. SQLite records the lease, rotating nonce, receipt, verification, and run result before the API reports success.
- **Why:** Long-running or isolated work must cross a process boundary without letting the worker choose broader targets, retain stale permission, hide a disconnect, or turn its own success claim into proof.
- **How it went:** Deterministic fixtures first proved binding, renewal, denial, expiry, replay, receipt, and crash behavior without any provider or credential. The complete check caught two remote-route guards that needed the generated executor endpoints and preserved acknowledgement exclusions. A fresh risky review then found that claim selection could skip ordered work, current recovery epoch was not checked inside the claim transaction, reconciliation could stop after one transient store failure, the simulator did not prove the real HTTP/SQLite/restart boundary, and authorization denials lacked durable evidence. The correction added single-item ordered admission, transactional epoch checks, retrying and rediscoverable reconciliation, fingerprint-only denial audit, explicit policy identity resolution, and a Linux real-API/SQLite loss-and-restart matrix.
- **Changed:** Migration 0010 external lease/receipt authority · exact claim/renew/receipt APIs · 60-second non-extendable leases and 20-second renewal rotation · one-work-item ordered admission · current plan/policy/recovery checks · independent receipt verification · cancellation and no-blind-reassignment behavior · restart-safe loss reconciliation · sanitized denial audit · deterministic offline simulator and Linux integration fixture.
- **Decisions:** none; the direct v1 external binding uses an explicitly authorized policy principal whose ID equals the declared executor ID, and production registers no external adapter, so no real provider, credential, executor, or fleet authority was introduced.

— approved by (omkarmohanta09) · built by Codex · branch feat/4.6-external-executor-leases

## 13-09-2026 — Approved plans now run through durable, interruption-safe steps ([#74](https://github.com/vegastack/vegastack-labs/issues/74))

- **What:** One current authorized immutable plan can create a durable run, execute its ordered typed steps through a narrow adapter boundary, record intent and receipts around every effect, verify the result independently, and report succeeded, failed, partial, interrupted, or cancelled truthfully. Exact retries reuse the original run; conflicting targets are protected by short leases; restart and resume never silently repeat an ambiguous effect.
- **Why:** Plans and acknowledgements are safe only if the server can carry them through real execution without widening targets, losing progress on disconnect, treating a receipt as proof, or guessing after a crash.
- **How it went:** Failure injection exercised every durable boundary, cancellation point, lease conflict, verification failure, partial result, and safe resume. Integration waited for Slack acknowledgement migration 0008, then registered run migration 0009 directly after it and wired the same durable proof service into execution. Preliminary review caught three fail-closed edges: later failures must preserve earlier changes, restart must not ignore lease-release errors, and a failed durable reload must stop before any adapter call. The first fresh risky review then found six deeper gaps: acknowledgement consumption was not recoverably bound to run creation, terminal API replay could change meaning, lease expiry was metadata-only, the crash matrix used memory instead of reopened SQLite, cancel/resume keys were not durable, and run reads authorized no exact resource. The correction added durable unique proof ownership, persistent mutation results, deadline enforcement, exact-ID authorization, and a real Debian/ext4 close/reopen matrix across all nine boundaries. Re-review caught one final post-commit success response edge; after fixing it, spec, standards, and security review were clean. The complete check then caught and refreshed the generator-owned embedded Console assets changed by the generated API client.
- **Changed:** Run/step/lease/receipt persistence and 30/180-day retention · typed provider-neutral adapter registry · state-before/effect/receipt/verification engine · exact submit/cancel/resume idempotency · recoverable acknowledgement-to-run ownership · enforced lease deadline · safe cancellation/interruption/restart/resume · current plan/policy/acknowledgement/fact prechecks · exact run-read authorization · truthful generated run APIs · audit/outbox/SSE publication · production-inaccessible fake adapter.
- **Decisions:** none; `vsk-labs server run` remains the only orchestrator, SQLite remains authoritative, no provider adapter or fleet access was added, and ambiguous effects require recovery instead of automatic retry.

— approved by (omkarmohanta09) · built by Codex · branch feat/4.5-durable-plan-runs

## 13-09-2026 — Slack can carry one exact human plan decision without becoming an authority ([#77](https://github.com/vegastack/vegastack-labs/issues/77))

- **What:** An authorized operator can request a short-lived Slack card for one immutable plan, and the server can accept exactly one matching approve or reject action through a server-owned Socket Mode connection. The resulting provider-neutral proof is durable, terminal, single-use, and rechecked against current plan and human authority immediately before execution.
- **Why:** Infrastructure changes need a convenient human acknowledgement path without trusting Slack as policy, allowing an agent to approve its own work, or letting stale, replayed, widened, or mismatched interactions authorize execution.
- **How it went:** Deterministic local HTTP/WebSocket fixtures drove reconnect, refresh, outage, malformed action, redaction, and duplicate-delivery behavior without live Slack or credentials. The first independent review found that the production server had not composed the adapter, execution did not repeat the human authorization check, envelopes were acknowledged before durable decisions, denial auditing was incomplete, and a test-host URL exception was compiled into production. The correction added strict optional profile composition with protected native credential references, a local status read, decision-or-denial durability before Slack acknowledgement, complete execution and adapter denial evidence, and production-only Slack URL validation. Focused race tests and a Debian ext4 fixture proved the SQLite and Linux credential boundaries.
- **Changed:** Generated local request/status endpoints · migration 0008 acknowledgement authority · exact plan/workspace/user/action/digest/nonce/revision/expiry/epoch binding · terminal approve/reject/expire states · consume-once execution proof · Slack Socket Mode reconnect and refresh lifecycle · systemd native credential resolution · sanitized denial audit.
- **Decisions:** none; Slack remains an optional typed adapter, local SQLite and current authorization remain authoritative, and absence or failure of Slack cannot disable local core operation or grant execution authority.

— approved by (omkarmohanta09) · built by Codex · branch feat/4.4-slack-acknowledgement

## 13-09-2026 — Disposable Debian checks are faster and deterministic ([#81](https://github.com/vegastack/vegastack-labs/issues/81))

- **What:** Trusted checks on `vsk-node-01` and `vsk-node-06` install the pinned public dependencies directly instead of asking `actions/setup-node` to restore the remote pnpm store. Hosted pull requests keep their cache. The production remote-bind integration test now serves its own temporary signing keys instead of contacting a public Cloudflare URL.
- **Why:** Restoring the 157 MB remote cache took about six minutes on the disposable machines, while a clean cache-free dependency install took seconds and produced the same complete check result. The external test request could also delay server startup long enough to make an unrelated listener assertion fail.
- **How it went:** Two main attempts exposed the slow restore. Cache-free diagnostics passed the complete lane, then visible parallel runs identified the intermittent failure as `TestProductionOperationsRemoteBindFailureKeepsRealStoreAPIAvailable`. Its identity refresh still depended on the public network; a local TLS key fixture and injected production-equivalent HTTP client made 20 consecutive Linux race runs pass.
- **Changed:** Trusted `setup-node` cache policy · workflow verifier and regression · deterministic remote-identity integration fixture.
- **Decisions:** none; runner allowlists, credentials, checks, versions, hosted pull-request behavior, and infrastructure authority are unchanged.

— approved by (omkarmohanta09) · built by Codex · branches chore/81-disable-trusted-pnpm-cache and chore/81-deterministic-remote-test

## 13-09-2026 — Every Phase 4 change now passes one current authorization policy ([#71](https://github.com/vegastack/vegastack-labs/issues/71))

- **What:** The server now resolves current resource-scoped author, acknowledge, and execute authority from SQLite, derives plan risk from a closed provider-neutral operation table, and permits exactly one human or narrowly preauthorized branch. Declaration and plan writes are checked before their body is read and again for the exact declaration immediately before the service call; future acknowledgement and execution endpoints share the same preflight.
- **Why:** Immutable plans are safe to act on only when stale, revoked, widened, mixed-branch, recovery-mismatched, and self-authorizing requests all fail closed against current policy.
- **How it went:** Work paused cleanly while the declaration/plan foundation landed, then migration 0007 was registered after 0006 without weakening the contiguous catalog. The full check caught an authorization field name that resembled a handwritten command registry, and an adversarial pass tightened malformed grant handling so an empty target or invalid role/branch pair can never become an allowed scope.
- **Changed:** Effective principal and grant snapshots · inert desired grants · append-only sanitized authorization decisions · closed risk and role matrix · exact branch and revision binding · pre-body and pre-service API checks · stable denial responses · Linux restart/race proof.
- **Decisions:** none; no default effective grant, live identity/provider record, policy service, permission cache, execution path, or infrastructure authority was introduced.

— approved by (omkarmohanta09) · built by Codex · branch feat/4.3-authorization-risk-policy

## 13-09-2026 — Desired changes now become one stable plan without touching infrastructure ([#76](https://github.com/vegastack/vegastack-labs/issues/76))

- **What:** Authorized local operators can append inert declaration revisions and turn one exact revision into an immutable 30-minute plan. The readable plan and canonical JSON bind the same operations, facts, targets, revisions, recovery epoch, versions, expiry, and digests, while exact retries return the original result.
- **Why:** Later acknowledgement and execution must authorize stable bytes, not a mutable draft or a plan reconstructed differently by each client.
- **How it went:** The existing single-writer and audit-intent transaction made the persistence boundary direct; final review tightened stored authority to exact contracts and ensured planning appends the committed desired declaration and immutable plan in the same rollback-safe transaction. Reason/readable digests, retry-before-stale checks, and the distinction between operation sequence and set-like normalization keep the bytes stable. Policy classification remains deliberately conservative until the parallel authorization work is integrated.
- **Changed:** Append-only draft and committed declaration storage · immutable-plan storage · atomic committed-revision/plan transactions · deterministic readable and JSON forms · 30-minute expiry and drift checks · strict local mutation APIs · generated declaration/plan reads · restart, rollback, replay, conflict, exact-authority, and authorization-before-parse tests.
- **Decisions:** none; provider-neutral operation names pass through unchanged, and current server wiring classifies every plan as destructive/human until Issue #71 supplies the approved policy result.

— approved by (omkarmohanta09) · built by Codex · branch feat/4.2-declarations-immutable-plans

## 12-09-2026 — Phase 4 now shares one safe contract before any engine runs ([#66](https://github.com/vegastack/vegastack-labs/issues/66))

- **What:** Declarations, immutable plans, authorization decisions, human acknowledgements, runs, steps, short external-worker leases, and receipts now come from one provider-neutral metadata graph. The same closed names, states, bindings, timing rules, Go types, browser types, schemas, and read-only compatibility rules are generated together.
- **Why:** Every later Phase 4 engine needs an identical contract that cannot drift between CLI, server, browser, and external executors or silently widen approved work.
- **How it went:** The implementation stayed inside the existing generator, but completeness review caught loose exact-version handling, a missing plan-to-lease link, shape-only missing-binding proof, and secret-shaped nested additions. Those were fixed and re-tested; a stale plan word was corrected so complete contracts do not falsely claim runnable engines, and the full check caught the generated Console embed that needed refreshing after its browser client changed.
- **Changed:** Closed declaration/plan/authorization/acknowledgement/run/lease/receipt schemas · exact 30-minute plan and 60/20-second lease timing · generated Go/browser validators · plan→run step→lease→receipt widening denial · safe same-major read compatibility · generated API/CLI reference and drift proof.
- **Decisions:** none; `plan`, `apply`, and all Phase 4 endpoints remain `planned` until Issues #74, #76, and #78 implement and activate their tested engines.

— approved by (omkarmohanta09) · built by Codex · branch feat/4.1-phase4-contracts

## 12-09-2026 — Phase 3 is proven and accepted at one exact commit ([#58](https://github.com/vegastack/vegastack-labs/issues/58))

- **What:** The embedded read-only Console, generated browser client, truthful source health, secure sessions, status screens, local recovery, and real-server Chromium boundary now form one accepted Phase 3 result. A strict exit command maps every requirement and child issue to exact evidence and accepts only a clean named commit.
- **Why:** Green child issues were not enough to prove the whole phase or bind the operator's decision to one immutable result.
- **How it went:** The full run first exposed a package argument mistake, a fake-secret test canary caught by repository safety, and two stale historical-pointer assertions. Independent review then found loose child-evidence bindings and noisy package output; all five defects were fixed, the corrected detached candidate passed twice with the same digest, PR CI passed, and the merged Debian run produced the final accepted proof.
- **Changed:** Exact child issue/PR/merge/evidence bindings · silent stable exit output · complete catalog plus Go race proof · deterministic artifact digest · guarded merged-main acceptance · explicit Phase 3 acceptance record.
- **Decisions:** none; the acceptance covers credential-free fixture software at `a0a07a425d6396703d8bec438634d9ec2c2ae980`, not release, deployment, provider access, fleet readiness, or live infrastructure.

— approved by (omkarmohanta09) · built by Codex · branch chore/3.9-phase-3-acceptance-record

## 12-09-2026 — Phase 3 gained one real-server browser acceptance boundary ([#57](https://github.com/vegastack/vegastack-labs/issues/57))

- **What:** A credential-free Chromium probe now exercises the embedded Console through the built `vsk-labs server run` executable over loopback TLS, protected browser sessions, generated reads, signing-key outage and recovery, and the same executable's local status command. A root guard rejects unsafe evidence and documents the remaining manual keyboard checks.
- **Why:** Static component tests alone cannot prove the real executable, TLS, cookie, origin, session, and local-recovery boundaries that make the read-only Console safe.
- **How it went:** Disposable-Debian runs exposed unsafe runner temporary storage, Linux Unix-socket path limits, cross-origin script authentication, and several assumptions that browser mocks did not reveal. Each failure was corrected at the boundary and the exact branch head was rerun twice before independent review.
- **Changed:** Built-executable TLS Chromium fixture · session and outage adversarial checks · same-origin credential containment · evidence sanitizer · `check:phase-3` · repeatable manual accessibility notes.
- **Decisions:** none; Chromium desktop/mobile is the Phase 3 development lane, while the broader browser, OS, and packaged-distribution matrix remains Phase 11.

— approved by (omkarmohanta09) · built by Codex · branch chore/57-phase3-browser-acceptance

## 11-09-2026 — Development checks stay thorough without repeating the slowest lane ([#81](https://github.com/vegastack/vegastack-labs/issues/81))

- **What:** Development now has one shared check catalog and a deterministic Git-diff selector. Local work runs only affected checks, while one complete clean-head check remains required before a pull request. Pull requests use fresh GitHub-hosted Ubuntu machines; trusted `main` and manual checks may temporarily use disposable Debian `vsk-node-01` or `vsk-node-06`. Chromium installs only when browser-facing code changed.
- **Why:** Repeating the complete Go, web build, and browser suite after every small edit was slowing Phase 3 without adding proof at each intermediate state.
- **How it went:** A concurrent planning session created a newer equivalent Plan v1 while implementation was starting; the branch switched to that current plan, kept the safe work already committed, and recorded the reconciliation instead of hiding it. The first pull-request run then caught a pnpm argument-separator mismatch; both workflow paths and their exact-command guard were corrected on the same branch.
- **Changed:** Shared ordered check groups · fail-closed changed-path plan · hosted pull-request CI · hostname-gated disposable Debian CI for trusted events · conditional Chromium CI · one-full-run-before-PR rule in every agent mandate.
- **Decisions:** none; the selector and its fixture matrix enforce the approved workflow directly.

— approved by (omkarmohanta09) · built by Codex · branch chore/81-change-aware-ci

## 11-09-2026 — Four more Console areas show honest status without pretending records exist ([#56](https://github.com/vegastack/vegastack-labs/issues/56))

- **What:** Operators can open People, Services, Backups, and Providers in the embedded Console and see the safe capability state and its freshness. Each screen says plainly that detailed records and actions are not implemented yet.
- **Why:** These areas need a useful Phase 3 destination without inventing domain APIs, fake records, recovery points, provider success, or new authority before their owning phases.
- **How it went:** The shared source-status boundary from the preceding Console work kept the implementation small; the important work was proving every failure state and that private backing records never enter browser responses, storage, URLs, or logs.
- **Changed:** Four fixed read-only routes · exact server-side source filters · shared current/stale/unknown/unavailable/failed/denied/error rendering · keyboard, mobile, privacy, and static-build evidence.
- **Decisions:** none; this implements the operator-selected status-only scope and keeps real records in their later phases.

— approved by (omkarmohanta09) · built by Codex · branch feat/56-domain-status-views

## 11-09-2026 — Operators can read Overview, Nodes, and honest gate availability ([#55](https://github.com/vegastack/vegastack-labs/issues/55))

- **What:** The embedded Console now reads authorized summary and source status, shows separately paginated inert node, alias, and observation records with bounded details, and reports gate capability without inventing gate results or controls.
- **Why:** Operators need useful read screens before later phases add declarations and gate evidence, while denied, stale, missing, and unavailable information must remain visibly different.
- **How it went:** Browser testing first appeared to show a denial loop because the preview was serving an older static build. Rebuilding exposed the real test ambiguity—the framework and the Console both own alert regions—and the assertion was narrowed to the Console state. The final flows preserve retryable stale data with a warning, immediately hide it after denial, restore focus after details, and keep operational data out of browser storage and URLs.
- **Changed:** Bounded in-memory TanStack Query state · generated-client-only reads · truthful shared view states · authorized Overview · independent Nodes/Aliases/Observations pagination and details · capability-only Gates · browser privacy and responsive evidence · static route drift guards.
- **Decisions:** Gate records remain deferred to their owning later phases, as selected by the operator; this issue creates no mutation, provider, deployment, or live-fleet authority.

— approved by (omkarmohanta09) · built by Codex · branch feat/55-overview-nodes-gates

## 11-09-2026 — The Console and protected reads now run inside one service ([#53](https://github.com/vegastack/vegastack-labs/issues/53))

- **What:** `vsk-labs server run` now contains the verified static Console and can serve it beside the existing versioned read API on one protected TLS origin. The local Unix-socket path remains independently available and reports whether remote reads are disabled, starting, ready, or unavailable.
- **Why:** Operators need one installable control service and one authorization path, without a Node.js production server or a browser failure taking away local recovery.
- **How it went:** Deterministic asset verification exposed a cross-language file-ordering difference, and the combined router exposed that initial session creation must carry a verified external identity before a local principal exists. Independent review then found that invalid optional settings still blocked local startup, local write routes were visible remotely, fixed-name build files were cached too long, TLS key files needed descriptor-safe loading, and the acceptance fixture was too sliced. The correction round isolated remote failure, closed the browser route set, protected credential reads, made replacement recoverable, and expanded the real-stack proof.
- **Changed:** Manifest-verified embedded Console · exact read-only static/API routing · build-derived browser security policy · server-profile 1.1 remote-read configuration · protected Cloudflare adapter profile and TLS material · TLS 1.3 bounded remote listener · audited read denials · separate typed remote health and local recovery · build and CI drift checks.
- **Decisions:** none; the work implements the approved one-executable, same-origin, local-authority architecture without activating a live listener or provider.

— approved by (omkarmohanta09) · built by Codex · branch feat/53-embed-console-and-reads

## 10-09-2026 — Remote browser access now has revocable local sessions ([#54](https://github.com/vegastack/vegastack-labs/issues/54))

- **What:** The Go control server can verify a Cloudflare Access identity through a provider-neutral adapter and bind it to existing local grants. Browser requests also require a short-lived, digest-only SQLite session that can be renewed, logged out, revoked, or invalidated after a grant or recovery change.
- **Why:** The future static Console needs remote access without trusting proxy email headers, putting provider tokens in JavaScript, adding local passwords, or creating a second Node authentication authority.
- **How it went:** The security boundary stayed inside one executable; adversarial JWT, key-outage, cookie, replay, audit, recovery, and authorization tests drove the implementation. Linux race tests exposed replay-idempotency and renewal foreign-key ordering defects that macOS skips, and both were fixed before review. Independent review then found durable-expiry, repeat-revocation, concurrent-key-refresh, real-integration-proof, and ordinary browser GET Origin gaps; the correction loop made the safe-read origin proof browser-compatible without weakening unsafe-method Origin checks. The new real-stack proof also exposed that the read API flattened a typed authorization denial to a generic dependency error, so it now admits only recognized generated backend error codes and returns the intended safe denial. The reviewed Issue #51/#52 contract chain was integrated, the combined additive contract moved to 1.8.0, and generated browser reads remained mutation-free.
- **Changed:** Provider-neutral verified identities · strict RS256 Access JWT validation · coalesced lazy key refresh with a 24-hour known-key outage bound · 15-minute idle/8-hour absolute digest-only sessions · exact Host/request-origin/JWT/session ordering · secure local-only logout · audited expiry/revocation and Cloudflare-independent local recovery.
- **Decisions:** D-125 records the one-Go-executable exception to the general Better Auth default, bounded signing-key cache, session limits, local logout meaning, and independent recovery.

— approved by (omkarmohanta09) · built by Codex · branch feat/54-secure-browser-sessions

## 10-09-2026 — Platform reads now say when their information is stale or unavailable ([#52](https://github.com/vegastack/vegastack-labs/issues/52))

- **What:** Authorized clients can read one provider-neutral source list covering the database, nodes, gates, people, services, backups, and providers. Each source reports `healthy`, `stale`, `unknown`, `unavailable`, or `failed`, and the existing summary includes counts plus the worst current state.
- **Why:** The Console must distinguish current evidence from missing, old, failed, or impossible future information instead of showing absent future adapters as healthy.
- **How it went:** Linux-only verification caught that an empty grant could not exist under the accepted authorization schema, so full access was represented by seven explicit least-privilege grants. Implementation verification also bound node freshness to the requested revision snapshot, kept optional fixtures outside SQLite transactions, rejected future-dated evidence, and preserved the exact Phase 2 evidence while Phase 3 added contracts. Integration with Issue #51 then generated and exercised strict browser types, decoding, and bounded source-filter serialization. Independent review found that wall-clock freshness could still change filtered membership between cursor pages, so the initial evaluation instant was signed into every source cursor and reused for the whole page sequence.
- **Changed:** Fixed source-state evaluator and safe reasons · exact source grants · revision- and evaluation-time-bound source pagination · `/api/v1/sources` · source summary counts · generated Go, JSON Schema, docs, and strict browser client · real ascending/descending filter coverage · failure-isolation and redaction proof.
- **Decisions:** 24-hour local database/inventory freshness · one-hour default for future optional adapters · seven exact source grants with no wildcard · unavailable future capabilities remain visible but create no live adapter, worker, provider dependency, or operational authority.

— approved by (omkarmohanta09) · built by Codex · branch feat/52-source-health-read-contracts

## 10-09-2026 — Browser reads now share one generated safe contract ([#51](https://github.com/vegastack/vegastack-labs/issues/51))

- **What:** The canonical endpoint and schema metadata now generates a dependency-free TypeScript client for every available finite read and event stream. Console code gets fixed same-origin functions, strict response decoding, pagination, cancellation, resumable events, and stable failures without constructing URLs or importing Go, provider, or database internals.
- **Why:** Every later Console screen needs one browser boundary that cannot drift away from the protected server API or quietly widen into mutation and provider access.
- **How it went:** The first independent review found two contract gaps: browser-only failure codes and a narrow secret-field filter. Both were corrected by generating the stable code union from canonical metadata and strengthening nested/open schema exposure checks; the second review was clean.
- **Changed:** Available-read endpoint metadata · generated TypeScript types and strict decoders · fixed same-origin GET methods · bounded finite responses and SSE frames · cancellation and explicit event resume without retry · generated-file drift checks · secret-bearing schema rejection.
- **Decisions:** none in the durable register; the additive public contract moved to 1.7.0, streamed events retain the canonical nested shape, and accepted Phase 2 evidence permits additive same-major contracts while still rejecting removal, rollback, or mutation enablement.

— approved by (omkarmohanta09) · built by Codex · branch feat/51-browser-safe-read-client

## 10-09-2026 — Phase 3 foundation plans preserve one safe control plane ([milestone](https://github.com/vegastack/vegastack-labs/milestone/4))

- **What:** Detailed implementation plans are ready for the generated browser read client, truthful source-health model, and secure remote browser sessions. Together they give the future Console a finite typed API, honest unavailable/stale states, and revocable browser access without creating another operational authority.
- **Why:** These foundations can be built while the private Design System registry remains blocked, and they close the contracts the later Console screens depend on.
- **How it went:** Planning found that endpoint metadata needed an explicit availability field and that Issue #54 did not need to wait before implementation, only before integration. Better Auth was considered, but the approved one-Go-executable/static-Console architecture made a Node authentication runtime the wrong fit; the existing Go JOSE library and Go-owned SQLite sessions keep the boundary smaller. Cloudflare signing-key outage behavior was separated from session expiry and bounded instead of trusting cached keys forever.
- **Changed:** Plans posted for Issues #51, #52, and #54 · #54 Brief v2 approved · #54 hard implementation dependency on #51 removed · merge order #51 before #52/#54 retained · plans lint clean.
- **Decisions:** Generate a dependency-free strict TypeScript read client · expose one paginated source-status endpoint plus compact summary · keep remote authentication inside `vsk-labs server run` · validate Cloudflare RS256 JWTs and store only digested local sessions · lazy JWKS refresh with a 24-hour known-key outage limit · 15-minute idle and 8-hour absolute browser-session expiry · record D-125 and its sources when Issue #54 lands.

— approved by (omkarmohanta09) · planned by Codex · no implementation branch

## 10-09-2026 — The complete Phase 3 read-Console batch is ready for decisions ([milestone](https://github.com/vegastack/vegastack-labs/milestone/4))

- **What:** Development Phase 3 has been converted into nine complete issue briefs covering the static Console and browser-test foundation, generated browser client, truthful source-health contracts, embedded same-origin serving, protected remote identity and revocable sessions, both read-screen groups, integrated browser/security/accessibility proof, and exact-commit phase acceptance.
- **Why:** The roadmap spans Platform Core plus Modules 3, 8, and 9. Planning only the visible Console pages would have omitted the client, authentication, staleness, privacy, recovery, and integrated proof that make those pages safe and truthful.
- **How it went:** The current default branch, all nine module parents, the Phase 3 roadmap row, control-plane/security specifications, existing Go/web boundaries, official Next.js static-export behavior, and Cloudflare JWT-validation requirements were reconciled before slicing. Every brief passed the intake linter, uses the native issue type and module parent where applicable, and records real GitHub blockers. The supplied registry variables were inspected without revealing their values and locally excluded from Git; direct reads of both required private registry items still returned `403 Forbidden`. Follow-up proved the public docs need no token, the registry itself is Access-protected, the Client ID has the expected service-token shape, and the supplied secret matches neither documented Cloudflare Access secret format; no ownership by the VegaStack Cloudflare account is assumed.
- **Changed:** Milestone #4 · Issues #50–#58 · four dependency waves · explicit no-mutation/no-live-provider boundary · Playwright/Chromium evidence lane · `vegastack/agent-dev-review-evidence` selected · one remaining registry-policy blocker.
- **Decisions:** The operator approved the browser lane, existing private evidence repository, per-request Access JWT plus revocable local session, 15-minute idle/8-hour absolute expiry, local-only logout, system-theme/toggle behavior, 44-pixel control targets, and Chromium desktop/mobile Phase 3 coverage. The briefs remain `needs-operator`; plans intentionally have not been drafted.

— requested by (omkarmohanta09) · prepared by Codex · no implementation branch

## 10-09-2026 — Phase 2 is proven and accepted ([#38](https://github.com/vegastack/vegastack-labs/issues/38))

- **What:** The authoritative local service, SQLite authority, inert inventory workflow, audit trail, recovery snapshots, protected reads, CLI parity, and signed draft-export boundary now work together as one accepted Phase 2 result. A deterministic manifest maps the whole phase to 31 executable scenarios.
- **Why:** Passing child issues was not enough; the phase needed one integrated proof that no hidden authority, privacy, recovery, or mutation gap remained.
- **How it went:** The first PR check exposed shallow Git history in CI. The cause was reproduced, CI was changed to fetch full history, a regression guard was added, and the corrected PR, post-merge CI, clean-main replay, and third Claude review all passed.
- **Changed:** Complete traceability · integrated happy/denial/privacy/recovery/parity tests · full-history CI guard · exact-main acceptance evidence · Phase 2 milestone closed after explicit operator acceptance.
- **Decisions:** none; fixture evidence remains separate from release, deployment, and live infrastructure authority.

— approved by (omkarmohanta09) · built by Codex · branch chore/2.10-phase-two-acceptance

## 09-09-2026 — Inventory workflows now run through the protected CLI ([#36](https://github.com/vegastack/vegastack-labs/issues/36))

- **What:** Operators can use `vsk-labs` to inspect status, import an inert inventory draft, compare drafts, and request a verified export through the protected local API. JSON output preserves the server envelope exactly, while human output is rendered from the same typed result.
- **Why:** Phase 2 needed one safe operator surface without direct SQLite, provider, shell, or arbitrary-network access.
- **How it went:** Landed interfaces revealed a package-cycle risk, an undersized export-response limit, and an authorization-registration footgun. The design was reconciled, the footgun was fixed after review, and all five target builds plus PR/post-merge CI passed.
- **Changed:** Five generated operator commands · three authorization-first APIs · typed JSON and Labs CSV decoding · deterministic draft diff · protected file reading · verified export delegation.
- **Decisions:** none; production signing trust remains deliberately unavailable until its later policy and custody work.

— approved by (omkarmohanta09) · built by Codex · branch feat/2.8-inventory-cli-parity

## 09-09-2026 — Draft exports are deterministic, signed, and secret-free ([#37](https://github.com/vegastack/vegastack-labs/issues/37))

- **What:** An exact immutable inventory draft can be encoded deterministically, signed through typed ports, independently verified, and published as an immutable artifact with an atomic current pointer and audit history.
- **Why:** Recovery and external verification need a safe declarative artifact, not a database dump or an unsigned best-effort export.
- **How it went:** Review closed a production-trust bypass. Merging the authorized-read work created four conflicts and a contract-version collision; both feature sets were preserved, contracts were regenerated at version 1.5.0, and the integration review and CI passed.
- **Changed:** Canonical draft snapshot · signing and verification ports · immutable artifact publication · interruption reconciliation · attributed export audit events.
- **Decisions:** none; production composition has no signer or verifier and fails closed until Phase 5 supplies real policy, keys, custody, rotation, and recovery proof.

— approved by (omkarmohanta09) · built by Codex · branch feat/2.9-signed-declaration-export

## 09-09-2026 — Authorized reads and durable event replay are available ([#35](https://github.com/vegastack/vegastack-labs/issues/35))

- **What:** The protected local service now exposes versioned status, database, inventory-draft, child-record, and event-stream reads. Every read is tied to the kernel-authenticated principal and rechecked against resource scope inside SQLite.
- **Why:** CLI and future Console clients need a single read authority with bounded pagination, safe cursors, and reconnectable events.
- **How it went:** PR CI found Linux migration tests hard-coded to the previous schema number and migration name. The tests were made catalog-derived, production code stayed unchanged, and a fresh review plus PR/post-merge CI passed.
- **Changed:** Generated read schemas/routes · scoped SQL reads · authenticated expiring cursors · bounded SSE replay · read authorization migration.
- **Decisions:** none; no real grants, browser access, or inventory mutations were introduced.

— approved by (omkarmohanta09) · built by Codex · branch feat/2.7-versioned-read-api

## 09-09-2026 — Labs CSV can become a safe inert inventory draft ([#32](https://github.com/vegastack/vegastack-labs/issues/32))

- **What:** A sanitized 15-column Labs Sheet1 CSV can be decoded offline into the provider-neutral inventory candidate model with exact provenance, lifecycle handling, identities, aliases, and hardware facts.
- **Why:** The deployment profile needed a practical import format without placing Google, Sheet-specific fields, or live provider access in platform core.
- **How it went:** Hosted CI exposed a timezone-dependent fixture, and a later merge required reconciling shared Phase 2 documents with the audit work. The fixture was made timezone-explicit, both feature contracts were preserved, and the fourth Claude review was clean.
- **Changed:** Bounded CSV adapter · exact header/version contract · public synthetic template and example · privacy/formula/control rejection · complete provenance and findings.
- **Decisions:** none; this adapter opens no files and contacts no live Sheet or provider.

— approved by (omkarmohanta09) · built by Codex · branch feat/2.4-labs-inventory-csv

## 09-09-2026 — Operational changes now produce durable attributed evidence ([#33](https://github.com/vegastack/vegastack-labs/issues/33))

- **What:** Inventory intent, its attributed audit event, intent binding, and required outbox rows now commit atomically or not at all. Durable retry states and crash/restart proofs preserve a truthful history.
- **Why:** Later plans, exports, notifications, and recovery need one local evidence trail that cannot silently separate from the state change it describes.
- **How it went:** Generated nullable enums and future migration fixtures needed reconciliation. The final candidate passed complete and clean-checkout runs, and Claude found no blocking issue.
- **Changed:** Audit/outbox contracts · migration 0003 · verified-context attribution · atomic event/outbox persistence · bounded retries · operational audit append seam.
- **Decisions:** none; there is still no external sender, worker, provider projection, retention deletion, or signing checkpoint.

— approved by (omkarmohanta09) · built by Codex · branch feat/2.5-attributed-audit-events

## 09-09-2026 — SQLite snapshots and pre-migration recovery are verified ([#34](https://github.com/vegastack/vegastack-labs/issues/34))

- **What:** The store can create verified online SQLite snapshots, publish them without replacement, discover only complete generations, and prove an isolated pre-migration restore without replacing the live authority.
- **Why:** Schema changes and crashes need a recoverable boundary before later phases can build more stateful capabilities.
- **How it went:** The branch had to integrate the newly merged inventory migration without rewriting either feature. Catalog-aware recovery remained intact, all fault tests passed, and Claude's third review was clean.
- **Changed:** Online Backup API use · secret-free manifests · protected staging/publication · crash-linearized discovery · isolated restore verification · fail-closed migration gating.
- **Decisions:** none; scheduling, encryption, retention, R2/restic, authority cutover, and live recovery remain later work.

— approved by (omkarmohanta09) · built by Codex · branch feat/2.6-online-snapshot-restore

## 08-09-2026 — Inventory candidates are typed, bounded, immutable drafts ([#31](https://github.com/vegastack/vegastack-labs/issues/31))

- **What:** Provider-neutral inventory input is strictly decoded, normalized, checked for conflicts and secret-shaped values, and stored only as a complete immutable `valid` or `blocked` draft.
- **Why:** Inventory data needed a safe internal model before any Labs adapter, CLI, API, or declaration workflow could rely on it.
- **How it went:** Review found one blocking issue and the Linux store tests exposed a single-connection deadlock risk. Both were corrected without creating a second database owner; the final Claude review was clean.
- **Changed:** Generated inventory schemas · bounded JSON decoder · deterministic normalization/findings · migration 0002 · exact idempotency and source-conflict rules.
- **Decisions:** none; drafts cannot become declared, effective, qualified, or applied in this phase.

— approved by (omkarmohanta09) · built by Codex · branch feat/2.3-inventory-draft-model

## 08-09-2026 — SQLite became the single durable operational authority ([#30](https://github.com/vegastack/vegastack-labs/issues/30))

- **What:** The control service now owns one CGO-free SQLite store with checked migrations, revisions, safe intent transactions, online pre-migration copies, isolated restore proof, and explicit read-only safe mode.
- **Why:** Every later declaration, audit, inventory, and recovery capability needs one durable local authority with no direct client access.
- **How it went:** The branch was integrated with the local-service work and the combined generated/provenance contracts were resealed. Review reached a clean third round with only a future compatibility note for the inventory migration.
- **Changed:** SQLite lifecycle · migration catalog 0001 · state revision conflicts · integrity/filesystem checks · recovery-safe migration flow · database health.
- **Decisions:** none; no inventory, grants, audit, automatic authority replacement, deployment, or live database was added.

— approved by (omkarmohanta09) · built by Codex · branch feat/2.2-sqlite-durability-foundation

## 08-09-2026 — One protected local control service now owns the API boundary ([#29](https://github.com/vegastack/vegastack-labs/issues/29))

- **What:** `vsk-labs server run` operates as the single foreground control service, while `server status` reaches it through a protected local socket. Linux peer credentials bind the caller to a configured local principal before the request enters the application.
- **Why:** The platform needed one server-owned path before SQLite, authorization, inventory, and the Console could safely exist.
- **How it went:** Review tightened peer/authentication and socket behavior, and repository-wide tests were intentionally delayed until generated command dispatch landed later in the same issue. The final candidate and PR/post-merge checks passed.
- **Changed:** Protected profile loading · Unix socket ownership/cleanup · local principal binding · generated health contracts · bounded lifecycle and shutdown · unsupported-platform denial.
- **Decisions:** none; no database authority, grant, provider, service installation, or live host qualification was claimed.

— approved by (omkarmohanta09) · built by Codex · branch feat/2.1-local-control-service

## 08-09-2026 — Release bundles can be verified offline before use ([#28](https://github.com/vegastack/vegastack-labs/issues/28))

- **What:** `vsk-labs` can inspect and verify release manifests and artifacts offline, reject tampering and incompatibility, and preserve a provider-neutral trust boundary.
- **Why:** Future installation and rollback require deterministic verification before any artifact is executed or trusted.
- **How it went:** The temporary trust-policy choice was explicitly documented, the implementation was reviewed on the exact integrated tree, and the final review had no unresolved finding.
- **Changed:** Offline manifest/artifact verification · stable failures · tamper and compatibility fixtures · documented temporary trust boundary.
- **Decisions:** none in the durable register; real production policy and signing identity were deliberately deferred and recorded for later replacement.

— approved by (omkarmohanta09) · built by Codex · branch feat/1.3-offline-release-verification

## 07-09-2026 — The portable `vsk-labs` executable now has one client boundary ([#25](https://github.com/vegastack/vegastack-labs/issues/25))

- **What:** A single buildable CLI now dispatches generated commands, produces stable JSON/error/exit behavior, resolves portable client paths and credential references, and invokes transports through direct argument arrays.
- **Why:** Every later platform feature needs the same trustworthy command and client behavior on Linux, macOS, and Windows.
- **How it went:** The first independent review found six must-fix items and the first Claude attempt returned no result. The fixes strengthened generated ownership, process tests, credential allowlisting, dependency analysis, cleanup, and five-target builds; final Codex and retried Claude reviews were clean.
- **Changed:** Executable and dispatcher · help/version/results · planned-command blocking · cancellation/request IDs · portable path/credential/transport contracts · cross-platform guards.
- **Decisions:** none; no server, database, provider adapter, plan engine, or live operation was added.

— approved by (omkarmohanta09) · built by Codex · branch feat/1.2-portable-cli

## 07-09-2026 — Public contracts now come from one metadata graph ([#24](https://github.com/vegastack/vegastack-labs/issues/24))

- **What:** One typed provider-neutral registry now generates Go contracts, JSON Schemas, command/endpoint registries, documentation, error codes, and exit behavior deterministically.
- **Why:** Hand-maintained parallel schemas would drift as the CLI, API, Console, and agents grew.
- **How it went:** Review found a dead symlink-resolution branch and a registry/schema validation mismatch. Both were fixed, generated output stayed path-safe and atomic, and the second Claude review was clean.
- **Changed:** Metadata registry · generators · drift checks · two foundation commands · 49 explicitly unavailable future commands · public-lane integration.
- **Decisions:** none; later command details remained unassigned rather than being invented early.

— approved by (omkarmohanta09) · built by Codex · branch feat/1.1-generated-contracts

## 07-09-2026 — Phase 0 evidence was reconciled after merge ([#22](https://github.com/vegastack/vegastack-labs/issues/22))

- **What:** The Phase 0 record now distinguishes verified implementation evidence, historical CI billing failure, and the two non-squash merge divergences without rewriting history.
- **Why:** Phase acceptance needed to describe what actually landed, not what the intended merge route said should have happened.
- **How it went:** Three review rounds found and fixed malformed-JSON leakage, incomplete stale-document guards, and permissive evidence URL/owner validation.
- **Changed:** Current Phase 0 evidence · stricter offline validator · documented squash-or-stop route · protected historical facts.
- **Decisions:** none.

— approved by (omkarmohanta09) · built by Codex · branch chore/0.6-phase-zero-post-merge-evidence

## 07-09-2026 — Phase 0 was audited and handed to Phase 1 ([#18](https://github.com/vegastack/vegastack-labs/issues/18))

- **What:** Every Phase 0 child merge was audited once, a checked evidence index and validator were added, shared-spine ownership across Modules 1–9 was confirmed, and the Phase 1 handoff was made metadata-graph-first.
- **Why:** The first executable phase needed verified foundations and explicit ownership, not assumptions based on closed issues.
- **How it went:** GitHub Actions was blocked by the external billing state, so the record kept CI as unverified instead of pretending it passed. Review clarified which historical merges diverged from the current squash route.
- **Changed:** Phase 0 evidence index · offline validation · parent ownership map · Phase 1 handoff.
- **Decisions:** none.

— approved by (omkarmohanta09) · built by Codex · branch chore/0.5-phase-zero-handoff

## 04-09-2026 — Host security and admission contracts became machine-checkable ([#17](https://github.com/vegastack/vegastack-labs/issues/17))

- **What:** Four host profiles, seven role IDs, eleven controls, one-shot privilege bindings, native credential references, Mesh-only Mac admission, and recurring evidence transitions are represented by sanitized deterministic fixtures.
- **Why:** Host onboarding must prove hardening, privilege, credential, and admission behavior before any workload is allowed.
- **How it went:** The implementation and independent Claude review were clean; two small fixture-naming/count-coupling nits were recorded without weakening the contract.
- **Changed:** Host-security fixture package · 69 positive/negative cases · downstream phase ownership · public verification.
- **Decisions:** D-123 and D-124 were reconciled into the authoritative register and documents.

— approved by (omkarmohanta09) · built by Codex · branch chore/0.4-host-security-admission

## 04-09-2026 — Bootstrap and human-proof rules became executable contracts ([#16](https://github.com/vegastack/vegastack-labs/issues/16))

- **What:** Installation manifests, local setup state, Slack acknowledgement, approver import, constrained SSH, and profile/gate resolution now have a machine-checked 77-case contract corpus.
- **Why:** The future runtime needed precise fail-closed bootstrap and acknowledgement behavior before implementation could safely begin.
- **How it went:** Three review rounds refined framing lengths, signed-manifest facts, provider-neutral structure, and private-value checks. No live Slack, server, database, or credential was introduced.
- **Changed:** Six contract families · deterministic validation · secret-safe denials · provider-neutral setup boundary.
- **Decisions:** D-122 was reconciled into the normative bootstrap and approval documents.

— approved by (omkarmohanta09) · built by Codex · branch chore/0.3-bootstrap-profile-human-proof

## 27-08-2026 — A clean checkout can build and verify the public scaffold ([#5](https://github.com/vegastack/vegastack-labs/issues/5))

- **What:** The repository gained its reproducible public development scaffold, pinned checks, build/test entry points, and clean-checkout verification path.
- **Why:** Later agents and contributors needed a known-good base that requires no private VegaStack credentials.
- **How it went:** The initial foundation landed before chronicle recording was enabled; this entry is reconstructed from the accepted Phase 0 milestone.
- **Changed:** Public Go/web/test scaffold · reproducible check command · credential-free development foundation.
- **Decisions:** none.

— approved by (omkarmohanta09) · built by Codex · branch historical branch not recorded

## 27-08-2026 — The issue-driven development route was established ([#3](https://github.com/vegastack/vegastack-labs/issues/3))

- **What:** The repository adopted the staged brief, plan, implementation, independent review, PR, merge, evidence, and acceptance workflow used by later phases.
- **Why:** A large infrastructure platform needed explicit human gates and recoverable agent handoffs instead of ad-hoc changes.
- **How it went:** This was the first workflow pilot and predates chronicle recording; the entry is reconstructed from the accepted Phase 0 milestone.
- **Changed:** Development mandate · issue states · review and shipping gates · evidence conventions · phase sequencing.
- **Decisions:** none.

— approved by (omkarmohanta09) · built by Codex · branch historical branch not recorded
