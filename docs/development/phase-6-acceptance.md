# Phase 6 acceptance

Updated: 10-10-2026. Issue [#234](https://github.com/vegastack/vegastack-labs/issues/234) owns the integrated software catalog and scoped exit report. This command grants no infrastructure, CI, release or workload authority. Nodes04/05 remain excluded. Mac/iMac [#227](https://github.com/vegastack/vegastack-labs/issues/227) remain required and deferred within v1.

## Software procedure

The operator selected delivery of working Linux workflows and deferred advanced signed recovery-fence qualification on 10-10-2026. Native baseline and role acceptance remain pending because their required runs have not completed; advanced recovery qualification is explicitly deferred. The software catalog retains all 61 obligations. The aggregate Linux native status is `pending-deferred` because it requires that deferred recovery component; a software pass or harness merge does not qualify any native stage. The existing native catalog and current-authority checks remain intact for later scoped qualification. Issues #228 and #234 remain open, with Mac and full Phase 6 acceptance pending.

Use a clean checkout, the pinned Go/Node/pnpm toolchain and a non-root isolated Linux development user. Point `TMPDIR` at a private user-owned directory whose parents satisfy the existing protected-file contract. Install public dependencies with `pnpm install --frozen-lockfile`.

```text
pnpm check:phase-6
```

The command validates the code-owned finite catalog, builds a fresh Console export, builds the actual fixture CLI and runs finite Go selector groups per package, with two independent API batches, plus the existing focused browser specifications with one worker. Existing owner fixtures prove setup, discovery/adoption, exact approval/execution/replay, access rollback, individual baseline collectors, current baseline/role admission, role installation, replacement/recovery, scoped grant changes and operator workflow. The resource/kernel check fills an uncovered collector boundary; it does not invent a second lifecycle fixture. Missing selectors, skipped tests, zero-pass results and command failure never count as success.

All software observations are `fixture`, including Linux process/SQLite/SSH/CLI success. Running on macOS can exercise portable/browser scenarios, but Linux-only obligations remain pending; this does not qualify the deferred Mac product. No native operation runs implicitly.

## Scoped exit procedure

To run software acceptance once and consume separately produced native material:

```text
pnpm check:phase-6-exit --scope linux --native-report <private-report.json> --receipt-root <private-native-output> --config <existing-protected-local-profile> --output <new-report-outside-checkout.json>
pnpm check:phase-6-exit --scope full --native-report <private-report.json> --receipt-root <private-native-output> --config <existing-protected-local-profile> --output <new-report-outside-checkout.json>
```

The native output root contains the exact `scope.json`, actual bounded `scenario-ordinal.result.json` files and the corresponding `scenario-ordinal.collect.json` requests. The fixed acceptance metadata pins the actual #228 source commit, executable and Debian profile. Changes to the native build require updating those measured pins. The runner compares the current production source closure with that compiled commit; documentation and acceptance-only tooling do not pretend an older executable was rebuilt.

The native reader is a development-only Go client of the existing protected local API. It reads `native.baseline`, `native.role` and `native.recovery`, then the actual evidence declaration, immutable plan and succeeded run for the same evidence IDs, profile, bundle digests and current recovery epoch. It re-reads the gates after joining the lineage and refuses drift. The server revalidates the actual internal native producer, receipt, source and freshness bindings. Report/scenario/receipt exports are bounded consistency material with `exportedReportAuthority=none`; their passed flags cannot qualify a server. No report-supplied endpoint, URI, credentials or host target is followed. The reader performs only GETs and opens no SQLite database.

For a separately coordinated read during #228's authorized fixture lifetime, the same helper can be cross-built and run under the existing qualified API identity:

```text
go build -o <private-reader-path> ./tooling/phase6-native-reader
<private-reader-path> --config <existing-protected-local-profile>
```

Its stdin is the finite JSON object `{"runIds":["actual-gate-apply-run"]}`. Its output is private lineage material, never an uploaded qualification or historical substitute for a current API. After native fixture teardown, unavailable current authority yields pending. Do not leave the fixture active, extend its scope or add a controller/export endpoint merely for this reporting command.

Exit codes are 0 for the requested scope passing, 1 for failed/invalid evidence and 2 for mandatory proof pending. There is no pending bypass or skip-required switch. Linux exit 0 still prints `macSoftware=pending-deferred`, `macNative=pending-deferred`, `fullPhase=pending` and `fleetActivation=pending`. Full Phase 6 additionally requires later Mac software/native proof and separate operator phase acceptance; the current deferred branch cannot pass. Full v1 acceptance remains Phase 11.

## Evidence and limits

Native-reader compatibility remains pending qualification work: the current trace loader recognizes ordinals 1–99 and bounds matching receipt files at 256 and run IDs at 128. The newer native preparation capacity can exceed those limits. The historical executable pins also require a newly measured build before current native qualification. Do not treat an incomplete trace as qualification or increase these limits as part of working software delivery; reconcile them with the complete actual native trace when that scope resumes.

Public output contains synthetic obligation IDs, digests, source commit, timestamps and statuses. Raw observations, private topology, keys, database paths and tokens are not copied into it. The sanitizer runs before public output; rejected diagnostics are reported as bounded failure codes. Temporary runtime/browser artifacts are removed even when a scenario fails. A cleanup failure cannot produce a successful report.

The harness may merge under the standing Linux development authority after the required checks. Keep #234 open while native, Mac or operator acceptance remains outstanding. Merging tooling is neither phase acceptance nor permission to onboard the fleet. Preserve existing workload/data boundaries; failures belong to the feature owner, with no automatic safe-workload stop or native rerun.
