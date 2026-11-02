# Phase 10 software acceptance map

Status on 02-11-2026: this maps each Phase 10 software requirement to the isolated test that proves it, on merged `main` at commit `e176c607`. It is **software and fixture evidence only**. It records no live target, provider, credential, host or VM operation and does not pass any live gate. The protected hosts `vsk-node-04` and `vsk-node-05` were not involved.

Tests that only build on Linux (for example `notification_readiness_workflow_linux_test.go`) were not executed on the macOS development machine that produced this map; they are marked.

## Result of the run

Run on 02-11-2026 on merged `main` (`e176c607`), macOS, Go via a throwaway module cache:

- `go test` for the 19 packages listed in the map (`internal/maintenance`, `operations`, `store`, `adapter/githubalerts`, `adapter/beszel`, `adapter/slackalerts`, `adapter/cloudflare`, `adapters/r2`, `siteheartbeat`, `serverconfig`, `server`, `api`, `plan`, `change`, `gate`, `authorization`, `localapi`, `metadata`, `cli`): **all ok**.
- `go vet` on the same packages: **clean**.
- `node --test tooling/test/agent-workflows.test.mjs tooling/test/site-watchdog.test.mjs`: **19 of 19 pass**.
- `node tooling/agent-workflows.mjs --check`: **20 artifacts verified; native acceptance not run**.

Linux-only tests compile but were not executed on this machine.

## Requirement map

| # | Requirement | Source | Proving test | Kind |
|---|---|---|---|---|
| 1 | One local alert per failure, one dedupe key, verified recovery closes it, warnings need two consecutive failures | `internal/operations/alerts.go` | `internal/operations/alerts_test.go`: `TestFailureDedupeAndVerifiedRecovery`, `TestWarningNeedsTwoConsecutiveFailures` | isolated |
| 2 | Alert state persists atomically, survives a destination outage, bounded retry then dead letter | `internal/store/outbox.go`, `internal/store/operations*.go` | `internal/store/operations_test.go`: `TestOperationsAtomicDedupePersistenceRecoveryAndOutage`, `TestOperationsOutboxBoundedDeadLetterAndIntegrity`, `TestOperationsInvalidAttributionRollsBackObservation` | isolated (real SQLite) |
| 3 | GitHub Issues delivery: retry, dedupe, update, verified close | `internal/adapter/githubalerts/client.go` | `client_test.go`: `TestIssueRetryDedupeUpdateAndVerifiedClose` | fixture |
| 4 | Beszel read: exact scope, freshness, sanitization (source staleness) | `internal/adapter/beszel/client.go` | `client_test.go`: `TestExactRecordScopeFreshnessAndSanitization` | fixture |
| 5 | Operations reads and collection require authorization | `internal/api/`, `internal/server/operations_monitoring.go` | `internal/api/operations_monitoring_test.go`: `TestOperationsAuthorizationPrecedesParsingOrCollection`; `internal/server/operations_monitoring_test.go`: `TestOperationsMissingPrincipalCannotReadSourcesOrBorrow` | isolated |
| 6 | No health upload and no provider target selection from CLI or API | `internal/cli/`, `internal/metadata/operations.go` | `internal/cli/operations_monitoring_test.go`: `TestOperationsCommandsCannotUploadHealthOrSelectProviderTargets`; `internal/metadata/operations_test.go`; `internal/localapi/operations_client_test.go` | isolated |
| 7 | Operations configuration freezes and fails closed | `internal/serverconfig/operations.go` | `internal/serverconfig/operations_test.go`; `internal/server/operations_test.go` | isolated |
| 8 | Operational audit does not mutate business state | `internal/audit/`, `internal/store/` | `internal/store/operational_audit_test.go` | isolated |
| 9 | Site silence: 5-minute check, 15-minute staleness, one issue, dedupe, verified recovery | `internal/adapter/cloudflare/assets/site-watchdog.mjs` | `tooling/test/site-watchdog.test.mjs` | fixture (node) |
| 10 | Missing, malformed, wrong-site, stale, future or secret-bearing heartbeat cannot close an alert | same Worker | `tooling/test/site-watchdog.test.mjs` | fixture (node) |
| 11 | Delivery failure and recovery (primary down, secondary down, lost create response, 429, expired credential, checker failure) | same Worker | `tooling/test/site-watchdog.test.mjs` | fixture (node) |
| 12 | Heartbeat producer is fresh, authority-health based, closed payload | `internal/siteheartbeat/heartbeat.go` | `heartbeat_test.go`: `TestEncodedHeartbeatMatchesConsumerFixtureAndRejectsStaleInput`, `TestPublisherRequiresFreshSuccessfulAuthorityRead` | isolated |
| 13 | R2 writer uses only an exact signed PUT and wipes the credential | `internal/adapters/r2/heartbeat.go` | `heartbeat_test.go` | fixture |
| 14 | Heartbeat server composition: authorized, denied before borrow, independent of busy dispatch, fail-closed in production | `internal/server/site_heartbeat*.go` | `internal/server/site_heartbeat_test.go`; `internal/serverconfig/site_heartbeat_test.go` | fixture |
| 15 | Worker artifact is versioned and independent | `internal/adapter/cloudflare/site_watchdog.go` | `site_watchdog_test.go` | isolated |
| 16 | Slack canary: fixed payload, wrong route or stale authority rejected, no retry or invented receipt | `internal/adapter/slackalerts/client.go` | `client_test.go` | fixture |
| 17 | G-011 route readiness needs real receipts, a complete workflow and an acknowledging human; no self-approval | `internal/operations/`, `internal/server/`, `internal/store/`, `internal/gate/`, `internal/authorization/` | `notification_readiness_test.go` in each package; the workflow test is **Linux-only** | isolated |
| 18 | Hardening drift and staleness diagnosis; unknown, excluded or duplicate targets denied | `internal/maintenance/drift.go` | `drift_test.go` | isolated |
| 19 | A failed or uncertain canary stops later batches; draft is inert with exact order | `internal/maintenance/plan.go` | `plan_test.go`: `TestCanaryFailureAndUncertaintyStopLaterBatches`, `TestInertDraftBindsExactOrderAndIncidentAndCannotExecute` | isolated (synthetic) |
| 20 | Maintenance denial, revocation and review cannot acquire an execution plan | `internal/api/`, `internal/plan/` | `maintenance_test.go` in each | isolated |
| 21 | Incident reconciliation is an inert new revision | `internal/change/` | `maintenance_test.go` | isolated |
| 22 | Maintenance CLI is preparation only; repair delegates the exact request | `internal/cli/maintenance.go` | `maintenance_test.go` | isolated |
| 23 | Doctor reports the first invariant without leaking or mutating | `internal/cli/doctor.go` | `doctor_test.go` | isolated |
| 24-26 | Nine canonical agent workflows; identical Claude and manual text; Hermes read/plan only; drift, precedence and secret/provider denial checks | `tooling/agent-workflows.mjs` | `tooling/test/agent-workflows.test.mjs` | fixture (node) |

## Open: not proven by software

These stay **open**. A software test does not close them, and a missing provider credential is not a successful live test.

- **Actual maintenance execution, patch, reboot, drain and failed-canary stopping during real execution.** No executor exists by design (`maintenance-execution-unsupported`); issue #324 lists it out of scope. Needs a live allowed host and its own approval.
- **Aggregate maintenance execution** is documented as unavailable.
- **Live delivery:** GitHub Issues credential and owner; a selected independent secondary route and its webhook; the R2 write-only identity and status bucket; the deployed Worker and its five-minute schedule; Beszel enrollment.
- **Independent detection of a fully stopped Worker or a Cloudflare-wide outage** (no independent observer asserted).
- **Human read of a notification.** Only provider acceptance is covered.
- **Native Codex, Claude and Hermes loading, trust and precedence.** Generated-text hashes are not native runtime proof.
- **Manual-parity** is covered only by the generator's identical-text test; no separate test runs a manual procedure against the same outcome.
- **Operations end-to-end through the server** (induced source failure, alert, delivery, recovery in one test) is not proven by a single server-level test; rows 1-3 prove the pieces.
- Phase 9's blocked real delivery demonstration (#317) is neither bypassed nor declared passed.
