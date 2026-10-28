# Independent site-silence watchdog source

This is the required Phase10 source capability, not a deployment. It uses the existing executable/server lifecycle, R2 signing client and selected Cloudflare Worker adapter. No daemon, queue, KV, broad token, new signing workflow or status projection is introduced.

## Producer and consumer contract

`internal/siteheartbeat.Publisher.Publish` performs one current authority-health read, encodes a closed signal and calls the configured writer once. The integration owner composes that read from the existing server authority plus UTC clock, with the current state revision/recovery epoch. It must not convert stale cached operations status into a fresh heartbeat. Publication rejects source observations older than 60 seconds or in the future. The payload contains only schema/version, opaque site SHA-256 digest, observation time, state revision and recovery epoch. It is a reachability signal, never host qualification or approval evidence.

`internal/adapters/r2.HeartbeatWriter` verifies a current protected reference for consumer `site-heartbeat-write`, resolves its short-lived value and uses the existing SigV4 client for only `PUT /<status-bucket>/heartbeat.json`. The credential material is a protected JSON value with `accessKeyId`, `secretAccessKey` and `sessionToken`; no value is placed in a request file, plan, CLI argument, log or source. It accepts only the exact canonical heartbeat and fixed object key, rejects a configured backup bucket match, uses a five-second request deadline, disallows redirects and closes/wipes resolved buffers. Actual write-only permissions, credential expiry/rotation and complete separation from every backup bucket require real deployment evidence; metadata and a successful PUT cannot prove those grants. No token is minted or signed by this feature.

The same checked-in heartbeat fixture is consumed by Go and built-in Node tests. The versioned Worker source is embedded by `cloudflare.SiteWatchdog()` for the owning typed adapter. The returned artifact declares cron `*/5 * * * *`, stale age 900 seconds and the two exact object keys. It grants no deployment authority.

The Worker requires protected runtime bindings `STATUS` (the separate status bucket), `SITE_DIGEST`, `GITHUB_REPOSITORY`, `GITHUB_TOKEN` and `SLACK_WEBHOOK`. It exposes no public HTTP management/status route. Missing or invalid configuration produces a fixed blocked result without provider calls. There is no deployed Worker or configured runtime binding from this source change.

## Detection and delivery

Each scheduled check uses the actual execution clock. Missing, malformed, wrong-site, future, replayed-epoch/revision or 15-minute-stale heartbeat cannot clear an incident. A recovery heartbeat must be fresh, match the site and follow incident detection. Scheduling adds up to the five-minute interval to stale detection; these are configured thresholds, not measured delivery latency.

A conditional R2 write owns one bounded check and stores sanitized delivery state in `watchdog-state.json`. It is a delivery projection, never operational or approval authority. GitHub issue lookup is bounded to three pages of 100 and an exact body marker; ambiguous results stop delivery rather than create another issue. An issue is reopened/closed only after the corresponding source condition. Creation intent is persisted before POST. A lost response is reconciled by the marker; unresolved uncertainty stops further creation and requires operator reconciliation. This avoids promising an impossible cross-provider exactly-once transaction.

Primary/secondary attempts are separate, capped at six with five-minute exponential backoff capped at 30 minutes. A valid provider Retry-After is respected up to that cap. Exhausted attempts remain visibly degraded/paused; verified source-condition transitions reset their bounded budgets. No infinite queue, raw log or error-response retry payload is retained.

Slack incoming webhooks are the concrete secondary source implementation. A purpose-specific webhook can notify independently of the home control plane and GitHub; it is separate from Slack acknowledgement and has no approval buttons or authorization effect. Its live provider/channel/recipient selection remains unconfirmed G-011 configuration. Source tests use a fake webhook only.

A functioning Worker catches heartbeat-store, primary-delivery and credential failures and attempts the independent secondary route. If its state store is unavailable, durable dedupe is unavailable: fallback is limited to one bounded notification attempt per scheduled invocation. Complete Worker nonexecution or a Cloudflare-wide outage cannot be detected by that same Worker. G-011 must therefore supply and test the independent secondary observer using last-check freshness; it cannot be replaced by a catch-handler test. No such observer, recipient binding or delivery proof is asserted here.

## Activation and human procedure

The server now composes an absent-by-default `operationsHeartbeat` protected profile binding into the existing notification lifecycle. No API/read/observe request starts heartbeat writes. Its existing 30-second ticker checks a fixed five-minute heartbeat attempt cadence; one bounded notification dispatch may run independently, so a slow/unavailable GitHub destination cannot block heartbeat publication. There is no second timer, daemon or new fixed scheduled-job action.

The protected binding names schema/version, endpoint, separate status bucket, fixed `heartbeat.json` object, site digest, target/reference/material version and policy ID/version. `serverconfig.HeartbeatCapability` derives `operations.heartbeat.<SHA256>` from the complete binding. The current human-applied profile must contain this exact capability plus `credential.operations.heartbeat`, and its policy ID/version and recovery epoch must match. Editing the protected file alone cannot grant writes: it invalidates the exact capability until the existing acknowledged profile workflow applies the corresponding intent.

Each attempt reads current authoritative health and obtains its UTC timestamp at the read boundary. The runtime rejects safe/recovery mode, stale policy epoch, inactive/unverified credentials, wrong `site-heartbeat-write` consumer, wrong `operations.heartbeat.write` purpose, native resolver, target or material binding. Native ciphertext custody is resolved only at point of use through the existing installed credential mechanism. Configured backup bucket/ref sharing is rejected before runtime composition. G-011 is still evaluated through a fail-closed hook; the integration owner connects the shared provider-receipt verifier when available. No uploaded fixture, runtime option or browser grant can make that hook pass.

Typed resource deployment and current applied G-011 evidence remain separate integration/activation responsibilities. The existing operations notification proof registry remains fail-closed; this artifact cannot activate that sender or mark G-011 passed. Before any separately authorized deployment, record exact status/backup bucket separation, the narrow write-only producer grant, Worker status-bucket binding, one Issues-only repository credential with its owner, named recipients and independent secondary monitoring/delivery. Preserve the existing plan, human acknowledgement and recovery precheck for resource/credential changes.

Manual diagnosis uses the same protected scope and sanitized data: inspect current authority state, producer delivery result, heartbeat age/site binding, checker `lastCheckAt`, conditional-state ownership, delivery attempt counts, exact issue marker and secondary receipt. Do not reveal webhook/token values, grant broader permissions, edit authoritative SQLite, blindly retry uncertain issue creation or call providers outside their approved owning workflow. A failed/uncertain result remains degraded. Recovery confirms a new heartbeat and exact issue closure plus secondary receipt; alert silence is insufficient.

For exhausted/uncertain delivery, preserve the exact state and issue evidence. The owning separately acknowledged adapter repair must reconcile actual destination state before resetting its delivery projection; never delete backup data or invent success. Worker rollback selects the last reviewed source artifact and preserves heartbeat/delivery state. Real procedures and targets remain unavailable until their owning deployment workflows and G-011 evidence exist. Nodes04/05 and all indirect effects remain excluded.

## Focused software proof and official protocols

Run `go test ./internal/siteheartbeat ./internal/adapters/r2 ./internal/adapter/cloudflare -run '^TestEncodedHeartbeat|^TestPublisherRequires|^TestHeartbeat|^TestSiteWatchdog' -count=1`, changed-package vet and `node --test tooling/test/site-watchdog.test.mjs`. These use synthetic credentials and fake HTTP/native-R2 fixtures. No provider, webhook, host, CI or native-runtime operation is performed.

Protocol references checked 28-10-2026:

- [R2 temporary credential scope](https://developers.cloudflare.com/r2/api/s3/temporary-credentials/): a supplied limited session can restrict operations/objects; `actions` and `scope` are mutually exclusive. This feature does not use or change the existing backup local signer.
- [R2 Workers object and conditional APIs](https://developers.cloudflare.com/r2/api/workers/workers-api-reference/): native get/put and etag preconditions; failed conditional PUT returns null.
- [Workers scheduled handler](https://developers.cloudflare.com/workers/runtime-apis/handlers/scheduled/): module scheduled entry and five-minute cron expression.
- [GitHub Issues REST](https://docs.github.com/en/rest/issues/issues): bounded repository issue listing, POST create, PATCH state and Issues-write credential.
- [Slack incoming webhooks](https://docs.slack.dev/messaging/sending-messages-using-incoming-webhooks/) and [rate limits](https://docs.slack.dev/apis/web-api/rate-limits/): JSON text POST, `ok` success and HTTP 429 Retry-After handling.
