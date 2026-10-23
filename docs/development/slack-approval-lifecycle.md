# Slack approval message lifecycle

Updated 23-10-2026 for #263.

The existing Slack app uses Socket Mode, an app token with `connections:write`,
and its own bot token with `chat:write`. Add the app to the private approval
channel. No public callback endpoint or additional Slack permissions are needed.

The controller records the successful publication's channel and message timestamp
with the exact plan digest in SQLite. Its existing Slack background loop projects
recorded decisions and execution results into that same message:

- Pending: readable scope and Approve/Reject buttons.
- Approved: buttons removed, awaiting execution.
- Verified successful run: Applied.
- Rejected, expired, stale or failed: the corresponding outcome, never Applied.

Approving does not execute the plan. Application state remains authoritative even
if Slack is unavailable. Updates retry, honoring HTTP 429 Retry-After, and resume
from stored receipts after restart. Historical cards without receipts are not
retroactively edited. The integration uses the bot identity, not a teammate's
Slack connector.

Schema 35 adds presentation receipts without changing declaration revision or
approval authority. Before an existing controller upgrades, provision a protected
0700 `migration-recovery` directory alongside its database, owned by the configured
service UID. The existing snapshot implementation verifies a pre-migration backup;
missing or unsafe recovery storage blocks migration. Preserve the prior executable.
Do not downgrade an upgraded database in place or reset it to recover startup.

For verification, publish an actual scoped plan, observe the pending card, approve
as the configured human, and confirm automatic button removal. Execute through the
normal approved-plan path and confirm Applied only after verified success. If the
card remains unchanged, inspect controller diagnostics and API state; do not edit
Slack manually as a substitute. All live checks require the usual target authority.

Official references:

- [Socket Mode setup and envelope acknowledgement](https://docs.slack.dev/apis/events-api/using-socket-mode/)
- [Message updates, ownership and clearing blocks](https://docs.slack.dev/reference/methods/chat.update/)
- [Interaction handling](https://docs.slack.dev/interactivity/handling-user-interaction/)
- [Rate limits and Retry-After](https://docs.slack.dev/apis/web-api/rate-limits/)
