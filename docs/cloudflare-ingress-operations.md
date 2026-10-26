# Owned ingress operations

This workflow uses `vsk-labs` and server-owned declarations, credentials and exact-plan approval. It does not select a real connector pair, qualify connectivity or close G-012. Nodes04/05, including indirect route or credential effects, remain excluded. Unknown target mapping blocks provider use.

An administrator first records the exact account, zone, existing tunnel/application/policy/DNS IDs, HTTPS origin and identity, and the complete connector-to-host mapping in the approved protected profile scope. Observation and mutation use different logical credential references. The replacement tunnel secret is a third credential reference with purpose `ingress.tunnel-secret`; its value never belongs in a request file, terminal argument, issue, plan or audit event.

Commands use one protected operator profile:

1. `vsk-labs network ingress observe --config <profile> --file <request>` reads the scoped existing resource and returns its before digest. It changes neither ownership nor provider state.
2. Put that exact digest in the typed import request and run `vsk-labs network ingress draft --config <profile> --file <request>`. Use the returned declaration with the existing `plan`, human acknowledgement and `apply` workflow. Import records ownership locally; it does not create provider resources.
3. Prepare an owned change with the current ownership revision and a fresh before digest. Supported changes update one existing hostname in a remotely managed tunnel, one application-specific Access policy using explicit existing Access group IDs, one proxied CNAME record, one explicitly named connector, or the tunnel secret. The CNAME targets the declared tunnel and uses automatic TTL. Unowned ingress entries, ordering, catch-all and other configuration survive a hostname update. No TLS bypass is accepted.
4. Inspect `vsk-labs network ingress status --config <profile> --profile-id <id>`. Observed configuration does not establish client connectivity, browser identity acceptance or direct-origin denial. Those fields remain unknown until their separate acceptance evidence exists. Provider outages preserve the independent local listener.

Every provider mutation requires current G-012/G-016 evidence, scoped authorization and exact human acknowledgement plus the existing recovery precheck. Local ownership import does not require the provider-mutation gates. G-012's credential/rotation boundary is unresolved; fixture source and imported records grant no live authority.

## Connector failure and rotation

Disconnect names one connector UUID. The adapter always sends `client_id` and never silently issues all-connector cleanup. Zero or one serving connector is reported without inventing route health. A disconnected connector may reconnect while its token remains valid.

Provider token rotation prevents future connections with the old token; existing sessions remain active. A successful provider change therefore leaves the run partial with `connector-update-required`. Preserve local/LAN recovery and the independently retained configuration before any separately authorized rollout.

The human fallback has the same exact target list, approval, credential references and recovery prerequisites. On each declared eligible connector, use the existing approved host secret-custody and configuration procedure to install the new referenced token, restart only its named service, and verify its provider reconnect and origin behavior before proceeding in the approved order. Do not paste an installation command containing the token or put a token in process arguments. If that secure host procedure is not implemented or authorized, stop at partial; this issue adds no host executor or privilege bypass.

Submit non-secret references through `vsk-labs network ingress rollout-evidence --config <profile> --file <evidence>`. The request names the exact rotation run, material version and connector set. The server independently rereads current provider connections; a caller receipt cannot mark success. Missing replicas or retained old sessions remain partial. The current provider API cannot prove the installed credential generation, so even new sessions remain `verification-pending`. This workflow does not claim full rotation, origin isolation, G-012 qualification or compromise containment. Any tunnel-wide emergency containment requires its own separately approved boundary; it is not an automatic fallback.
