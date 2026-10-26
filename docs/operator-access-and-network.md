# Operator access and network procedures

This guide describes the Phase 7 software workflows. The delivery map records which changes have landed; actual deployment and provider qualification require their separate evidence. It is not permission to change a host, provider, router or switch. Use a protected operator profile and the current authorization for the exact target. Nodes04/05 and their identities, addresses and indirect effects remain excluded from every Labs operation.

## Know which state you are looking at

| State | Meaning |
| --- | --- |
| Platform human active | The controller may evaluate this person's current grants. No external account was created. |
| Controller device pending | A device record exists, but it gives no access. |
| Controller device approved | Attributed requests may use the owning human's existing grants. It installs no SSH key or provider client. |
| Provider device enrolled | The external provider has a registration. This does not prove controller approval, intended routes or qualified connectivity. |
| Host adopted-unadmitted | Hardware is registered. It is not qualified to run workloads. |
| Provider configured | Protected configuration exists. Connectivity may still be unknown. |
| Connection diagnostic successful | One declared host accepted a pinned SSH authentication and the controller confirmed current authority. No shell or persistent session was opened. |
| Rotation partial | The provider change happened, but some required connector updates or verification are still outstanding. |

## Inspect people and devices

Open People in the Console. You see only people covered by your current principal-specific policy-read grants. Inspect a person to read their bounded device and grant collections; use continuation controls when another page exists. Refresh checks current state. Denied access removes cached people and details rather than continuing to show them.

Providers shows configured capabilities and available observations. Unknown connectivity is not a connection test. The browser never receives provider credentials or opens the control database.

For lifecycle changes use the existing `user onboard`, `user suspend`, `user resume`, `user offboard`, `device request`, `device approve` and `device revoke` commands with their generated request files and protected profile. These prepare declarations; they do not silently apply them. Inspect the exact plan, obtain the required Slack acknowledgement, and apply that plan through the existing executor. Use the generated CLI/API references for the exact request fields and current revisions.

Onboarding creates no grants or browser mapping. Resume does not restore ended sessions. Offboarding and device revocation are terminal. Revoking a controller device does not claim to remove an external provider registration or terminate a separately established OS shell.

## Link a browser identity

Use the existing `authorization grants draft` request's exact `identityBinding` object for an already active human. Bind verified method, issuer, immutable subject and sorted audiences; never place a JWT, OAuth token or credential in the request. The existing browser adapter still authenticates the real login. Slack approval identity does not automatically establish browser login identity.

Review and acknowledge the exact mapping plan before apply. Revoke only the intended owned binding to end its browser sessions. An unrelated binding and its sessions remain unchanged. A revoked identity cannot be silently rebound by editing a database row.

## Prepare a managed-host connection

The controller must already hold the host registration, current discovery identity/key binding and an explicitly approved network endpoint. The endpoint names its exact LAN/Mesh addresses, pinned SSH host key, non-root user and site marker. Registration and a network endpoint grant no workload admission.

Prepare the endpoint through its generated draft command and the existing plan/acknowledgement/apply path. Review the full target, identity, addresses, marker and recovery epoch. The operator also needs an exact current `network.connect` grant for that host. Do not substitute a host-read grant or caller-supplied address.

Configure the operator's own private-key file through the protected client profile. Keep the key local and owner-only; never copy it into a plan, issue, browser form, log or another person's account. Unsupported protection or an encrypted key without a supported unlock method produces a blocked result; it does not trigger a plaintext prompt or fall back to an SSH agent.

Use the declared endpoint and your protected operator profile:

```sh
vsk-labs network endpoint draft --config /path/to/operator-profile.json --file /path/to/endpoint-request.json --output json
vsk-labs connect --config /path/to/operator-profile.json --node example-node --port 22 --path auto --output json
```

The first command stages the endpoint only. Plan, acknowledge and apply it before the diagnostic. `example-node` is a placeholder for a current authorized host ID, not a discovered address. The supported diagnostic port is 22; arbitrary port forwarding is not provided. Auto verifies the declared TLS marker before choosing LAN; otherwise it chooses the declared Mesh path. If the LAN TCP connection fails before SSH begins, auto may try the declared Mesh path. Forced LAN never retries through Mesh. Forced LAN/Mesh is for diagnosis and does not bypass the host-key or controller authorization checks. Once SSH starts, an identity/authentication error is returned without silently trying another address.

The current `connect` command is a diagnostic, not an OpenSSH `ProxyCommand`: do not put it in an SSH include or expect an interactive shell. Automatic SSH alias/stream transport is not supplied by this diagnostic. The diagnostic authenticates and immediately closes. It does not install an agent, execute commands, open a terminal, forward ports or guarantee continuing provider availability. Current authorization and endpoint identity are checked again before success is reported.

## Enroll and reconcile Mesh

Cloudflare client enrollment and controller device approval are separate steps. Use the approved account's actual enrollment instructions; do not invent an enrollment URL, organization name or address range. An administrator completes any necessary external account action; the platform does not provision Workspace accounts.

Use the implemented Mesh observation workflow to obtain a current sanitized before-state digest for the explicitly scoped resources. Import ownership through an acknowledged plan before changing existing objects. Draft only owned custom profile routes, owned policy rules or the one bound registration action. Review all direct and indirect targets and the current credential/material versions before apply.

Foundation configuration is permitted only by its explicitly pinned protected scope and required current safety/recovery/credential/ownership conditions. It is not a qualified-Mesh bypass. Qualified operation still needs its applicable qualification evidence. Missing provider access, scope or evidence is blocked; a fixture cannot supply live proof.

After apply, independent provider reads verify the intended result. Outage or an uncertain response leaves unavailable/partial state; do not automatically replay a possibly successful mutation. Deleting a provider registration proves absence of that registration only. A later enrollment is a different registration requiring an explicit new binding.

## Publish or change ingress

The selected Labs website is `labs.vegastack.dev`. Actual account/zone permission, tunnel/Access/DNS ownership, origin TLS, audience/subject mapping, complete connector identities and applicable placement/ownership gates are required before a live change. A DNS permission alone is not evidence that these are available.

Use the ingress commands with the protected operator profile and their generated request types:

```sh
vsk-labs network ingress observe --config /path/to/operator-profile.json --file /path/to/observation-request.json
vsk-labs network ingress draft --config /path/to/operator-profile.json --file /path/to/change-request.json
vsk-labs network ingress status --config /path/to/operator-profile.json --profile-id example-ingress
vsk-labs network ingress rollout-evidence --config /path/to/operator-profile.json --file /path/to/rollout-observation.json
```

Observation precedes ownership import. Draft remains inert until the existing declaration/plan/acknowledgement/apply path runs. The supported changes are an existing tunnel hostname's config, an existing app-specific Access policy, an existing proxied CNAME, one explicit connector disconnection and bound tunnel-token rotation. They do not create a new tunnel or shared Access policy. Follow the [ingress procedure](cloudflare-ingress-operations.md) for exact ownership and preserved fields. Review the exact hostname, origin/TLS, audience rules, complete before-state and affected connector set. Preserve unrelated configuration when the provider requires a whole-document update. The origin must remain protected when a connector fails; do not substitute an undeclared connector or broaden public access.

For routine connector removal, name the single connector explicitly. An omitted connector selector must never become an account/tunnel-wide cleanup. Shared tunnel-secret rotation has shared scope: reviewing one host does not authorize disrupting every other connector, especially a protected host.

Provider rotation alone is not complete connector rollout. Keep new secret/token values inside approved credential custody; public results contain only references, versions and status. Follow the approved per-connector update/restart procedure only on separately authorized targets, then obtain the required independent verification. The current adapter cannot independently prove which credential generation a connector uses, so rotation remains partial. A new session plus a manual receipt does not close that gap. Never present a manual confirmation alone as proof of current-generation connectivity.

## Manual router and switch work

Use [network-device operations](network-device-operations.md) for researched hardware boundaries. Confirm the delivered model/revision/firmware and actual DHCP authority before proposing settings. The ES216G's DHCP client is not a DHCP server. Keep the selected single-uplink flat LAN; do not add a DHCP server, VLAN design, public port forward or another service.

A manual proposal names the exact device, setting, affected hosts, before/desired state, verification, rollback and recovery access. Keep configuration exports private because they can contain credentials. Obtain the scoped manual approval before changing anything. A guide or broad development approval is not permission to click Apply on a live router.

If the normal platform workflow does not support a requested device write, report that boundary and prepare the approved manual procedure; do not disguise a direct API call or shell as an implemented adapter. Preserve the same target, approval, verification and audit/reconciliation requirements. An operation with unknown impact on nodes04/05 is blocked.

Change only the approved setting. Verify the selected target and retained management/recovery path using authorized checks. Never restore a whole router/switch export as a casual rollback: it may affect every attached host and needs its own complete target analysis and authority.

## Mobile and recovery

Use the authenticated responsive Console for supported browser reads on a phone or tablet. A mobile browser does not run the CLI or gain SSH/device attribution from a browser login. A Cloudflare client, where supported and explicitly enrolled, is still subject to the separate provider/device/policy checks. Keep a supported operator workstation for CLI and local key custody.

If provider access is unavailable, retain the already approved local/constrained-SSH controller path and independent machine console/admin access. Do not infer new access from an outage. Wrong identity, revoked authority or stale endpoint is a stop, not a reason to disable verification. Inspect the failed layer, obtain current authorized state, then prepare a fresh plan where required.

Phase 6 native/Mac/advanced recovery deferrals remain deferred. A local pilot, these software procedures and isolated tests do not qualify physical hosts, public ingress or a 30-day Mesh pilot.
