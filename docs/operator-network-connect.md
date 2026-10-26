# Diagnose an approved node connection

This procedure uses the same `vsk-labs` API, grants and exact-plan engine as agents. It performs one SSH authentication handshake and immediately closes it. It supplies no shell, commands, port forwarding or persistent connection. Registration and diagnostic success do not establish hardening, admission or live Mesh qualification.

## Prerequisites and target resolution

Use an explicitly authorized registered host and current discovery target. Resolve its full identity, aliases and declared LAN/Mesh/marker addresses from existing records before any network operation. Never contact nodes04/05, their aliases or addresses, including by a marker request. An ambiguous physical identity or indirect effect stops the procedure. The operator exclusion remains absolute even if a profile is incomplete.

Before any future authorized Labs deployment, its protected server profile must set `networkConnectExcludedHostIds` to include `vsk-node-04` and `vsk-node-05`. This is deployment policy; portable core types contain no Labs names. The server validates/copies the bounded unique ID list and follows registered identity, current/historical alias ownership and historical discovery/endpoint addresses. Clients cannot override it.

The caller needs current exact grants: administrator `network.endpoint.write` author on resource kind `host`; `network.endpoint.change` execute on `execution-target` with human branch; human `plan.acknowledge` on `plan-target`; and separate read `network.connect` on `host`, all naming the same host ID. Existing controller connection/health prerequisites still apply. Request only the permissions needed for that host through the existing grant workflow. Host-read/discovery grants alone confer no connect access.

A usable client profile must specify one absolute `networkConnectPrivateKeyPath`. Keep the file owned by the invoking user, regular, singly linked and inaccessible to group/other users; no symlink or automatic credential lookup is accepted. Never paste the private key or a password into a plan, issue or prompt. The portable constrained-SSH controller client profile supports this optional path as well as the protected local server profile. Windows currently returns `UNSUPPORTED_PLATFORM` for the protected-key read; this procedure's functional key path is Unix-only.

## Prepare and activate an endpoint

Prepare one private JSON request using the generated [NetworkEndpointRequest schema](../schemas/v1/network-endpoint-request.schema.json). Use the current host ID, registered identity digest, discovery target ID/revision, exact canonical SSH host key and non-root user. Include explicit LAN and Mesh literal-IP addresses with SSH port 22, the HTTPS marker literal IP/port/path, whole leaf-certificate SHA-256 digest and exact bounded non-secret response value. The only supported flow is `operator-client-to-host-ssh`.

The enclosing request contains schema/version, `action: "activate"`, endpoint revision equal to the current endpoint revision plus one, expected endpoint/declaration/state revisions, recovery epoch, an idempotency key and a reason digest. Obtain current values through the authorized platform reads; never open the controller database directly. A wrong or unavailable input is a stop, not permission to invent a value. Installing the actual marker, distributing credentials and enabling real Mesh routes require their own scoped authorization.

1. Run `vsk-labs network endpoint draft --config <protected-profile> --file <request.json> --output json`.
2. Inspect the returned declaration. Run `vsk-labs plan --config <protected-profile> --declaration-id <returned-id> --revision <returned-revision> --output json`.
3. Request the normal human acknowledgement for the exact returned immutable plan through the existing approval workflow. Review the exact host, both addresses, marker, pinned identity and database-only effect. Agents cannot acknowledge their own apply.
4. After approval, run `vsk-labs apply --config <protected-profile> --plan-id <approved-plan-id> --output json`. Inspect the resulting run using the existing `run inspect` command.

A draft grants no access and activates no endpoint. The exact plan must remain current; stale state, changed identity/target, absent approval, revoked authority and unavailable recovery preimage deny execution. A successful effect retains an attributed audit record and verified local database preimage. No host/provider configuration is changed by this declaration.

## Run the diagnostic

Run `vsk-labs connect --config <protected-profile> --node <host-id> --port 22 --path auto --output json`. Port 22 and `auto` are the defaults when omitted. The API authorizes a fresh descriptor before any target dial. Automatic selection uses LAN only after the exact pinned TLS marker and body verify; otherwise it selects the declared Mesh address. If that initial LAN TCP dial fails before SSH protocol/authentication starts, automatic mode may try the declared Mesh endpoint. It never searches a subnet or substitutes an undeclared address.

For an explicitly selected diagnostic, use `--path lan` or `--path mesh`. This skips marker selection and preserves authorization and SSH identity checks. It does not add a route or configure a network. The command reports `authenticated-and-closed`, chosen path and endpoint digest only after a second descriptor fetch confirms unchanged authority and bindings.

A forced-LAN TCP failure is final. Any failure after TCP connects and SSH protocol/authentication starts, including host-key or authentication failure, is final for that command. No automatic fallback occurs after that boundary. Check the current declaration and target identity through authorized platform reads; do not bypass pinning or introduce raw SSH options. On timeout/cancellation, the bounded connection closes. If the post-handshake authority check fails, the command reports failure even though the already completed authentication cannot be undone. Repeat only after independently resolving the cause and confirming the current authorized target.

## Revoke or correct a declaration

Prepare a new request with `action: "revoke"`, the next endpoint revision, current endpoint/declaration/state revisions and recovery epoch. Use the identical draft→plan→human acknowledgement→apply path. New descriptors are denied after revocation; history remains. This does not delete provider registrations, OS accounts, keys or sessions outside this diagnostic.

For a mistaken active endpoint, acknowledge/apply its exact revoke request and prepare a corrected activation as a new revision. Do not edit old rows or reuse a stale plan. If a database restore is actually required, use the existing authorized control-database recovery procedure with its identical prerequisites and preimage verification; an ordinary endpoint correction is a new declaration, not an automatic whole-database rollback. No direct API/provider command is a fallback.
