# Host admission evidence

Issue [#229](https://github.com/vegastack/vegastack-labs/issues/229) connects the existing host checks to the existing gate API. The server reads its own SQLite records; checking a gate does not connect to a machine or change its configuration.

## What the two decisions mean

- `host.hardening-baseline`: the exact registered machine has current applicable baseline checks and the required native profile qualification.
- `host.role-admission`: the machine also has current checks for its intended installed role, storage and recovery prerequisites.

Registration alone passes neither decision. A passed baseline permits the separately authorized role installation path; role admission is checked after installation and recollection. This avoids requiring an installed role before the role can be installed. The preparatory `host` role never qualifies a workload role.

The existing executable, plan, human acknowledgement, action receipt and server database remain the only operational path. No extra service runs these checks. A negative decision blocks new admission; it does not stop existing services, delete data or trigger automatic repair.

## Evidence the server checks

The server resolves one current host snapshot and verifies the complete stored action results against their successful execution receipts. It binds the machine identity and pinned SSH target, exact OS/version/architecture, selected profile, role, declaration and recovery epoch. A digest supplied by a caller, a count of successful checks or a manually uploaded fixture is insufficient.

| Requirement | Existing producer |
|---|---|
| Accounts and remote access | Exact account policy and the complete allowed/denied SSH probe sequence from #225 |
| Host firewall | Declared host paths and their allowed/denied probes from #225 |
| Container firewall | The container policy and actual probes after the role installs containers; absence before installation does not mean a passed container check |
| Fail2ban, audit, AppArmor, updates, time, resources and kernel settings | Bounded baseline observations from #226, with native qualification where required |
| Control-role file integrity | The selected AIDE scope and approved current reference |
| Encrypted volumes and recovery | Each declared volume's current mapping receipt and independent custodian recovery receipt from #226 |
| Installed role | The finite role measurements owned by #230 |
| Native behavior | Applied qualification for the exact profile and stage, owned by #228 |
| Physical prerequisites | Actual applicable capacity, inspection, thermal and power evidence; ordinary resource observations do not prove these facts |

Administrator confirmation proves the named machine and independent console access. It cannot replace automated checks. A qualified virtual fixture does not prove a physical machine's thermal or power behavior. Phase 5 backup encryption does not prove that a host volume is encrypted.

## Freshness and invalidation

Mandatory host evidence has a maximum age of 86400 seconds. Recollect daily and immediately after a relevant change. The existing volume/recovery receipt reader has a stricter ten-minute limit, which still applies.

Changes to identity, SSH binding, OS, role, profile, relevant declaration or recovery epoch invalidate the corresponding evidence immediately. An unrelated database write cannot make stale evidence current or invalidate an otherwise unchanged host binding. The newest failed or partial observation blocks use of an older success. Missing, unsupported, expired, future-dated or revoked proof cannot pass.

Native qualification and per-machine observations are separate. Baseline qualification is used for baseline readiness; role qualification is additionally required for admission. Missing role qualification does not erase valid baseline qualification. An overall development report cannot replace the applied records.

## Operator procedure

1. Select the exact registered host and use an identity with current gate-read and host-read permission. Resolve its operational eligibility before any separately authorized machine operation. Nodes04/05 remain absolutely excluded, including reads and indirect effects.
2. Use the existing gate check command with the protected server profile, exact gate ID and host ID:

   ```text
   vsk-labs gate check --config <protected-server-profile> --gate-id host.hardening-baseline --subject-id <host-id> --output json
   vsk-labs gate check --config <protected-server-profile> --gate-id host.role-admission --subject-id <host-id> --output json
   ```

3. Read the outcome and bounded reason code. A control denial names the control, for example `host-control-missing:host.ssh-effective` or `host-control-failed:linux.fail2ban-sshd`; missing native qualification names its stage. Missing producer, native qualification or prerequisite evidence remains a blocker. Do not insert a synthetic success or treat registration as admission.
4. If a new observation or configuration change is needed, prepare its existing exact action plan. Review the targets, current authorization, human acknowledgement and recovery prerequisites before executing within separately granted infrastructure scope.
5. After role installation or another relevant change, recollect the affected baseline and role checks and repeat the same gate check. Admission-dependent execution must recheck the current binding before reserving the action.

The existing API also accepts `GET /api/v1/gates?subjectId=<host-id>` and `GET /api/v1/gates/<gate-id>?subjectId=<host-id>`. The host-specific views use the same evaluator as `POST /api/v1/gates/<gate-id>/check`. Omitting the subject keeps the existing unbound overview; it cannot establish a host admission result.

Humans and agents use the same commands and server authority. A gate result is a read decision, not permission to deploy or an acknowledgement of a mutation. There is no automatic rollback associated with reading it; recovery uses the separately approved action and its own tested recovery procedure.

## Delivery limits

Synthetic positive and negative tests prove the software evaluator and API composition. They do not qualify a native Debian profile, a physical host, fleet onboarding or workload placement. Native qualification remains #228, installed role producers remain #230, and the broader operator workflow remains #239. Mac/iMac implementation is deferred within v1; Ubuntu is unsupported by this Linux admission implementation. Full Phase 6/v1 acceptance remains separate.
