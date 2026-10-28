# Local controller prerequisite inspection

On the selected Linux controller, the responsible operator can run the existing executable locally:

```text
vsk-labs doctor controller-prerequisites --expected-machine-id <exact-recorded-machine-id> --output json
```

Compare the expected machine ID with the already selected physical target before invoking it. This command never connects to another machine. Run it as the existing individual controller operator; do not add broad sudo authority to improve missing results. Non-Linux platforms return an explicit unsupported result. A missing, invalid or mismatched identity blocks before controller metadata collection.

The finite collector reports the canonical `vsk-labs` account UID/GID; metadata for the canonical profile, executable, state/runtime directories and systemd unit; and presence of native authority enrollment and credential-draft directory. It reads neither credential contents nor private keys. It runs no command, opens no SQLite database, controls no service and writes no files. Missing, unsafe and unreadable paths remain distinct. Canonical profile, unit and executable hashes identify their observed bytes; the result is not an applied declaration or gate evidence.

Public TLS facts are collected only when the canonical protected profile enables remote read and selects `/etc/vsk-labs/control/tls/server.crt`. Other certificate paths are reported unsafe rather than opened. The certificate fact contains the public leaf-DER SHA-256 digest, DNS names and expiration. This finite path is an inspection contract, not permission to create/move certificates or change an existing listener. Disabled remote read remains disabled. Certificate validity, trust and browser identity still need their owning verification.

Keep this JSON in private operational records. A partial result does not qualify service readiness: unit presence does not prove an active invocation, custody policy presence does not qualify its authority or any loaded credential, and a matching machine ID grants no host admission. Existing `server prepare` remains an inert renderer; role installation and control handoff still require their exact current baseline, target/profile inputs, authorization, plan, Slack acknowledgement and verification. Handoff additionally needs fresh foreground/writer/socket/unit identities and bounded recovery inputs. Protected native enrollment and credential activation, artifact installation/update, account/path changes and any listener change remain separately authorized actions.

For a remote operator, use only an actually enrolled constrained API transport for commands that support that transport. This local collector does not invent a remote SSH command or install enrollment. If no such route exists, the selected operator runs the command on their local controller console and supplies the sanitized result; do not substitute an ad-hoc shell probe. Manual and automated use have identical identity, path, privacy and no-mutation boundaries. No emergency changes or reconciliation revision are needed because this command makes no changes.
