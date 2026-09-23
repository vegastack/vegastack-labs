#!/usr/bin/env bash
set -euo pipefail

# Run only in a freshly created, isolated Debian/systemd VM with synthetic data.
marker=/run/vsk141-native-lifecycle
policy=/etc/vsk-labs/native-credential-authority.json
polkit_rule=/etc/polkit-1/rules.d/00-vsk-native-credential-restart.rules
sudo_rule=/etc/sudoers.d/49-vsk-native-credential-probe
alpha_unit=/etc/systemd/system/vsk141-alpha.service
beta_unit=/etc/systemd/system/vsk141-beta.service
app_binary=/usr/local/bin/vsk-labs
test_binary=/usr/local/libexec/vsk141-native-lifecycle.test
server_test_binary=/usr/local/libexec/vsk141-server.test

fatal() { printf '%s\n' "$*" >&2; exit 1; }
test "${VSK141_DISPOSABLE:-}" = 1 || fatal 'Disposable marker missing'
test "$(id -u)" = 0 || fatal 'Root required for isolated fixture'
test "$(hostname)" = lima-vsk141-disposable || fatal 'Unexpected host'
test "$(ps -p 1 -o comm= | tr -d ' ')" = systemd || fatal 'PID1 systemd required'
test -n "${VSK141_WORKSPACE:-}" && test -d "$VSK141_WORKSPACE/ansible/roles/native_credential_authority" || fatal 'Role workspace missing'
test -f "${VSK141_APP_BINARY:-}" && test -f "${VSK141_TEST_BINARY:-}" && test -f "${VSK141_SERVER_TEST_BINARY:-}" || fatal 'Fixture binaries missing'
for command in ansible-playbook systemd-creds systemctl pkcheck sudo nsenter runuser python3 visudo sha256sum setfacl; do
  command -v "$command" >/dev/null || fatal "Missing disposable prerequisite: $command"
done
for path in "$marker" "$policy" "$polkit_rule" "$sudo_rule" "$alpha_unit" "$beta_unit" "$app_binary" "$test_binary" "$server_test_binary" /etc/vsk-labs; do
  test ! -e "$path" || fatal "Fixture path already exists: $path"
done
for account in vsk-labs vsk141-alpha vsk141-beta vsk141-denied-a vsk141-denied-b; do
  ! getent passwd "$account" >/dev/null || fatal "Fixture account exists: $account"
done
for number in 21141 21142 21143 21144 21145; do
  ! getent passwd "$number" >/dev/null || fatal "Fixture UID exists: $number"
  ! getent group "$number" >/dev/null || fatal "Fixture GID exists: $number"
done
for unit in vsk141-alpha.service vsk141-beta.service; do
  test "$(systemctl show "$unit" --property=LoadState --value)" = not-found || fatal "Fixture unit exists: $unit"
done

umask 077
install -d -o root -g root -m 0755 "$marker"
cleanup() {
  systemctl stop vsk141-alpha.service vsk141-beta.service >/dev/null 2>&1 || true
	rm -f -- "$policy" "$polkit_rule" "$sudo_rule" "$alpha_unit" "$beta_unit" "$app_binary" "$test_binary" "$server_test_binary"
  systemctl daemon-reload >/dev/null 2>&1 || true
  systemctl restart polkit.service >/dev/null 2>&1 || true
  rmdir /etc/vsk-labs >/dev/null 2>&1 || true
  for account in vsk141-denied-b vsk141-denied-a vsk141-beta vsk141-alpha vsk-labs; do
    getent passwd "$account" >/dev/null && userdel "$account" || true
    getent group "$account" >/dev/null && groupdel "$account" || true
  done
  rm -rf -- "$marker"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

useradd -M -u 21141 -U vsk-labs
useradd -M -u 21142 -U vsk141-alpha
useradd -M -u 21143 -U vsk141-beta
useradd -M -u 21144 -U vsk141-denied-a
useradd -M -u 21145 -U vsk141-denied-b
install -d -o root -g root -m 0755 /usr/local/libexec
install -o root -g root -m 0755 "$VSK141_APP_BINARY" "$app_binary"
install -o root -g root -m 0755 "$VSK141_TEST_BINARY" "$test_binary"
install -o root -g root -m 0755 "$VSK141_SERVER_TEST_BINARY" "$server_test_binary"
install -d -o vsk-labs -g vsk-labs -m 0700 "$marker/credential-drafts"
name="$(python3 - <<'PY'
import hashlib
h=hashlib.sha256(b'native-loaded-credential-v1\0consumer-a\0reference-a\0version-a').digest()
print('credential-'+h[:16].hex())
PY
)"
printf 'synthetic-disposable-vsk141\n' >"$marker/plaintext"
systemd-creds encrypt --with-key=host --name="$name" "$marker/plaintext" "$marker/credential-drafts/$name" >/dev/null
rm -f -- "$marker/plaintext"
chown vsk-labs:vsk-labs "$marker/credential-drafts/$name"
chmod 0600 "$marker/credential-drafts/$name"
fingerprint="sha256:$(sha256sum "$marker/credential-drafts/$name" | cut -d ' ' -f 1)"
machine="$(cat /etc/machine-id)"

write_unit() {
  local path="$1" service_user="$2" credential_id="$3" source="$4"
  cat >"$path" <<UNIT
[Unit]
Description=Disposable #141 encrypted credential lifecycle fixture
StartLimitIntervalSec=0
[Service]
User=$service_user
Group=$service_user
LoadCredentialEncrypted=$credential_id:$source
ExecStart=/usr/bin/sleep infinity
UNIT
  chmod 0644 "$path"
}
write_unit "$alpha_unit" vsk141-alpha "$name" "$marker/credential-drafts/$name"
write_unit "$beta_unit" vsk141-beta "$name" "$marker/credential-drafts/$name"
systemctl daemon-reload
systemctl start vsk141-alpha.service vsk141-beta.service

python3 - "$marker/vars.json" "$machine" "$name" <<'PY'
import json,sys
out,machine,name=sys.argv[1:]
units=['vsk141-alpha.service','vsk141-beta.service']
probes=[]
for unit,positive in zip(units,[21142,21143]):
    for uid in [positive,21144,21145]:
        probes.append({'unit_name':unit,'credential_name':name,'uid':uid,'gid':uid})
probes.sort(key=lambda x:(x['unit_name'],x['credential_name'],x['uid'],x['gid']))
with open(out,'w') as file:
    json.dump({'native_credential_enrolled_units':units,'native_credential_probe_bindings':probes,'native_credential_host_machine_id':machine},file)
PY
cat >"$marker/role.yml" <<'YAML'
- hosts: localhost
  connection: local
  gather_facts: false
  roles:
    - native_credential_authority
YAML
ANSIBLE_ROLES_PATH="$VSK141_WORKSPACE/ansible/roles" ansible-playbook -i localhost, -e "@$marker/vars.json" "$marker/role.yml" >"$marker/ansible.out"
systemctl restart polkit.service

runuser -u vsk-labs -- env VSK141_DISPOSABLE=1 VSK141_CIPHERTEXT_ROOT="$marker/credential-drafts" \
  "$server_test_binary" -test.run='^TestDisposableNativeVerifierComposition$' >"$marker/composition.out" 2>&1 || { cat "$marker/composition.out" >&2; fatal 'Qualified server composition failed'; }

run_verifier() {
  local expectation="$1"
  runuser -u vsk-labs -- env VSK141_DISPOSABLE=1 VSK141_EXPECT_DENIAL="$expectation" \
    VSK141_CIPHERTEXT_ROOT="$marker/credential-drafts" VSK141_FINGERPRINT="$fingerprint" VSK141_MACHINE_ID="$machine" \
    "$test_binary" -test.run='^TestDisposableNativeLifecycle$' >"$marker/test.out" 2>&1
}
run_verifier 0 || { cat "$marker/test.out" >&2; fatal 'Real encrypted two-unit lifecycle proof failed'; }
"$test_binary" -test.run='^TestInvocationNamespaceReplacement$' >"$marker/namespace.out" 2>&1 || { cat "$marker/namespace.out" >&2; fatal 'Mount namespace replacement was accepted'; }

write_unit "$beta_unit" vsk141-beta "$name" "$marker/credential-drafts/nonexistent"
systemctl daemon-reload
run_verifier 1 || fatal 'Changed applied source was accepted'
write_unit "$beta_unit" vsk141-beta credential-other "$marker/credential-drafts/$name"
systemctl daemon-reload
run_verifier 1 || fatal 'Changed applied credential ID was accepted'
write_unit "$beta_unit" vsk141-denied-a "$name" "$marker/credential-drafts/$name"
systemctl daemon-reload
run_verifier 1 || fatal 'Changed service UID was accepted'
write_unit "$beta_unit" vsk141-beta "$name" "$marker/credential-drafts/$name"
systemctl daemon-reload
chmod 0644 "$marker/credential-drafts/$name"
run_verifier 1 || fatal 'Broad ciphertext mode was accepted'
chmod 0600 "$marker/credential-drafts/$name"
mv "$policy" "$marker/policy.saved"
run_verifier 1 || fatal 'Missing root authority was accepted'
mv "$marker/policy.saved" "$policy"
run_verifier 0 || { cat "$marker/test.out" >&2; fatal 'Restored exact lifecycle proof failed'; }
install -d -o root -g vsk-labs -m 0770 "$marker/capstone-coordinate"
install -d -o vsk-labs -g vsk-labs -m 0700 "$marker/capstone-ciphertext"
coordinate_capstone() {
  local index request credential root
  for index in 1 2; do
    request="$marker/capstone-coordinate/request-$index"
    for _ in $(seq 1 500); do test -f "$request" && break; sleep 0.02; done
    test -f "$request" || fatal 'Capstone coordinator request timed out'
    mapfile -t values <"$request"
    test "${#values[@]}" = 2 || fatal 'Capstone coordinator request malformed'
    credential="${values[0]}"; root="${values[1]}"
    [[ "$credential" =~ ^credential-[0-9a-f]{32}$ ]] || fatal 'Capstone credential name invalid'
    [[ "$root" =~ ^/var/tmp/vsk135-lifecycle-[A-Za-z0-9]+/credential-drafts$ ]] || fatal 'Capstone ciphertext root invalid'
    test "$(stat -c '%U:%G:%a' "$root")" = root:root:700 || fatal 'Capstone import root metadata invalid'
    install -o vsk-labs -g vsk-labs -m 0600 "$root/$credential" "$marker/capstone-ciphertext/$credential"
    write_unit "$alpha_unit" vsk141-alpha "$credential" "$marker/capstone-ciphertext/$credential"
    write_unit "$beta_unit" vsk141-beta "$credential" "$marker/capstone-ciphertext/$credential"
    systemctl daemon-reload
    python3 - "$marker/capstone-policy" "$machine" "$credential" <<'PY'
import json,sys
out,machine,name=sys.argv[1:]
units=['vsk141-alpha.service','vsk141-beta.service']
probes=[]
for unit,positive in zip(units,[21142,21143]):
    for uid in [positive,21144,21145]:
        probes.append({'unit_name':unit,'credential_name':name,'uid':uid,'gid':uid})
probes.sort(key=lambda x:(x['unit_name'],x['credential_name'],x['uid'],x['gid']))
with open(out,'w') as file: json.dump({'version':1,'machine_id':machine,'units':units,'probes':probes},file)
PY
    install -o root -g vsk-labs -m 0640 "$marker/capstone-policy" "$policy"
    touch "$marker/capstone-coordinate/ready-$index"
    chown vsk-labs:vsk-labs "$marker/capstone-coordinate/ready-$index"
  done
}
coordinate_capstone & coordinator_pid=$!
VSK135_LIFECYCLE_ACCEPTANCE=1 VSK135_COORDINATOR="$marker/capstone-coordinate" VSK135_NATIVE_ROOT="$marker/capstone-ciphertext" "$server_test_binary" -test.run='^TestFullCredentialLifecycleAcceptance$' >"$marker/capstone.out" 2>&1 || { cat "$marker/capstone.out" >&2; cat "$marker/capstone-coordinate/debug" >&2 2>/dev/null || true; kill "$coordinator_pid" 2>/dev/null || true; fatal 'Integrated full lifecycle capstone failed'; }
wait "$coordinator_pid"
if grep -Fq 'synthetic-private-lifecycle-canary-135' "$marker/capstone.out" "$marker/capstone-coordinate/verify-request.json" "$marker/capstone-coordinate/verify-response.json"; then
  fatal 'Lifecycle canary escaped captured process or test output'
fi
printf 'native encrypted credential lifecycle disposable matrix passed\n'
