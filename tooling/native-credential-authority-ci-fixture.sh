#!/usr/bin/env bash
set -Eeuo pipefail
trap 'status=$?; printf "Native fixture failed at line %s (status %s)\n" "$LINENO" "$status" >&2' ERR

# Root-only, disposable-host fixture. The second invocation cleans up after
# a failed or cancelled acceptance step. No inventory host is an allowed target.
marker=/run/vsk143-native-authority-fixture
unit_allow=/etc/systemd/system/vsk-native-allow.service
unit_other=/etc/systemd/system/vsk-native-other.service
policy=/etc/vsk-labs/native-credential-authority.json
polkit_rule=/etc/polkit-1/rules.d/00-vsk-native-credential-restart.rules
sudo_rule=/etc/sudoers.d/49-vsk-native-credential-probe
binary=/usr/local/bin/vsk-labs

fatal() { printf '%s\n' "$*" >&2; exit 1; }
check_host() {
  test "$(id -u)" = 0 || fatal 'Native fixture requires root'
  case "$(hostname)" in vsk-node-01|vsk-node-06) ;; *) fatal 'Native fixture refuses unapproved host' ;; esac
  test "$(ps -p 1 -o comm= | tr -d ' ')" = systemd || fatal 'Native fixture requires PID1 systemd'
  [[ "${VSK143_RUN_ID:-}" =~ ^[0-9]+$ ]] || fatal 'Native fixture run ID is invalid'
  [[ "${VSK143_SHA:-}" =~ ^[0-9a-f]{40}$ ]] || fatal 'Native fixture commit is invalid'
}
clean_fixture() {
  test ! -e "$marker" && return 0
  test "$(stat -c '%u:%a' "$marker")" = 0:700 || fatal 'Native fixture marker metadata changed; refusing cleanup'
  test "$(cat "$marker/identity")" = "$VSK143_RUN_ID $VSK143_SHA" || fatal 'Native fixture marker belongs to another run'
  systemctl stop vsk-native-allow.service vsk-native-other.service >/dev/null 2>&1 || true
  rm -f -- "$unit_allow" "$unit_other" "$policy" "$polkit_rule" "$sudo_rule" "$binary" /run/vsk-native-authority-disposable
  rm -f -- /etc/polkit-1/rules.d/90-vsk-native-permissive-fixture.rules /etc/polkit-1/rules.d/00-aaa-vsk-native-permissive-fixture.rules /etc/sudoers.d/00-vsk-native-broad-fixture
  systemctl daemon-reload
  systemctl restart polkit.service
  if test -d /etc/vsk-labs; then rmdir /etc/vsk-labs; fi
  for account in vsk-native-denied vsk-native-positive vsk-labs; do
    if getent passwd "$account" >/dev/null; then userdel "$account"; fi
    if getent group "$account" >/dev/null; then groupdel "$account"; fi
  done
  rm -rf -- "$marker"
}
check_host
if test "${1:-}" = --cleanup; then clean_fixture; exit 0; fi
test $# = 0 || fatal 'Unexpected fixture argument'
test "${VSK_NATIVE_AUTHORITY_DISPOSABLE:-}" = 1 || fatal 'Disposable fixture marker missing'
test "$(git -c "safe.directory=$VSK143_WORKSPACE" -C "$VSK143_WORKSPACE" rev-parse HEAD)" = "$VSK143_SHA" || fatal 'Checkout SHA differs from requested fixture SHA'
test "$(git -c "safe.directory=$VSK143_WORKSPACE" -C "$VSK143_WORKSPACE" status --porcelain)" = '' || fatal 'Checkout is not clean'
for command in git systemctl pkcheck sudo nsenter jq python3 useradd userdel groupdel node visudo; do
  command -v "$command" >/dev/null || fatal "Missing fixture prerequisite: $command"
done
test "$(stat -c '%u:%a' "$VSK143_BINARY")" = "$(id -u "${SUDO_USER:-root}"):755" || fatal 'Built fixture binary metadata is unexpected'
for path in "$marker" "$unit_allow" "$unit_other" "$policy" "$polkit_rule" "$sudo_rule" "$binary" /etc/vsk-labs /run/vsk-native-authority-disposable /etc/polkit-1/rules.d/90-vsk-native-permissive-fixture.rules /etc/polkit-1/rules.d/00-aaa-vsk-native-permissive-fixture.rules /etc/sudoers.d/00-vsk-native-broad-fixture; do
  test ! -e "$path" || fatal "Fixture path already exists: $path"
done
for account in vsk-labs vsk-native-positive vsk-native-denied; do
  getent passwd "$account" >/dev/null && fatal "Fixture account exists: $account"
  getent group "$account" >/dev/null && fatal "Fixture group exists: $account"
done
getent group polkitd >/dev/null || fatal 'Missing polkitd group'
for uid in 20143 20144 20145; do
  getent passwd "$uid" >/dev/null && fatal "Fixture UID exists: $uid"
  getent group "$uid" >/dev/null && fatal "Fixture GID exists: $uid"
done
systemctl show vsk-native-allow.service --property=LoadState --value | grep -qx not-found || fatal 'Fixture allowed unit already known'
systemctl show vsk-native-other.service --property=LoadState --value | grep -qx not-found || fatal 'Fixture other unit already known'

umask 077
mkdir -m 0700 "$marker"
printf '%s %s\n' "$VSK143_RUN_ID" "$VSK143_SHA" >"$marker/identity"
trap clean_fixture EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
useradd -M -u 20143 -U vsk-labs
useradd -M -u 20144 -U vsk-native-positive
useradd -M -u 20145 -U vsk-native-denied
install -o root -g root -m 0755 "$VSK143_BINARY" "$binary"
printf 'synthetic-only-vsk143\n' >"$marker/credential-a"
chmod 0600 "$marker/credential-a"
touch /run/vsk-native-authority-disposable
chmod 0600 /run/vsk-native-authority-disposable
cat >"$unit_allow" <<UNIT
[Unit]
Description=Disposable #143 native credential allowed fixture
[Service]
User=vsk-native-positive
LoadCredential=credential-a:$marker/credential-a
ExecStart=/usr/bin/sleep infinity
UNIT
cat >"$unit_other" <<'UNIT'
[Unit]
Description=Disposable #143 native credential other fixture
[Service]
ExecStart=/usr/bin/sleep infinity
UNIT
chmod 0644 "$unit_allow" "$unit_other"
systemctl daemon-reload
systemctl start vsk-native-allow.service vsk-native-other.service
machine_id="$(cat /etc/machine-id)"
node "$VSK143_WORKSPACE/tooling/render-native-credential-fixture.mjs" "$machine_id" "$marker"
install -d -o root -g vsk-labs -m 0750 /etc/vsk-labs
install -o root -g vsk-labs -m 0640 "$marker/policy" "$policy"
install -o root -g polkitd -m 0640 "$marker/rule" "$polkit_rule"
install -o root -g root -m 0440 "$marker/sudoers" "$sudo_rule"
test "$(stat -c '%U:%G:%a' /etc/vsk-labs)" = root:vsk-labs:750
test "$(stat -c '%U:%G:%a' "$policy")" = root:vsk-labs:640
test "$(stat -c '%U:%G:%a' "$polkit_rule")" = root:polkitd:640
test "$(stat -c '%U:%G:%a' "$sudo_rule")" = root:root:440
systemctl restart polkit.service
node --check <"$polkit_rule"
visudo -c -f "$sudo_rule" >/dev/null
VSK_NATIVE_AUTHORITY_DISPOSABLE=1 VSK143_FIXTURE_TMP="$marker" bash "$VSK143_WORKSPACE/tooling/native-credential-authority-acceptance.sh"
printf 'native credential authority real disposable-systemd matrix passed at %s\n' "$VSK143_SHA"
