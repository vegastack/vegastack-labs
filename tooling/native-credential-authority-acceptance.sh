#!/usr/bin/env bash
set -euo pipefail

# Run only inside a disposable Debian/systemd fixture prepared by the role.
test "${VSK_NATIVE_AUTHORITY_DISPOSABLE:-}" = 1
test "$(id -u)" = 0
test "$(ps -p 1 -o comm= | tr -d ' ')" = systemd
test "$(stat -c '%u:%a' /run/vsk-native-authority-disposable)" = 0:600
test "$(stat -c '%u:%a' /etc/vsk-labs/native-credential-authority.json)" = 0:640
test "$(stat -c '%u:%a' /etc/polkit-1/rules.d/49-vsk-native-credential-restart.rules)" = 0:640
test "$(stat -c '%u:%a' /etc/sudoers.d/49-vsk-native-credential-probe)" = 0:440
/usr/sbin/visudo -c -f /etc/sudoers.d/49-vsk-native-credential-probe >/dev/null

unit=vsk-native-allow.service
other=vsk-native-other.service
name=credential-a
positive_uid="$(id -u vsk-native-positive)"
positive_gid="$(id -g vsk-native-positive)"
denied_uid="$(id -u vsk-native-denied)"
denied_gid="$(id -g vsk-native-denied)"
test "$positive_uid" -gt 0
test "$denied_uid" -gt 0
test "$positive_uid" != "$denied_uid"

tmpdir="$(mktemp -d -p /run vsk-native-accept.XXXXXX)"
chmod 700 "$tmpdir"
cleanup() {
  if test -f "$tmpdir/enrollment.saved"; then mv "$tmpdir/enrollment.saved" /etc/vsk-labs/native-credential-authority.json; fi
  if test -f "$tmpdir/sudoers.saved"; then mv "$tmpdir/sudoers.saved" /etc/sudoers.d/49-vsk-native-credential-probe; fi
  if test -f "$tmpdir/polkit.saved"; then
    mv "$tmpdir/polkit.saved" /etc/polkit-1/rules.d/49-vsk-native-credential-restart.rules
    /usr/bin/systemctl restart polkit.service || true
  fi
  rm -rf -- "$tmpdir"
}
trap cleanup EXIT

expect_denied() {
  if "$@" >"$tmpdir/denied.stdout" 2>"$tmpdir/denied.stderr"; then
    printf 'A forbidden operation succeeded\n' >&2
    exit 1
  fi
}

runuser -u vsk-labs -- /usr/bin/systemctl --system --no-ask-password restart "$unit" >"$tmpdir/restart.stdout" 2>"$tmpdir/restart.stderr"
test ! -s "$tmpdir/restart.stdout"
test ! -s "$tmpdir/restart.stderr"
expect_denied runuser -u vsk-labs -- /usr/bin/systemctl --system --no-ask-password restart "$other"
expect_denied runuser -u vsk-labs -- /usr/bin/systemctl --system --no-ask-password stop "$unit"
expect_denied runuser -u vsk-labs -- /usr/bin/systemctl --system --no-ask-password start "$unit"
expect_denied runuser -u vsk-labs -- /usr/bin/systemctl --system --no-ask-password enable "$unit"
expect_denied runuser -u vsk-labs -- /usr/bin/systemctl --system --no-ask-password daemon-reload
expect_denied runuser -u vsk-labs -- /usr/bin/systemd-run --system --unit=vsk-native-transient-accept /usr/bin/true

pid="$(/usr/bin/systemctl show "$unit" --property=MainPID --value)"
test "$pid" -gt 1
boot_id="$(cat /proc/sys/kernel/random/boot_id)"
start_ticks="$(python3 - "$pid" <<'PY'
import pathlib, sys
data=pathlib.Path('/proc',sys.argv[1],'stat').read_text()
print(data[data.rfind(')')+2:].split()[19])
PY
)"

probe_json() {
  jq -cn --arg unit "$unit" --arg name "$name" --arg boot "$boot_id" \
    --argjson pid "$pid" --argjson ticks "$start_ticks" --argjson uid "$1" --argjson gid "$2" \
    '{unit_name:$unit,credential_name:$name,boot_id:$boot,main_pid:$pid,process_start_ticks:$ticks,uid:$uid,gid:$gid}'
}

probe_json "$positive_uid" "$positive_gid" | runuser -u vsk-labs -- /usr/bin/sudo -n -- /usr/local/bin/vsk-labs __native-credential-access-probe >"$tmpdir/positive.json" 2>"$tmpdir/positive.stderr"
test ! -s "$tmpdir/positive.stderr"
jq -e '.status == "opened" and .inode > 0 and .mode > 0 and .owner_uid >= 0' "$tmpdir/positive.json" >/dev/null
probe_json "$denied_uid" "$denied_gid" | runuser -u vsk-labs -- /usr/bin/sudo -n -- /usr/local/bin/vsk-labs __native-credential-access-probe >"$tmpdir/denied.json" 2>"$tmpdir/probe.stderr"
test ! -s "$tmpdir/probe.stderr"
jq -e '.status == "denied" and (.inode // 0) == 0' "$tmpdir/denied.json" >/dev/null

probe_json 0 "$positive_gid" >"$tmpdir/malformed.json"
expect_denied runuser -u vsk-labs -- /usr/bin/sudo -n -- /usr/local/bin/vsk-labs __native-credential-access-probe extra
test ! -s "$tmpdir/denied.stdout"
wrong_uid=2147483646
if jq -e --argjson uid "$wrong_uid" '.probes[] | select(.uid == $uid)' /etc/vsk-labs/native-credential-authority.json >/dev/null; then
  printf 'Fixture reserved UID is enrolled unexpectedly\n' >&2
  exit 1
fi
probe_json "$wrong_uid" "$positive_gid" >"$tmpdir/wrong-identity.json"
if runuser -u vsk-labs -- /usr/bin/sudo -n -- /usr/local/bin/vsk-labs __native-credential-access-probe <"$tmpdir/wrong-identity.json" >"$tmpdir/denied.stdout" 2>"$tmpdir/denied.stderr"; then
  printf 'Unenrolled UID probe succeeded\n' >&2
  exit 1
fi
test ! -s "$tmpdir/denied.stdout"
if runuser -u vsk-labs -- /usr/bin/sudo -n -- /usr/local/bin/vsk-labs __native-credential-access-probe <"$tmpdir/malformed.json" >"$tmpdir/denied.stdout" 2>"$tmpdir/denied.stderr"; then
  printf 'Root UID probe succeeded\n' >&2
  exit 1
fi
test ! -s "$tmpdir/denied.stdout"

probe_json "$positive_uid" "$positive_gid" >"$tmpdir/positive-request.json"
mv /etc/vsk-labs/native-credential-authority.json "$tmpdir/enrollment.saved"
if runuser -u vsk-labs -- /usr/bin/sudo -n -- /usr/local/bin/vsk-labs __native-credential-access-probe <"$tmpdir/positive-request.json" >"$tmpdir/denied.stdout" 2>"$tmpdir/denied.stderr"; then
  printf 'Missing root enrollment accepted\n' >&2
  exit 1
fi
test ! -s "$tmpdir/denied.stdout"
mv "$tmpdir/enrollment.saved" /etc/vsk-labs/native-credential-authority.json

mv /etc/sudoers.d/49-vsk-native-credential-probe "$tmpdir/sudoers.saved"
if probe_json "$positive_uid" "$positive_gid" | runuser -u vsk-labs -- /usr/bin/sudo -n -- /usr/local/bin/vsk-labs __native-credential-access-probe >"$tmpdir/denied.stdout" 2>"$tmpdir/denied.stderr"; then
  printf 'Missing sudoers rule accepted\n' >&2
  exit 1
fi
test ! -s "$tmpdir/denied.stdout"
mv "$tmpdir/sudoers.saved" /etc/sudoers.d/49-vsk-native-credential-probe

mv /etc/polkit-1/rules.d/49-vsk-native-credential-restart.rules "$tmpdir/polkit.saved"
/usr/bin/systemctl restart polkit.service
expect_denied runuser -u vsk-labs -- /usr/bin/systemctl --system --no-ask-password restart "$unit"
mv "$tmpdir/polkit.saved" /etc/polkit-1/rules.d/49-vsk-native-credential-restart.rules
/usr/bin/systemctl restart polkit.service
runuser -u vsk-labs -- /usr/bin/systemctl --system --no-ask-password restart "$unit" >"$tmpdir/recovered.stdout" 2>"$tmpdir/recovered.stderr"
test ! -s "$tmpdir/recovered.stdout"
test ! -s "$tmpdir/recovered.stderr"

printf 'native credential authority allow/deny matrix passed\n'
