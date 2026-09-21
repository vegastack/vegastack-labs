#!/usr/bin/env bash
set -euo pipefail

# Run only inside a disposable Debian/systemd fixture prepared by the role.
test "${VSK_NATIVE_AUTHORITY_DISPOSABLE:-}" = 1
test "$(id -u)" = 0
test "$(ps -p 1 -o comm= | tr -d ' ')" = systemd
test "$(stat -c '%u:%a' /run/vsk-native-authority-disposable)" = 0:600
test "$(stat -c '%u:%a' /etc/vsk-labs/native-credential-authority.json)" = 0:640
test "$(stat -c '%u:%a' /etc/polkit-1/rules.d/00-vsk-native-credential-restart.rules)" = 0:640
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

tmpdir="$(mktemp -d -p "${VSK143_FIXTURE_TMP:-/run}" vsk-native-accept.XXXXXX)"
chmod 700 "$tmpdir"
cleanup() {
  rm -f /etc/polkit-1/rules.d/90-vsk-native-permissive-fixture.rules /etc/polkit-1/rules.d/00-aaa-vsk-native-permissive-fixture.rules /etc/sudoers.d/00-vsk-native-broad-fixture
  if test -f "$tmpdir/enrollment.saved"; then mv "$tmpdir/enrollment.saved" /etc/vsk-labs/native-credential-authority.json; fi
  if test -f "$tmpdir/sudoers.saved"; then mv "$tmpdir/sudoers.saved" /etc/sudoers.d/49-vsk-native-credential-probe; fi
  if test -f "$tmpdir/polkit.saved"; then
    mv "$tmpdir/polkit.saved" /etc/polkit-1/rules.d/00-vsk-native-credential-restart.rules
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

policy_check() {
  # The inner shell expands its own PID and UID.
  # shellcheck disable=SC2016
  runuser -u vsk-labs -- /bin/sh -c '
    start=$(cut -d " " -f 22 /proc/$$/stat)
    printf "{\"unit_name\":\"%s\",\"subject\":\"%s,%s,%s\"}" "$1" "$$" "$start" "$(id -u)" |
      /usr/bin/sudo -n -- /usr/local/bin/vsk-labs __native-credential-policy-check
  ' sh "$1"
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
policy_check "$unit" >"$tmpdir/policy.stdout" 2>"$tmpdir/policy.stderr"
test ! -s "$tmpdir/policy.stdout"
test ! -s "$tmpdir/policy.stderr"
expect_denied policy_check "$other"
test ! -s "$tmpdir/denied.stdout"

# A later permissive rule cannot bypass the exact NO; an earlier one must
# disqualify the trusted effective-policy query before any operation.
cat >/etc/polkit-1/rules.d/90-vsk-native-permissive-fixture.rules <<'RULE'
polkit.addRule(function(action, subject) {
  if (subject.user === 'vsk-labs' && action.id === 'org.freedesktop.systemd1.manage-units') return polkit.Result.YES;
  return polkit.Result.NOT_HANDLED;
});
RULE
chown root:polkitd /etc/polkit-1/rules.d/90-vsk-native-permissive-fixture.rules
chmod 0640 /etc/polkit-1/rules.d/90-vsk-native-permissive-fixture.rules
/usr/bin/systemctl restart polkit.service
policy_check "$unit" >"$tmpdir/policy.stdout" 2>"$tmpdir/policy.stderr"
mv /etc/polkit-1/rules.d/90-vsk-native-permissive-fixture.rules /etc/polkit-1/rules.d/00-aaa-vsk-native-permissive-fixture.rules
/usr/bin/systemctl restart polkit.service
expect_denied policy_check "$unit"
test ! -s "$tmpdir/denied.stdout"
rm /etc/polkit-1/rules.d/00-aaa-vsk-native-permissive-fixture.rules
/usr/bin/systemctl restart polkit.service

printf 'vsk-labs ALL=(root) NOPASSWD: ALL\n' >/etc/sudoers.d/00-vsk-native-broad-fixture
chmod 0440 /etc/sudoers.d/00-vsk-native-broad-fixture
/usr/sbin/visudo -c -f /etc/sudoers.d/00-vsk-native-broad-fixture >/dev/null
runuser -u vsk-labs -- /usr/bin/sudo -n -l -- /usr/bin/true >"$tmpdir/broad.stdout"
rm /etc/sudoers.d/00-vsk-native-broad-fixture
expect_denied runuser -u vsk-labs -- /usr/bin/sudo -n -l -- /usr/bin/true

pid="$(/usr/bin/systemctl show "$unit" --property=MainPID --value)"
test "$pid" -gt 1
if test ! -f "/proc/$pid/root/run/credentials/$unit/$name"; then
  printf 'Real systemd LoadCredential path is absent in the target process; native acceptance cannot pass\n' >&2
  exit 1
fi
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

mv /etc/polkit-1/rules.d/00-vsk-native-credential-restart.rules "$tmpdir/polkit.saved"
/usr/bin/systemctl restart polkit.service
expect_denied runuser -u vsk-labs -- /usr/bin/systemctl --system --no-ask-password restart "$unit"
mv "$tmpdir/polkit.saved" /etc/polkit-1/rules.d/00-vsk-native-credential-restart.rules
/usr/bin/systemctl restart polkit.service
runuser -u vsk-labs -- /usr/bin/systemctl --system --no-ask-password restart "$unit" >"$tmpdir/recovered.stdout" 2>"$tmpdir/recovered.stderr"
test ! -s "$tmpdir/recovered.stdout"
test ! -s "$tmpdir/recovered.stderr"

printf 'native credential authority allow/deny matrix passed\n'
