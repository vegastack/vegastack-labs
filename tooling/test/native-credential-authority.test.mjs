import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import vm from 'node:vm';

const root = new URL('../../', import.meta.url);
const file = (path) => readFileSync(new URL(path, root), 'utf8');

test('native authority role has exact enrollment and no broad systemd grant', () => {
  const tasks = file('ansible/roles/native_credential_authority/tasks/main.yml');
  const policy = file('ansible/roles/native_credential_authority/templates/managed-units.rules.j2');
  const sudoers = file('ansible/roles/native_credential_authority/templates/native-denied-probe.sudoers.j2');
  assert.match(tasks, /native_credential_enrolled_units/);
  assert.match(tasks, /visudo -c/);
  assert.match(policy, /org\.freedesktop\.systemd1\.manage-units/);
  assert.match(policy, /action\.lookup\('verb'\) === 'restart'/);
  assert.match(policy, /action\.lookup\('unit'\)/);
  assert.doesNotMatch(policy, /manage-unit-files|StartTransientUnit|\*\.service/);
  assert.match(sudoers, /__native-credential-access-probe/);
  assert.doesNotMatch(sudoers, /NOPASSWD:\s*ALL|\*|SETENV/);
});

test('rendered polkit rule grants only the enrolled restart tuple', () => {
  const template = file('ansible/roles/native_credential_authority/templates/managed-units.rules.j2');
  const source = template.replace('{{ native_credential_enrolled_units | to_json }}', '["alpha.service"]');
  let rule;
  const polkit = { Result: { YES: 'yes', NOT_HANDLED: 'not-handled' }, addRule: (value) => { rule = value; } };
  vm.runInNewContext(source, { polkit }, { timeout: 1000 });
  assert.equal(typeof rule, 'function');
  const decision = (user, actionID, unit, verb) => rule(
    { id: actionID, lookup: (key) => ({ unit, verb })[key] },
    { user },
  );
  const action = 'org.freedesktop.systemd1.manage-units';
  assert.equal(decision('vsk-labs', action, 'alpha.service', 'restart'), 'yes');
  for (const [user, id, unit, verb] of [
    ['other', action, 'alpha.service', 'restart'],
    ['vsk-labs', action, 'beta.service', 'restart'],
    ['vsk-labs', action, 'alpha.service', 'start'],
    ['vsk-labs', action, 'alpha.service', 'stop'],
    ['vsk-labs', 'org.freedesktop.systemd1.manage-unit-files', 'alpha.service', 'restart'],
    ['vsk-labs', 'org.freedesktop.systemd1.reload-daemon', 'alpha.service', 'restart'],
  ]) assert.equal(decision(user, id, unit, verb), 'not-handled');
});
