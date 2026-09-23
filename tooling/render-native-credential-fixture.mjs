#!/usr/bin/env node
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const role = path.join(root, 'ansible/roles/native_credential_authority/templates');
// Updated only after exact-byte parity against Ansible-rendered fixture files.
const roleDigests = {
  'tasks/main.yml': 'a5efb1aaf1832a8bc0be5d67abff6f9ab6f6aa22a7cdd8c821b296133c6c5e39',
  'templates/probe-policy.json.j2': 'fcb4cc424da4862072c7354b5f5c2a897b254d3558c71b6087c6de5d5f634fde',
  'templates/managed-units.rules.j2': 'c0f881aa360252ec19df5b50a3a358050fd1308c2725cafc320df5dc5e8b8e80',
  'templates/native-denied-probe.sudoers.j2': '3ba167bf2fff861b64b1dd1a6150df35f14db1ef6e76ddb59db47dafd47d0b17',
};
const unit = 'vsk-native-allow.service';
const name = 'credential-a';
const binary = '/usr/local/bin/vsk-labs';
const probes = [20144, 20145].map((uid) => ({ unit_name: unit, credential_name: name, uid, gid: uid }));

function ansibleJSON(value) {
  if (Array.isArray(value)) return '[' + value.map(ansibleJSON).join(', ') + ']';
  if (value && typeof value === 'object') {
    return '{' + Object.entries(value).map(([key, item]) => JSON.stringify(key) + ': ' + ansibleJSON(item)).join(', ') + '}';
  }
  return JSON.stringify(value);
}

export function renderNativeFixture(machineID) {
  if (!/^[0-9a-f]{32}$/.test(machineID)) throw new Error('Fixture machine ID is invalid');
  for (const [file, expected] of Object.entries(roleDigests)) {
    const source = readFileSync(path.join(root, 'ansible/roles/native_credential_authority', file));
    if (createHash('sha256').update(source).digest('hex') !== expected) {
      throw new Error('Native authority role changed since fixture parity check');
    }
  }
  const read = (file) => readFileSync(path.join(role, file), 'utf8');
  const source = read('probe-policy.json.j2').trim();
  const expected = "{{ {'version': 1, 'machine_id': native_credential_host_machine_id, 'units': native_credential_enrolled_units, 'probes': native_credential_probe_bindings} | to_json }}";
  if (source !== expected) throw new Error('Probe policy role template changed');
  const policy = ansibleJSON({ version: 1, machine_id: machineID, units: [unit], probes }) + '\n';
  const ruleTemplate = read('managed-units.rules.j2');
  const unitSlot = '{{ native_credential_enrolled_units | to_json }}';
  if (ruleTemplate.split(unitSlot).length !== 2) throw new Error('Polkit role template changed');
  const rule = ruleTemplate.replace(unitSlot, ansibleJSON([unit]));
  const sudoTemplate = read('native-denied-probe.sudoers.j2');
  const binarySlot = '{{ native_credential_binary_path }}';
  if (sudoTemplate.split(binarySlot).length !== 3) throw new Error('Sudoers role template changed');
  const sudoers = sudoTemplate.replaceAll(binarySlot, binary);
  for (const rendered of [policy, rule, sudoers]) {
    if (rendered.includes('{{') || rendered.includes('}}')) throw new Error('Unresolved role template expression');
  }
  return { policy, rule, sudoers };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try {
    const [machineID, dest] = process.argv.slice(2);
    if (process.argv.length !== 4 || !path.isAbsolute(dest)) throw new Error('Fixture arguments are invalid');
    const files = renderNativeFixture(machineID);
    for (const [name, content] of Object.entries(files)) {
      writeFileSync(path.join(dest, name), content, { flag: 'wx', mode: 0o600 });
    }
  } catch (error) {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 1;
  }
}
