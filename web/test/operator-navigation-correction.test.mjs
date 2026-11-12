import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
const read = name => readFile(new URL(`../components/${name}.tsx`, import.meta.url), 'utf8');
test('known operation inspection does not prepare another execution', async () => {
  const source = await read('changes-workspace');
  assert.match(source, /Inspect existing run/);
  const handler = source.match(/function inspectRun\([\s\S]*?\n  \}/)?.[0] ?? '';
  assert.match(handler, /handlePattern\.test/);
  assert.match(handler, /setRunId/);
  assert.doesNotMatch(handler, /mutate|execute|setExecutionKey\([^n]/);
});
test('readiness, backup and audit screens can refresh successful reads', async () => {
  for (const [name, label] of [['gates-view','Refresh Gates'],['backup-recovery-view','Refresh Backups'],['audit-view','Refresh Audit']]) {
    assert.match(await read(name), new RegExp(label));
  }
});
test('node browsing separates advanced changes from registered host inspection', async () => {
  const source = await read('host-lifecycle');
  assert.match(source, /<details[\s\S]*Add or prepare a node/);
  assert.match(source, /<details[\s\S]*Advanced host maintenance/);
  assert.doesNotMatch(await read('nodes-view'), /until its owning phase/);
});
test('empty provider configuration is explicit and operation times use the shared display formatter', async () => {
  assert.match(await read('providers-view'), /No provider capabilities visible/);
  for (const file of ['approval-status', 'run-progress', 'plan-review']) assert.match(await read(file), /formatConsoleTime\(/);
});
