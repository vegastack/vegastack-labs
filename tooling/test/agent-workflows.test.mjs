import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, writeFile, mkdir, cp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { buildArtifacts, checkArtifacts, selectInstructions, validateInvocation } from '../agent-workflows.mjs';

const root = new URL('../../', import.meta.url);
test('nine canonical workflows produce identical human and Claude instructions; Hermes is read/plan only', async () => {
  const artifacts = await buildArtifacts(root);
  const skills = [...artifacts.keys()].filter(path => path.startsWith('.claude/skills/'));
  assert.equal(skills.length, 9);
  for (const path of skills) {
    const name = path.split('/')[2];
    const canonical = await readFile(new URL(`.agents/skills/${name}/SKILL.md`, root), 'utf8');
    assert.equal(artifacts.get(path), canonical);
    assert.equal(artifacts.get(`docs/runbooks/${name}.md`), canonical);
  }
  const hermes = JSON.parse(artifacts.get('docs/generated/hermes-read-plan.json'));
  assert.ok(hermes.commands.length > 0);
  assert.ok(hermes.commands.every(command => command.risk === 'read-only'));
  assert.ok(hermes.commands.every(command => !/^(apply|credential|approval|node discover|network .*observe)/.test(command.path.join(' '))));
  assert.equal(hermes.nativeAcceptance, 'not-run');
});
test('drift check detects changed generated content', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'vsk-workflows-'));
  const artifacts = new Map([['copy.md', 'reviewed\n']]);
  await writeFile(join(dir, 'copy.md'), 'injected\n');
  await assert.rejects(checkArtifacts(dir, artifacts), /copy.md/);
});
test('canonical instruction precedence is explicit and inherited for nested workspaces', () => {
  assert.deepEqual(selectInstructions('codex', ['AGENTS.md','nested/AGENTS.md','CLAUDE.md']), ['AGENTS.md','nested/AGENTS.md']);
  assert.deepEqual(selectInstructions('claude', ['AGENTS.md','CLAUDE.md']), ['CLAUDE.md','AGENTS.md']);
  assert.deepEqual(selectInstructions('hermes', ['AGENTS.md','CLAUDE.md','.hermes.md']), ['.hermes.md']);
  assert.deepEqual(selectInstructions('hermes', ['AGENTS.md','CLAUDE.md']), ['AGENTS.md']);
});
test('unavailable commands, unknown flags and missing required flags are rejected', () => {
  const registry = [{path:['status'],availability:'available',flags:[{name:'--config',kind:'value',required:true}]}];
  assert.throws(() => validateInvocation(['apply'], registry), /unavailable/);
  assert.throws(() => validateInvocation(['status'], registry), /required/);
  assert.throws(() => validateInvocation(['status','--config','x','--reveal'], registry), /flag/);
  assert.equal(validateInvocation(['status','--config','<protected-profile>'], registry).path[0], 'status');
});

test('missing safety boundaries and injected secret/provider commands fail workflow validation', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'vsk-workflow-hostile-'));
  try {
    await cp(new URL('.agents', root), join(dir, '.agents'), {recursive:true});
    await mkdir(join(dir,'schemas/v1'), {recursive:true});
    await cp(new URL('schemas/v1/command-registry.json', root), join(dir,'schemas/v1/command-registry.json'));
    const skill = join(dir,'.agents/skills/vegastack-labs-inspect/SKILL.md');
    const text = await readFile(skill,'utf8');
    for (const boundary of ['Never reveal secrets','Never self-approve','Never call providers directly','protected targets','human acknowledgement']) {
      await writeFile(skill,text.replaceAll(boundary,'removed-boundary'));
      await assert.rejects(buildArtifacts(dir), /safety boundary/);
    }
    for (const command of [['credential','reveal'],['aws','ec2','terminate-instances'],['apply','--self-approve']]) {
      await writeFile(skill,`${text}\n<!-- vsk-command: ${JSON.stringify(command)} -->\n`);
      await assert.rejects(buildArtifacts(dir), /unavailable|required|flag/);
    }
  } finally { await rm(dir,{recursive:true,force:true}); }
});
