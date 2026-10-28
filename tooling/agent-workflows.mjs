import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { dirname, resolve, join } from 'node:path';
import { fileURLToPath } from 'node:url';

export const names = ['inspect', 'manage-users', 'manage-devices', 'manage-nodes', 'manage-services', 'manage-network', 'backup-restore', 'maintenance', 'incident-response'].map(name => `vegastack-labs-${name}`);
const rootPath = root => root instanceof URL ? fileURLToPath(root) : resolve(root);
const digest = text => `sha256:${createHash('sha256').update(text).digest('hex')}`;

// A contract fixture for the documented precedence, not a vendor runtime probe.
export function selectInstructions(tool, paths) {
  if (tool === 'codex') return paths.filter(path => /(^|\/)AGENTS\.md$/.test(path));
  if (tool === 'claude') return paths.includes('CLAUDE.md') ? ['CLAUDE.md', ...(paths.includes('AGENTS.md') ? ['AGENTS.md'] : [])] : [];
  if (tool === 'hermes') return ['.hermes.md', 'AGENTS.md', 'CLAUDE.md'].filter(path => paths.includes(path)).slice(0, 1);
  throw new Error('unsupported instruction consumer');
}

export function validateInvocation(args, commands) {
  const command = commands.filter(command => command.availability === 'available' && command.path.every((part, i) => args[i] === part)).sort((a,b) => b.path.length-a.path.length)[0];
  if (!command) throw new Error('unavailable command in canonical workflow');
  const flags = new Map(command.flags.map(flag => [flag.name, flag]));
  const seen = new Set();
  for (let index = command.path.length; index < args.length; index++) {
    const flag = flags.get(args[index]);
    if (!flag || seen.has(flag.name) && !flag.repeatable) throw new Error('unknown or duplicate workflow flag');
    seen.add(flag.name);
    if (flag.kind === 'value') {
      const value = args[++index];
      if (!value || value.startsWith('--') || flag.enum?.length && !flag.enum.includes(value)) throw new Error('invalid workflow flag value');
    }
  }
  if (command.flags.some(flag => flag.required && !seen.has(flag.name))) throw new Error('missing required workflow flag');
  return command;
}

export async function buildArtifacts(root) {
  const base = rootPath(root);
  const registry = JSON.parse(await readFile(join(base, 'schemas/v1/command-registry.json'), 'utf8'));
  const artifacts = new Map();
  const inventory = [];
  const hermes = new Map();
  const required = ['## Prerequisites', '## Commands', '## Approval', '## Verification', '## Recovery', '## Boundaries'];
  for (const name of names) {
    const canonical = `.agents/skills/${name}/SKILL.md`;
    const text = await readFile(join(base, canonical), 'utf8');
    for (const heading of required) if (!text.includes(heading)) throw new Error(`${canonical}: missing ${heading}`);
    for (const boundary of ['Never reveal secrets', 'Never self-approve', 'Never call providers directly', 'protected targets', 'human acknowledgement']) {
      if (!text.includes(boundary)) throw new Error(`${canonical}: missing safety boundary ${boundary}`);
    }
    const matches = [...text.matchAll(/<!-- vsk-command: (\[[^\n]+\]) -->/g)];
    if (!matches.length) throw new Error(`${canonical}: missing command contract`);
    for (const [, encoded] of matches) {
      const args = JSON.parse(encoded);
      const command = validateInvocation(args, registry.commands);
      if (!text.includes(`vsk-labs ${args.join(' ')}`)) throw new Error(`${canonical}: command prose differs from contract`);
      // Hermes receives no apply, credential, discovery, provider refresh or authoring route.
      if (command.risk === 'read-only' && /^(status|server status|gate (list|inspect)|backup status|audit (checkpoints|verify)|node (inspect|observation inspect)|service (list|show)|run inspect|plan)$/.test(command.path.join(' '))) {
        hermes.set(command.path.join(' '), {path: command.path, risk: command.risk, invocation: args});
      }
    }
    artifacts.set(`.claude/skills/${name}/SKILL.md`, text);
    artifacts.set(`docs/runbooks/${name}.md`, text);
    inventory.push({name, canonical, sha256: digest(text), claude: `.claude/skills/${name}/SKILL.md`, manual: `docs/runbooks/${name}.md`});
  }
  artifacts.set('docs/generated/agent-workflows.json', `${JSON.stringify({schema:'vegastack-labs.dev/agent-workflows',schemaVersion:'1.0.0',generatedBy:'node tooling/agent-workflows.mjs --write',nativeAcceptance:'not-run',workflows:inventory},null,2)}\n`);
  artifacts.set('docs/generated/hermes-read-plan.json', `${JSON.stringify({schema:'vegastack-labs.dev/hermes-read-plan',schemaVersion:'1.0.0',nativeAcceptance:'not-run',instructionPriority:['.hermes.md','AGENTS.md','CLAUDE.md'],trustedRootRequired:true,allowMutation:false,allowSecrets:false,allowProviderDirect:false,commands:[...hermes.values()].sort((a,b)=>a.path.join(' ').localeCompare(b.path.join(' ')))},null,2)}\n`);
  return artifacts;
}
export async function checkArtifacts(root, artifacts) {
  for (const [path, expected] of artifacts) {
    let actual;
    try { actual = await readFile(join(rootPath(root), path), 'utf8'); } catch { throw new Error(`missing generated workflow: ${path}`); }
    if (actual !== expected) throw new Error(`generated workflow drift: ${path}`);
  }
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const args = process.argv.slice(2);
    if (args.length !== 1 || !['--write','--check'].includes(args[0])) throw new Error('usage: node tooling/agent-workflows.mjs --write|--check');
    const root = fileURLToPath(new URL('../', import.meta.url));
    const artifacts = await buildArtifacts(root);
    if (args[0] === '--check') await checkArtifacts(root, artifacts);
    else for (const [path, content] of artifacts) { await mkdir(dirname(join(root,path)), {recursive:true}); await writeFile(join(root,path),content); }
    process.stdout.write(`agent workflows: ${artifacts.size} artifacts ${args[0] === '--check' ? 'verified' : 'written'}; native acceptance not run\n`);
  } catch (error) { process.stderr.write(`${error.message}\n`); process.exitCode = 1; }
}
