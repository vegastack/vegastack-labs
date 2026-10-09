import { open, readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const DIGEST = /^sha256:[a-f0-9]{64}$/;
const STATE_PAIR = new Set(['access-idempotence', 'access-rollback-timeout', 'access-rollback-reboot', 'volume-unchanged-after-verification', 'replacement-recovery']);
const TIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;
const fail = (reason) => { throw new Error(`NATIVE_REPORT_INVALID:${reason}`); };
const digest = (value) => typeof value === 'string' && DIGEST.test(value);
const instant = (value) => typeof value === 'string' && TIME.test(value) && Number.isFinite(Date.parse(value));

// This checks a diagnostic export, never authenticates it or activates a gate.
export function verifyNativeReport(report, scenarioIds) {
  if (!Array.isArray(scenarioIds) || !scenarioIds.length || new Set(scenarioIds).size !== scenarioIds.length) fail('catalog');
  if (!report || report.schema !== 'vegastack-labs.dev/native-report' || report.schemaVersion !== '1.0.0' || !/^[a-f0-9]{40}$/.test(report.sourceCommit ?? '') || !/^[a-z][a-z0-9-]{0,63}$/.test(report.runId ?? '') || !['scopeDigest', 'executableDigest', 'profileLockDigest'].every((key) => digest(report[key]))) fail('binding');
  if (!instant(report.startedAt) || !instant(report.finishedAt) || Date.parse(report.finishedAt) < Date.parse(report.startedAt) || Date.parse(report.finishedAt) - Date.parse(report.startedAt) > 14400000) fail('window');
  if (!Array.isArray(report.pendingRequirements) || report.pendingRequirements.length) fail('pending');
  if (!Array.isArray(report.scenarios) || report.scenarios.length !== scenarioIds.length) fail('coverage');
  const seen = new Set();
  for (const s of report.scenarios) {
    if (!s || !scenarioIds.includes(s.scenarioId) || seen.has(s.scenarioId)) fail('scenario');
    seen.add(s.scenarioId);
    if (s.schema !== 'vegastack-labs.dev/scenario-result' || s.schemaVersion !== '1.0.0' || s.status !== 'passed' || s.qualificationClass !== 'native' || s.cleanupResult !== 'passed' || !['passed', 'not-required'].includes(s.recoveryResult)) fail('outcome');
    if (s.executableDigest !== report.executableDigest || s.profileLockDigest !== report.profileLockDigest || !digest(s.artifactDigest)) fail('scenario-binding');
    const before = s.beforeStateDigest, after = s.afterStateDigest;
    if (Boolean(before) !== Boolean(after) || (STATE_PAIR.has(s.scenarioId) && !before) || (before && (!digest(before) || !digest(after)))) fail('state-pair');
    if (!instant(s.startedAt) || !instant(s.finishedAt) || Date.parse(s.startedAt) < Date.parse(report.startedAt) || Date.parse(s.finishedAt) > Date.parse(report.finishedAt) || Date.parse(s.finishedAt) < Date.parse(s.startedAt)) fail('scenario-window');
    for (const key of ['positiveObservationDigests', 'negativeObservationDigests', 'producerReceiptDigests', 'nativeObservationDigests']) {
      const values = s[key];
      if (!Array.isArray(values) || !values.length || values.length > 64 || new Set(values).size !== values.length || !values.every(digest)) fail('observations');
    }
    if (!Array.isArray(s.producerRunIds) || !s.producerRunIds.length || s.producerRunIds.length > 64 || new Set(s.producerRunIds).size !== s.producerRunIds.length || !s.producerRunIds.every((id) => typeof id === 'string' && /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(id))) fail('producers');
  }
  return { status: 'consistent', authority: 'none', scenarios: seen.size, nativeAuthenticity: 'requires-applied-internal-evidence', physicalQualification: 'not-established', macQualification: 'pending' };
}

export async function verifyReportFile(filename) {
  const handle = await open(filename, 'r');
  let raw;
  try {
    if (!(await handle.stat()).isFile()) fail('input');
    const bounded = Buffer.alloc(4 * 1024 * 1024 + 1);
    let total = 0;
    while (total < bounded.length) {
      const { bytesRead } = await handle.read(bounded, total, bounded.length - total, null);
      if (!bytesRead) break;
      total += bytesRead;
    }
    if (total === bounded.length) fail('size');
    raw = bounded.subarray(0, total);
  } finally { await handle.close(); }
  const schema = JSON.parse(await readFile(path.join(ROOT, 'schemas/v1/scenario-result.schema.json'), 'utf8'));
  return verifyNativeReport(JSON.parse(raw.toString('utf8')), schema.properties.scenarioId.enum);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    if (process.argv.length !== 4 || process.argv[2] !== '--report') fail('arguments');
    process.stdout.write(`${JSON.stringify(await verifyReportFile(process.argv[3]))}\n`);
  } catch (error) {
    // Never echo report bytes, paths or native material in diagnostics.
    const message = /^NATIVE_REPORT_INVALID:[a-z-]+$/.test(error?.message ?? '') ? error.message : 'NATIVE_REPORT_INVALID:input';
    process.stderr.write(`${message}\n`);
    process.exitCode = 1;
  }
}
