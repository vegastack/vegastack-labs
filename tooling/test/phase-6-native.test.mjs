import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import { verifyNativeReport } from '../verify-phase-6-native.mjs';

const ids = JSON.parse(await readFile(new URL('../../schemas/v1/scenario-result.schema.json', import.meta.url), 'utf8')).properties.scenarioId.enum;
const d = `sha256:${'1'.repeat(64)}`;
function fixture() {
  const startedAt = '2026-10-09T12:00:00Z', finishedAt = '2026-10-09T13:00:00Z';
  return { schema: 'vegastack-labs.dev/native-report', schemaVersion: '1.0.0', runId: 'test-native', sourceCommit: 'a'.repeat(40), scopeDigest: d, executableDigest: d, profileLockDigest: d, startedAt, finishedAt, pendingRequirements: [], scenarios: ids.map((scenarioId) => ({ schema: 'vegastack-labs.dev/scenario-result', schemaVersion: '1.0.0', scenarioId, status: 'passed', qualificationClass: 'native', cleanupResult: 'passed', recoveryResult: 'passed', executableDigest: d, profileLockDigest: d, artifactDigest: d, beforeStateDigest: d, afterStateDigest: d, startedAt, finishedAt, positiveObservationDigests: [d], negativeObservationDigests: [d], producerReceiptDigests: [d], nativeObservationDigests: [d], producerRunIds: ['run-1'] })) };
}

test('a complete synthetic report is structurally consistent but grants no authenticity or authority', () => {
  const result = verifyNativeReport(fixture(), ids);
  assert.equal(result.status, 'consistent');
  assert.equal(result.authority, 'none');
  assert.equal(result.nativeAuthenticity, 'requires-applied-internal-evidence');
  assert.equal(result.physicalQualification, 'not-established');
  assert.equal(result.macQualification, 'pending');
});

for (const [name, mutate] of Object.entries({
  missing: r => r.scenarios.pop(),
  duplicate: r => r.scenarios[1] = r.scenarios[0],
  unknown: r => r.scenarios[0].scenarioId = 'invented',
  fixture: r => r.scenarios[0].qualificationClass = 'fixture',
  skipped: r => r.scenarios[0].status = 'not-run',
  pending: r => r.pendingRequirements.push('cleanup-unconfirmed'),
  cleanup: r => r.scenarios[0].cleanupResult = 'uncertain',
  recovery: r => r.scenarios[0].recoveryResult = 'failed',
  executable: r => r.scenarios[0].executableDigest = `sha256:${'2'.repeat(64)}`,
  profile: r => r.scenarios[0].profileLockDigest = `sha256:${'2'.repeat(64)}`,
  noDenial: r => r.scenarios[0].negativeObservationDigests = [],
  noProducer: r => r.scenarios[0].producerReceiptDigests = [],
  noNativeObservation: r => r.scenarios[0].nativeObservationDigests = [],
  fabricatedDigest: r => r.scenarios[0].nativeObservationDigests = ['passed'],
  renewedWindow: r => r.finishedAt = '2026-10-09T17:00:01Z',
  outOfWindow: r => r.scenarios[0].startedAt = '2026-10-09T11:59:59Z',
})) test(`rejects ${name} report`, () => {
  const report = fixture(); mutate(report);
  assert.throws(() => verifyNativeReport(report, ids), /^Error: NATIVE_REPORT_INVALID:/);
});

test('read-only scenarios may omit unobserved state pairs without fabricating them', () => {
 const report=fixture();delete report.scenarios[0].beforeStateDigest;delete report.scenarios[0].afterStateDigest;
 assert.equal(verifyNativeReport(report,ids).status,'consistent');
 report.scenarios[0].beforeStateDigest=d;
 assert.throws(()=>verifyNativeReport(report,ids),/state-pair/);
});
test('actual state-comparison scenarios require both observations', () => {
 const report=fixture(), row=report.scenarios.find(s=>s.scenarioId==='replacement-recovery');
 delete row.beforeStateDigest;delete row.afterStateDigest;
 assert.throws(()=>verifyNativeReport(report,ids),/state-pair/);
});
