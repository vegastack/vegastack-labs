import { createHash } from 'node:crypto';
import { constants } from 'node:fs';
import { lstat, open, readdir, realpath } from 'node:fs/promises';
import path from 'node:path';
import { verifyNativeReport } from '../verify-phase-6-native.mjs';
import { PHASE6_NATIVE_SCENARIOS } from '../verify-phase-6.mjs';
import { canonicalJSON, exactKeys } from './acceptance-scenarios.mjs';
const fail=reason=>{throw new Error(`PHASE6_NATIVE_INVALID:${reason}`);};
const digest=value=>`sha256:${createHash('sha256').update(JSON.stringify(value)).digest('hex')}`;
const same=(a,b)=>canonicalJSON(a)===canonicalJSON(b);
export async function boundedNativeJSON(filename,limit) {
 const before=await lstat(filename);if(!before.isFile()||before.isSymbolicLink()||before.nlink!==1||before.size<1||before.size>limit)fail('input');
 const handle=await open(filename,constants.O_RDONLY|constants.O_NOFOLLOW);
 try {
 const opened=await handle.stat();if(opened.ino!==before.ino||opened.dev!==before.dev||opened.size!==before.size)fail('input');
 const raw=Buffer.alloc(limit+1);let total=0;while(total<raw.length){const {bytesRead}=await handle.read(raw,total,raw.length-total,null);if(!bytesRead)break;total+=bytesRead;}
 const after=await lstat(filename);if(total!==before.size||total>limit||after.ino!==opened.ino||after.dev!==opened.dev||after.size!==opened.size||after.mtimeMs!==opened.mtimeMs)fail('input');
 return JSON.parse(raw.subarray(0,total).toString('utf8'));
 }finally{await handle.close();}
}
function reportKeys(report) {
 if(!exactKeys(report,['schema','schemaVersion','changed','runId','scopeDigest','sourceCommit','executableDigest','profileLockDigest','scenarios','pendingRequirements','startedAt','finishedAt']))fail('schema');
 const required=['schema','schemaVersion','scenarioId','status','profileLockDigest','executableDigest','startedAt','finishedAt','positiveObservationDigests','negativeObservationDigests','recoveryResult','cleanupResult','qualificationClass','producerRunIds','producerReceiptDigests','nativeObservationDigests','artifactDigest'];
 for(const s of report.scenarios??[]){if(!s||Object.keys(s).some(k=>![...required,'beforeStateDigest','afterStateDigest'].includes(k))||required.some(k=>!Object.hasOwn(s,k)))fail('schema');}
}
// Exported records remain trace material. Only current server evaluation can
// authenticate their native origin and rerun the owning semantic predicates.
export function validatePhase6Trace(report,records,expected) {
 reportKeys(report);verifyNativeReport(report,PHASE6_NATIVE_SCENARIOS);
 if(!(records instanceof Map)||report.sourceCommit!==expected.sourceCommit||report.executableDigest!==expected.executableDigest||report.profileLockDigest!==expected.profileLockDigest||report.scopeDigest!==expected.scopeDigest)fail('binding');
 const results=[...records.entries()].filter(([name])=>name.endsWith('.result.json')).map(([,value])=>value);
 const collections=[];
 for(const result of results) {
  if(result.schema!=='vegastack-labs.dev/native-step-result'||result.binding?.scopeDigest!==report.scopeDigest||!PHASE6_NATIVE_SCENARIOS.includes(result.binding?.scenarioId))fail('receipt-schema');
  if(result.collection) {
   const name=`${result.binding.scenarioId}-${result.binding.ordinal}.collect.json`,request=records.get(name),data=result.collection;
   if(!request||request.schema!=='vegastack-labs.dev/native-collect-request'||request.scopeDigest!==report.scopeDigest||data.requestDigest!==digest(request)||data.submission?.evidenceId!==request.evidenceId||data.submission?.recoveryEpoch!==request.recoveryEpoch||!['baseline','role','recovery'].includes(request.stage)||!Array.isArray(data.scenarios))fail('missing-collection-receipt');
   collections.push({stage:request.stage,request,data,ordinal:result.binding.ordinal});
  }
 }
 // A recovery epoch clears prior stage qualifications. Select only collections
 // belonging to the final epoch; never revive an earlier successful stage.
 if(!collections.length)fail('missing-receipt');
 const epoch=Math.max(...collections.map(c=>c.request.recoveryEpoch));
 const current=collections.filter(c=>c.request.recoveryEpoch===epoch);
 const stages=['baseline','role','recovery'].map(stage=>{
  const matching=current.filter(c=>c.stage===stage).sort((a,b)=>Date.parse(a.data.scenarios[0]?.finishedAt)-Date.parse(b.data.scenarios[0]?.finishedAt)||a.ordinal-b.ordinal);if(!matching.length)fail('missing-stage-receipt');return matching.at(-1);
 });
 const covered=new Set();
 for(const c of stages)for(const summary of c.data.scenarios){
  const actual=report.scenarios.find(s=>s.scenarioId===summary.scenarioId);if(!actual||covered.has(actual.scenarioId)||summary.status!=='uncertain'||summary.artifactDigest!==c.data.bundleDigest||summary.qualificationClass!=='native')fail('receipt-binding');
  for(const k of ['profileLockDigest','executableDigest','artifactDigest','positiveObservationDigests','negativeObservationDigests','producerRunIds','producerReceiptDigests','nativeObservationDigests','beforeStateDigest','afterStateDigest'])if(!same(actual[k],summary[k]))fail('receipt-binding');
  covered.add(actual.scenarioId);
 }
 if(covered.size!==PHASE6_NATIVE_SCENARIOS.length)fail('missing-scenario-receipt');
 const runIds=[...new Set(results.flatMap(r=>[...(r.producerRunIds??[]),...(r.run?.run?.runId?[r.run.run.runId]:[])]))];
 if(runIds.length>128||runIds.length===0)fail('missing-run-receipt');
 return {stages,epoch,runIds};
}
export function validateCurrentNativeAuthority(authority,stages,expected) {
 if(!authority||!Array.isArray(authority.gates)||authority.gates.length!==3||!Array.isArray(authority.runs)||!Array.isArray(authority.plans)||!Array.isArray(authority.declarations))fail('authority-schema');
 for(const c of stages) {
  const envelope=authority.gates.find(g=>g.data?.definition?.gateId===`native.${c.stage}`),evaluation=envelope?.data?.evaluation;
  if(!envelope||envelope.changed||envelope.status!=='succeeded'||envelope.sourceRevision!==expected.runtimeSourceCommit||evaluation?.gateId!==`native.${c.stage}`||evaluation.subjectId!==c.request.profileId||evaluation.outcome!=='passed'||evaluation.evidenceSource!=='local'||evaluation.recoveryEpoch!==c.request.recoveryEpoch||envelope.recoveryEpoch!==c.request.recoveryEpoch||!evaluation.evidenceIds?.includes(c.request.evidenceId))fail('current-gate');
  const at=Date.parse(evaluation.evaluatedAt),now=Date.parse(expected.now);if(!Number.isFinite(at)||!Number.isFinite(now)||at>now+1000||now-at>30000)fail('current-gate-expiry');
  const declaration=authority.declarations.find(d=>d.declarationId===`gate-evidence-${c.request.evidenceId}`);
  const op=declaration?.operations?.[0];
  if(!declaration||declaration.recoveryEpoch!==c.request.recoveryEpoch||declaration.operations.length!==1||op.adapterId!=='core.gate'||op.operationId!==c.request.evidenceId||op.targetId!==c.request.profileId||!['gate.evidence.apply','gate.evidence.supersede'].includes(op.operationType)||op.inputDigest!==c.data.bundleDigest||op.artifactDigest!==c.data.bundleDigest)fail('applied-declaration');
  const plans=authority.plans.filter(p=>p.declarationId===declaration.declarationId&&p.binding?.declarationRevision===declaration.revision&&p.binding?.recoveryEpoch===c.request.recoveryEpoch&&p.operations?.length===1&&p.operations[0].operationId===op.operationId&&p.operations[0].inputDigest===op.inputDigest&&p.operations[0].artifactDigest===op.artifactDigest&&p.operations[0].adapterId===op.adapterId&&p.operations[0].operationType===op.operationType&&p.operations[0].targetId===op.targetId);
  const applied=plans.some(p=>authority.runs.some(r=>r.status==='succeeded'&&r.recoveryEpoch===c.request.recoveryEpoch&&r.sourceRevision===expected.runtimeSourceCommit&&r.data?.run?.status==='succeeded'&&r.data.run.planId===p.planId&&r.data.run.planDigest===p.planDigest&&r.data.run.steps?.length===1&&r.data.run.steps[0].status==='succeeded'&&r.data.run.steps[0].operationId===op.operationId&&r.data.run.steps[0].operationType===op.operationType&&r.data.run.steps[0].targetId===op.targetId));
  if(!applied)fail('missing-applied-run');
 }
 return {status:'passed',authority:'current-local-api',stages:stages.map(c=>({stage:c.stage,evidenceId:c.request.evidenceId,bundleDigest:c.data.bundleDigest})),physicalQualification:'not-established'};
}
export async function loadPhase6NativeEvidence({reportPath,receiptRoot,expectedSourceDigest,expectedProfileDigest,now,qualificationReader}) {
 const report=await boundedNativeJSON(reportPath,2*1024*1024);
 const metadata=await lstat(receiptRoot);if(!metadata.isDirectory()||metadata.isSymbolicLink())fail('receipt-root');
 const root=await realpath(receiptRoot),scope=await boundedNativeJSON(path.join(root,'scope.json'),65536);
 if(scope.schema!=='vegastack-labs.dev/qualification-scope'||scope.sourceCommit!==report.sourceCommit||scope.executableDigest!==report.executableDigest||scope.profileLockDigest!==expectedProfileDigest||digest(scope)!==report.scopeDigest)fail('scope-binding');
 const names=(await readdir(root)).filter(name=>/^[a-z][a-z0-9-]*-[1-9][0-9]?\.(?:result|collect)\.json$/.test(name));if(names.length>256)fail('receipt-count');
 const records=new Map();for(const name of names)records.set(name,await boundedNativeJSON(path.join(root,name),name.endsWith('.collect.json')?65536:262144));
 const trace=validatePhase6Trace(report,records,{sourceCommit:report.sourceCommit,executableDigest:report.executableDigest,profileLockDigest:expectedProfileDigest,scopeDigest:report.scopeDigest});
 if(typeof qualificationReader!=='function')return {status:'pending',reason:'current-api-unavailable',authority:'none'};
 const authority=await qualificationReader({runIds:trace.runIds});
 if(!authority)return {status:'pending',reason:'current-api-unavailable',authority:'none'};
 // The caller checks the native executable's commit against the current
 // production source closure, not a report-supplied compatibility flag.
 if(authority.sourceDigest!==expectedSourceDigest)return {status:'failed',reason:'production-source-drift',authority:'none'};
 return {...validateCurrentNativeAuthority(authority,trace.stages,{runtimeSourceCommit:report.sourceCommit,now:now??new Date().toISOString()}),traceIntegrity:'consistent',exportedReportAuthority:'none'};
}
