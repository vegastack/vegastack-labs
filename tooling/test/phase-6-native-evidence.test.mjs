import test from 'node:test';
import assert from 'node:assert/strict';
import { validatePhase6Trace, validateCurrentNativeAuthority, boundedNativeJSON } from '../lib/phase-6-native-evidence.mjs';
import { PHASE6_NATIVE_SCENARIOS } from '../verify-phase-6.mjs';
import { mkdtemp, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
test('summary-only native pass is rejected',()=>{
 assert.throws(()=>validatePhase6Trace({proofClass:'native',scenarios:[{scenarioId:'rollback',status:'passed'}]},new Map(),{}),/missing|receipt|schema|binding/i);
});
test('missing current server authority cannot count as native success',()=>{
 assert.throws(()=>validateCurrentNativeAuthority({},[],{}),/authority|gate|schema/i);
});
test('independent native catalog contains exact required rollback storage and recovery scenarios',()=>{
 assert.equal(PHASE6_NATIVE_SCENARIOS.length,27);assert.equal(new Set(PHASE6_NATIVE_SCENARIOS).size,27);
 for(const id of ['access-rollback-timeout','access-rollback-reboot','volume-inconsistent-redundant-header','native-credential-lifecycle','replacement-recovery'])assert.ok(PHASE6_NATIVE_SCENARIOS.includes(id));
});
test('native inputs refuse symlinks and oversized files',async()=>{
 const root=await mkdtemp(path.join(tmpdir(),'vsk-p6-test-'));try {
 const file=path.join(root,'file.json');await writeFile(file,'{}');await symlink(file,path.join(root,'link.json'));
 await assert.rejects(boundedNativeJSON(path.join(root,'link.json'),32));
 await writeFile(file,'x'.repeat(33));await assert.rejects(boundedNativeJSON(file,32));
 }finally{await rm(root,{recursive:true,force:true});}
});
function currentFixture(){
 const source='a'.repeat(40),now='2026-10-10T09:00:00Z',bundle='sha256:'+'b'.repeat(64),planDigest='sha256:'+'c'.repeat(64);
 const stages=['baseline','role','recovery'].map(stage=>({stage,request:{profileId:'synthetic-profile',evidenceId:`native-${stage}`,recoveryEpoch:1},data:{bundleDigest:bundle}}));
 const authority={gates:[],declarations:[],plans:[],runs:[]};
 for(const c of stages){const id=c.request.evidenceId,op={operationId:id,adapterId:'core.gate',operationType:'gate.evidence.apply',targetId:'synthetic-profile',inputDigest:bundle,artifactDigest:bundle};
 authority.gates.push({changed:false,status:'succeeded',sourceRevision:source,recoveryEpoch:1,data:{definition:{gateId:`native.${c.stage}`},evaluation:{gateId:`native.${c.stage}`,subjectId:'synthetic-profile',outcome:'passed',evidenceSource:'local',recoveryEpoch:1,evidenceIds:[id],evaluatedAt:now}}});
 authority.declarations.push({declarationId:`gate-evidence-${id}`,revision:1,recoveryEpoch:1,operations:[op]});
 authority.plans.push({planId:`plan-${id}`,planDigest,declarationId:`gate-evidence-${id}`,binding:{declarationRevision:1,recoveryEpoch:1},operations:[op]});
 authority.runs.push({status:'succeeded',sourceRevision:source,recoveryEpoch:1,data:{run:{status:'succeeded',planId:`plan-${id}`,planDigest,steps:[{status:'succeeded',operationId:id,operationType:'gate.evidence.apply',targetId:'synthetic-profile'}]}}});
 }
 return {authority,stages,expected:{runtimeSourceCommit:source,now}};
}
test('native success depends on current API qualification and actual applied lineage',()=>{
 const f=currentFixture();assert.equal(validateCurrentNativeAuthority(f.authority,f.stages,f.expected).status,'passed');
 for(const alter of [a=>a.gates[0].data.evaluation.outcome='blocked',a=>a.gates[0].data.evaluation.evidenceSource='fixture',a=>a.gates[0].recoveryEpoch=0,a=>a.gates[0].sourceRevision='d'.repeat(40),a=>a.gates[0].data.evaluation.evidenceIds=['superseded'],a=>a.gates[0].data.evaluation.evaluatedAt='2026-10-09T09:00:00Z',a=>a.declarations[0].operations[0].inputDigest='sha256:'+'e'.repeat(64),a=>a.plans[0].binding.declarationRevision=2,a=>a.runs[0].data.run.status='failed',a=>a.runs[0].data.run.planDigest='sha256:'+'f'.repeat(64),a=>a.runs[0].data.run.steps=[]]){
 const changed=structuredClone(f.authority);alter(changed);assert.throws(()=>validateCurrentNativeAuthority(changed,f.stages,f.expected));
 }
});
