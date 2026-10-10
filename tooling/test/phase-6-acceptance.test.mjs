import test from 'node:test';
import assert from 'node:assert/strict';
import { aggregatePhase6, REQUIRED_PHASE6_SCENARIOS, validatePhase6Definition, scanPhase6Captured, phase6GoFailure } from '../verify-phase-6.mjs';
test('deferred Mac cannot produce full phase acceptance', () => {
  const got=aggregatePhase6({linuxSoftware:'passed',linuxNative:'passed',macSoftware:'pending-deferred',macNative:'pending-deferred',operatorAcceptance:'pending'});
  assert.equal(got.fullPhase,'pending'); assert.equal(got.fleetActivation,'pending');
});
test('failures and missing evidence cannot disappear in aggregation',()=>{
  assert.equal(aggregatePhase6({linuxSoftware:'failed'}).fullPhase,'failed');
  assert.equal(aggregatePhase6({}).linuxSoftware,'pending');
  assert.equal(aggregatePhase6({linuxSoftware:'passed'}).linuxNative,'pending-deferred');
  assert.equal(aggregatePhase6({linuxSoftware:'passed'}).fullPhase,'pending');
  assert.throws(()=>aggregatePhase6({linuxSoftware:'waived'}));
});
test('catalog rejects omitted duplicated and changed obligations',()=>{
  const definition={schemaVersion:1,scenarios:structuredClone(REQUIRED_PHASE6_SCENARIOS)};
  assert.equal(validatePhase6Definition(definition),true);
  for(const alter of [d=>d.scenarios.pop(),d=>d.scenarios.push(d.scenarios[0]),d=>d.scenarios[0].selector='TestFake',d=>d.extra=true]){
    const changed=structuredClone(definition);alter(changed);assert.throws(()=>validatePhase6Definition(changed));
  }
});
test('captured evidence rejects secrets and private material',()=>{
  for(const value of ['-----BEGIN '+'OPENSSH PRIVATE KEY-----','Authorization: Bearer secret','VSK_PRIVATE_CANARY','/home/operator/control.db','192.168.88.71','10.228.1.1','ghp_exampletoken']) assert.throws(()=>scanPhase6Captured(value));
  assert.equal(scanPhase6Captured({stdout:'synthetic-host sha256:'+'a'.repeat(64),stderr:''}),true);
});
test('Go failure diagnostics retain only fixed selector names and bounded status',()=>{
  const selector=REQUIRED_PHASE6_SCENARIOS[0].selector;
  const stdout=[{Action:'fail',Test:selector,Output:'VSK_PRIVATE_CANARY'},{Action:'fail',Test:'/home/operator/credential'},{Action:'fail',Test:'TestUnknown'}].map(JSON.stringify).join('\n');
  const error=phase6GoFailure({stdout,stderr:'VSK_PRIVATE_CANARY',code:1,timedOut:false},[selector,'TestUnknown']);
  assert.deepEqual(error.phase6Failure,{stage:'go-test',failedSelectors:[selector],exitCode:1,timedOut:false});
  assert.equal(scanPhase6Captured(JSON.stringify(error.phase6Failure)),true);
  assert.equal(phase6GoFailure({code:'VSK_PRIVATE_CANARY',timedOut:true},[selector]).phase6Failure.exitCode,null);
});
