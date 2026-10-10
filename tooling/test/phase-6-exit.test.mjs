import test from 'node:test';
import assert from 'node:assert/strict';
import { exitResult, parsePhase6ExitArgs } from '../verify-phase-6-exit.mjs';
test('full exit remains pending when Mac is deferred',()=>{
 const got=exitResult('full',{linuxSoftware:'passed',linuxNative:'passed',macSoftware:'pending-deferred',macNative:'pending-deferred',operatorAcceptance:'pending'});
 assert.equal(got.code,2);assert.equal(got.report.fullPhase,'pending');assert.equal(got.report.fleetActivation,'pending');
});
test('Linux exit cannot masquerade as full phase completion',()=>{
 const got=exitResult('linux',{linuxSoftware:'passed',linuxNative:'passed'});assert.equal(got.code,0);assert.equal(got.report.macNative,'pending-deferred');assert.equal(got.report.fullPhase,'pending');
 assert.equal(exitResult('linux',{linuxSoftware:'passed'}).code,2);assert.equal(exitResult('linux',{linuxNative:'failed'}).code,1);
 assert.equal(exitResult('linux',{linuxSoftware:'passed',linuxNative:'pending-deferred'}).code,2);
});
test('exit requires explicit scope and rejects pending bypasses and repeated flags',()=>{
 assert.deepEqual(parsePhase6ExitArgs(['--scope','linux']),{scope:'linux'});
 for(const args of [[],['--scope','unknown'],['--scope','linux','--allow-pending'],['--scope','linux','--scope','full'],['--scope','linux','--native-report','report.json']])assert.throws(()=>parsePhase6ExitArgs(args));
});
