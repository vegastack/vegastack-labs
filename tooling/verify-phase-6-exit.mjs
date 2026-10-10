import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { aggregatePhase6, phase6SourceState, runPhase6, scanPhase6Captured } from './verify-phase-6.mjs';
import { boundedNativeJSON, loadPhase6NativeEvidence } from './lib/phase-6-native-evidence.mjs';
import { runCommand } from './lib/process.mjs';
const ROOT=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const fail=reason=>{throw new Error(`PHASE6_EXIT_INVALID:${reason}`);};
// These are actual #228 development build/profile pins, not official release
// signing, deployment qualification or a configurable caller upload flag.
export const PHASE6_NATIVE_ARTIFACT_LOCK=Object.freeze({sourceCommit:'68b0e5cd6daa854141f341258e5afba16c97b71d',executableDigest:'sha256:b93f049dec5a26db506d183f1413aaff06f19d13108a31b71e971ac1ee993818',profileLockDigest:'sha256:cb80d401e6368e13b931fa60e70e49798b11096e3b151f2df99662805c7e2b76'});
export function parsePhase6ExitArgs(args) {
 const allowed=new Map([['--scope','scope'],['--native-report','reportPath'],['--receipt-root','receiptRoot'],['--output','output'],['--config','config']]),out={};
 for(let i=0;i<args.length;i+=2){const key=allowed.get(args[i]);if(!key||Object.hasOwn(out,key)||typeof args[i+1]!=='string'||args[i+1].startsWith('--')||!args[i+1]||args[i+1].includes('\0'))fail('arguments');out[key]=args[i+1];}
 if(!['linux','full'].includes(out.scope)||Boolean(out.reportPath)!==Boolean(out.receiptRoot)||(out.config&&!out.reportPath))fail('arguments');return out;
}
export function exitResult(scope,results) {
 if(!['linux','full'].includes(scope))fail('scope');const report={schema:'vegastack-labs.dev/phase6-exit',schemaVersion:1,scope,...aggregatePhase6(results)};
 const wanted=scope==='linux'?[report.linuxSoftware,report.linuxNative]:[report.fullPhase];
 return {code:wanted.includes('failed')?1:wanted.every(s=>s==='passed')?0:2,report};
}
export async function phase6ProductionSourceDigest(root,commit) {
 if(!/^[a-f0-9]{40}$/.test(commit))fail('source');
 const found=await runCommand('git',['ls-tree','-r','--full-tree',commit,'--','cmd','internal','ansible','schemas/v1','go.mod','go.sum'],{cwd:root,capture:true,timeoutMs:30000});
 const lines=found.stdout.split('\n').filter(s=>s&&!s.endsWith('_test.go')&&!s.includes('/testdata/'));
 if(!lines.length)fail('source');return `sha256:${createHash('sha256').update(lines.join('\n')).digest('hex')}`;
}
async function readCurrentNative(root,config,input) {
 const work=await mkdtemp(path.join(tmpdir(),'vsk-phase6-reader-'));try {
 const binary=path.join(work,'reader');await runCommand('go',['build','-o',binary,'./tooling/phase6-native-reader'],{cwd:root,capture:true,timeoutMs:180000});
 return await new Promise(resolve=>{
  const child=spawn(binary,['--config',config],{cwd:root,shell:false,stdio:['pipe','pipe','pipe']}),chunks=[];let length=0,done=false;
  const finish=value=>{if(!done){done=true;clearTimeout(timer);resolve(value);}};
  const timer=setTimeout(()=>{child.kill('SIGKILL');finish(null);},300000);
  child.stdout.on('data',chunk=>{length+=chunk.length;if(length>8*1024*1024){child.kill('SIGKILL');finish(null);}else chunks.push(chunk);});
  child.stderr.resume();child.on('error',()=>finish(null));child.on('close',code=>{if(code!==0)return finish(null);try{finish(JSON.parse(Buffer.concat(chunks).toString('utf8')));}catch{finish(null);}});
  child.stdin.on('error',()=>finish(null));child.stdin.end(JSON.stringify(input));
 });
 }finally{await rm(work,{recursive:true,force:true});}
}
export async function runPhase6Exit(root=ROOT,args={}) {
 const before=await phase6SourceState(root),software=await runPhase6(root);
 let native={status:'pending',reason:'native-proof-not-supplied',authority:'none'};
 if(args.reportPath) {
  const report=await boundedNativeJSON(args.reportPath,2*1024*1024),lock=PHASE6_NATIVE_ARTIFACT_LOCK;
  if(report.sourceCommit!==lock.sourceCommit||report.executableDigest!==lock.executableDigest||report.profileLockDigest!==lock.profileLockDigest)fail('native-artifact-lock');
  const current=await phase6ProductionSourceDigest(root,before),compiled=await phase6ProductionSourceDigest(root,lock.sourceCommit);
  if(current!==compiled)native={status:'failed',reason:'production-source-drift',authority:'none'};
  else native=await loadPhase6NativeEvidence({reportPath:args.reportPath,receiptRoot:args.receiptRoot,expectedSourceDigest:current,expectedProfileDigest:lock.profileLockDigest,qualificationReader:args.config?async input=>{
   const authority=await readCurrentNative(root,args.config,input);return authority?{...authority,sourceDigest:compiled}:null;
  }:undefined});
 }
 if(await phase6SourceState(root)!==before)fail('source-drift');
 const {code,report}=exitResult(args.scope,{linuxSoftware:software.linuxSoftware,linuxNative:native.status});
 const result={...report,sourceCommit:before,software,native};scanPhase6Captured(JSON.stringify(result));
 if(args.output){const output=path.resolve(args.output);if(output===root||output.startsWith(root+path.sep))fail('output-inside-source');await writeFile(output,JSON.stringify(result,null,2)+'\n',{flag:'wx',mode:0o600});}
 return {code,report:result};
}
if(process.argv[1]===fileURLToPath(import.meta.url)) {
 try {const {code,report}=await runPhase6Exit(ROOT,parsePhase6ExitArgs(process.argv.slice(2)));process.stdout.write(`${JSON.stringify(report)}\n`);process.exitCode=code;}
 catch {process.stderr.write('PHASE6_EXIT_INVALID:verification\n');process.exitCode=1;}
}
