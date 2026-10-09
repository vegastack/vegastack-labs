import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { createHostClient, hostRequestDigest } from "../generated/read-api.ts";

const schema = name => `vegastack-labs.dev/${name}`;
const digest = char => `sha256:${char.repeat(64)}`;
const fixture = async kind => JSON.parse(await readFile(new URL(`../../internal/localapi/testdata/host-${kind}.json`, import.meta.url)));
const envelope = (command, data, epoch=0, revision=3) => ({schema:schema("browser-run-result"),schemaVersion:"1.0.0",toolVersion:"test",command,runId:null,status:"succeeded",changed:false,recoveryEpoch:epoch,stateRevision:revision,snapshotDigest:null,releaseBuildId:"test",sourceRevision:null,planId:null,errors:[],data});
const clientFor = value => createHostClient(async()=>new Response(JSON.stringify(value)));

test("generated host drafts reject another independently valid request response",async()=>{
 for(const [kind,method,op,prefix] of [
  ["target","prepareHostTarget","host-discovery-targets.draft","discovery-draft-"],
  ["action","prepareHostAction","host-actions.draft","host-action-"],
  ["access","prepareHostAccess","host-access.draft","host-access-"],
  ["replacement","prepareHostReplacement","host-replacements.create","host-replacement-"],
 ]) {
  const a=await fixture(kind),b=structuredClone(a);
  if(kind==="access") b.subject.idempotencyKey+="-other";else b.idempotencyKey+="-other";
  const requests=[a,b],responses=[];
  for(let i=0;i<2;i++){
   const original=await hostRequestDigest(requests[i].schema,requests[i]);
   const rendered=kind==="action"||kind==="access"?digest(i===0?"a":"b"):original;
   const data={schema:schema(kind==="target"?"host-discovery-target-draft-submission":kind==="replacement"?"host-replacement-submission":"host-action-submission"),schemaVersion:"1.0.0",draftId:prefix+rendered.slice(7,39),declarationId:prefix+rendered.slice(7,39),contentDigest:rendered,stateRevision:3,recoveryEpoch:0};
   if(kind==="replacement")data.replacementId=requests[i].replacementId;
   if(kind==="action"||kind==="access")data.originalRequestDigest=original;
   responses.push(envelope(`api.v1.${op}`,data));
   await clientFor(responses[i])[method](requests[i]);
  }
  await assert.rejects(()=>clientFor(responses[1])[method](requests[0]),{code:"INTEGRITY_FAILURE"});
  await assert.rejects(()=>clientFor(responses[0])[method](requests[1]),{code:"INTEGRITY_FAILURE"});
  const wrongEpoch=structuredClone(responses[0]);wrongEpoch.data.recoveryEpoch=99;
  await assert.rejects(()=>clientFor(wrongEpoch)[method](requests[0]),{code:"INTEGRITY_FAILURE"});
 }
});

test("generated managed host reader rejects a different valid host and envelope revision",async()=>{
 const host=id=>({schema:schema("managed-host"),schemaVersion:"1.0.0",hostId:id,targetId:`target-${id}`,observationId:"observation-a",profileId:"debian-13-amd64",identityClass:"qualified-virtual",status:"adopted-unadmitted",stateRevision:3,recoveryEpoch:0});
 for(const id of ["host-a","host-b"])await clientFor(envelope("api.v1.hosts.get",host(id))).getHosts({hostID:id});
 await assert.rejects(()=>clientFor(envelope("api.v1.hosts.get",host("host-b"))).getHosts({hostID:"host-a"}),{code:"INTEGRITY_FAILURE"});
 await clientFor(envelope("api.v1.hosts.get",host("host-a"),0,4)).getHosts({hostID:"host-a"});
 await assert.rejects(()=>clientFor(envelope("api.v1.hosts.get",host("host-a"),0,2)).getHosts({hostID:"host-a"}),{code:"INTEGRITY_FAILURE"});
});

test("host request digest matches Go encoding for actual finite fixtures",async()=>{
 const expected={target:"6f417223269fca6e9042e609284dc73ee5435b1b1f7e535c1e0df34f05b96d97",action:"cef41c391efb1d4773304b19c28ea52b200c231e43dd464359d410790cd2b306",access:"53f7548f8d1fa647fadd098b0719ffae57d67c323acf902d51adbff237520f19",replacement:"3b70673b7d7630b532ddf84a17f62d47998139a9d8c0e25d13efe51a3c63a897"};
 for(const [kind,hex] of Object.entries(expected)){
  const request=await fixture(kind);
  assert.equal(await hostRequestDigest(request.schema,request),`sha256:${hex}`);
  const reordered=Object.fromEntries(Object.entries(request).reverse());
  assert.equal(await hostRequestDigest(request.schema,reordered),`sha256:${hex}`);
 }
});

test("host request digest preserves Go HTML escaping and omits nil optional pointers",async()=>{
 const action=await fixture("action");action.actionInput="<>&\u2028\u2029";
 assert.equal(await hostRequestDigest(action.schema,action),"sha256:b454b169400aaa9a41fcd1ac240e2b0eae6f7e2e7956d9fe194c0a471acf19cf");
 const target=await fixture("target"),before=await hostRequestDigest(target.schema,target);
 target.target.credentialMode=null;
 assert.equal(await hostRequestDigest(target.schema,target),before);
});

test("discovery rejects a valid observation from another scan of the same target",async()=>{
 const requests=[0,1].map(i=>({schema:schema("host-discovery-request"),schemaVersion:"1.0.0",targetId:"target-a",targetRevision:1,expectedStateRevision:1,recoveryEpoch:0,idempotencyKey:`scan-${i}`}));
 const responses=[];
 for(let i=0;i<2;i++){
  const observation={schema:schema("host-observation"),schemaVersion:"1.0.0",observationId:`observation-${i}`,targetId:"target-a",targetRevision:1,targetDigest:digest("a"),collector:"collector-a",collectorVersion:"1.0.0",observedAt:"2026-10-09T12:00:00Z",expiresAt:"2026-10-09T12:15:00Z",status:"incomplete",facts:[],blockers:["hardening-unverified"],contentDigest:digest(i===0?"a":"b"),stateRevision:3,recoveryEpoch:0};
  responses.push(envelope("api.v1.host-observations.create",{schema:schema("host-discovery-submission"),schemaVersion:"1.0.0",originalRequestDigest:await hostRequestDigest(requests[i].schema,requests[i]),observation,created:true}));
  await clientFor(responses[i]).discoverHost(requests[i]);
 }
 await assert.rejects(()=>clientFor(responses[1]).discoverHost(requests[0]),{code:"INTEGRITY_FAILURE"});
 await assert.rejects(()=>clientFor(responses[0]).discoverHost(requests[1]),{code:"INTEGRITY_FAILURE"});
});
