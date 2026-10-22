import assert from "node:assert/strict";
import test from "node:test";
import { createHostClient } from "../generated/read-api.ts";

const request = { schema:"vegastack-labs.dev/host-discovery-request",schemaVersion:"1.0.0",targetId:"target-a",targetRevision:1,expectedStateRevision:7,recoveryEpoch:2,idempotencyKey:"scan-a" };
test("host discovery uses exact typed route once and never retries network errors",async()=>{
 let calls=0;
 const client=createHostClient(async(path,options)=>{calls++;assert.equal(path,"/api/v1/host-observations");assert.equal(options.method,"POST");assert.deepEqual(JSON.parse(options.body),request);throw new TypeError("connection lost");});
 await assert.rejects(()=>client.discoverHost(request));assert.equal(calls,1);
});
test("host browser client rejects unknown secret fields before transport",async()=>{
 let calls=0;const client=createHostClient(async()=>{calls++;throw new Error("unexpected");});
 await assert.rejects(()=>client.discoverHost({...request,password:"private-canary"}));assert.equal(calls,0);
});
test("host inspection encodes one exact target rather than a path",async()=>{
 let calls=0;const client=createHostClient(async(path)=>{calls++;assert.equal(path,calls===1 ? "/api/v1/hosts/..%2Foutside" : "/api/v1/hosts/host-a");return new Response("{}",{status:403});});
 await assert.rejects(()=>client.getHosts({hostID:"../outside"}));assert.equal(calls,1);
 await assert.rejects(()=>client.getHosts({hostID:"host-a"}));assert.equal(calls,2);
});

test("registered host list uses the collection endpoint and validates snapshot binding", async () => {
 const host={schema:"vegastack-labs.dev/managed-host",schemaVersion:"1.0.0",hostId:"host-a",targetId:"target-a",observationId:"observation-a",profileId:"profile-a",identityClass:"physical",status:"adopted-unadmitted",stateRevision:3,recoveryEpoch:0};
 const envelope=(hosts)=>({schema:"vegastack-labs.dev/browser-run-result",schemaVersion:"1.0.0",toolVersion:"test",command:"api.v1.hosts.list",runId:null,status:"succeeded",changed:false,recoveryEpoch:0,stateRevision:3,snapshotDigest:null,releaseBuildId:"test",sourceRevision:null,planId:null,errors:[],data:{schema:"vegastack-labs.dev/managed-host-list",schemaVersion:"1.0.0",hosts,stateRevision:3,recoveryEpoch:0}});
 let response=envelope([host]); let calls=0;
 const client=createHostClient(async(path,options)=>{calls++;assert.equal(path,"/api/v1/hosts");assert.equal(options.method,"GET");return Response.json(response);});
 assert.equal((await client.listHosts()).data.hosts[0].status,"adopted-unadmitted");
 response=envelope([]);assert.deepEqual((await client.listHosts()).data.hosts,[]);
 response=envelope([host,host]);await assert.rejects(()=>client.listHosts());
 response=envelope([host]);response.data.stateRevision=4;await assert.rejects(()=>client.listHosts());assert.equal(calls,4);
});
