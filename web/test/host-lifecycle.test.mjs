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
