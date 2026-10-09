import assert from "node:assert/strict";
import test from "node:test";
import { readFile } from "node:fs/promises";
import { stripTypeScriptTypes } from "node:module";

const source = await readFile(new URL("../lib/host-policy-input.ts", import.meta.url), "utf8");
const javascript = stripTypeScriptTypes(source).replace('"../generated/read-api"', JSON.stringify(new URL("../generated/read-api.ts",import.meta.url).href));
const {readHostPolicy,hostPolicySummary} = await import(`data:text/javascript;base64,${Buffer.from(javascript).toString("base64")}`);
const fixture = JSON.parse(await readFile(new URL("../../internal/localapi/testdata/host-access.json", import.meta.url),"utf8"));
fixture.subject.actionId="debian.access.apply";
fixture.subject.hostId=fixture.input.hostId;
fixture.subject.consoleConfirmation.hostIdentityDigest=fixture.input.hostIdentityDigest;
fixture.subject.callerUid=fixture.input.automationUid;
fixture.probes=[{schema:"vegastack-labs.dev/host-access-probe-request",schemaVersion:"1.0.0",kind:"collect",request:{...fixture.subject}}];

test("access import accepts inert server-compiled subject and collection placeholders",()=>{
 const loaded=readHostPolicy("access",JSON.stringify(fixture));
 assert.equal(loaded.request.subject.actionInput,"{}");
 assert.equal(hostPolicySummary(loaded).hostId,fixture.input.hostId);
});
test("access import rejects unknown private fields inside the actual policy and probe body",()=>{
 const unknown=structuredClone(fixture);unknown.input.privateKey="secret-canary";
 assert.throws(()=>readHostPolicy("access",JSON.stringify(unknown)));
 const probe=structuredClone(fixture);probe.probes[0].request.actionInput='{"password":"secret-canary"}';
 assert.throws(()=>readHostPolicy("access",JSON.stringify(probe)));
});
test("baseline import rejects arbitrary actions and excess size",()=>{
 assert.throws(()=>readHostPolicy("baseline",JSON.stringify(fixture.subject)));
 assert.throws(()=>readHostPolicy("baseline"," ".repeat(131073)));
});

const roleInput = JSON.parse(await readFile(new URL("../../internal/linuxrole/testdata/role-input.json", import.meta.url), "utf8"));
const actionFixture = JSON.parse(await readFile(new URL("../../internal/localapi/testdata/host-action.json", import.meta.url), "utf8"));
function roleRequest() {
 return {...actionFixture,actionId:"debian.role.apply",hostId:roleInput.hostId,callerUid:roleInput.automationUid,consoleConfirmation:{...actionFixture.consoleConfirmation,hostIdentityDigest:roleInput.hostIdentityDigest},actionInput:JSON.stringify(roleInput)};
}
test("role policy imports exact finite input without fabricating qualification",()=>{
 const request=roleRequest();const loaded=readHostPolicy("role",JSON.stringify(request));
 assert.equal(loaded.kind,"role");assert.equal(loaded.request.actionInput,request.actionInput);
 assert.equal(hostPolicySummary(loaded).hostId,roleInput.hostId);
});
test("role policy rejects cross-host, unknown secret fields and wrong handoff action",()=>{
 const wrong=roleRequest();wrong.hostId="other-host";assert.throws(()=>readHostPolicy("role",JSON.stringify(wrong)));
 const secret=roleRequest();secret.actionInput=JSON.stringify({...roleInput,privateKey:"secret-canary"});assert.throws(()=>readHostPolicy("role",JSON.stringify(secret)));
 const handoff=roleRequest();handoff.actionId="debian.control.handoff";assert.throws(()=>readHostPolicy("role",JSON.stringify(handoff)));
 const arbitrary=roleRequest();arbitrary.actionId="test.write-file";assert.throws(()=>readHostPolicy("role",JSON.stringify(arbitrary)));
});
