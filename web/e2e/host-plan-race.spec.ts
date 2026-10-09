import { test, expect } from "@playwright/test";
import { readFileSync } from "node:fs";
import { installReadFixture } from "./api-fixture";
import { phase4AcceptancePlan } from "./change-api-fixture";
import { hostRequestDigest } from "../generated/read-api";
const digest=(c:string)=>`sha256:${c.repeat(64)}`;
function envelope(command:string,data:unknown,revision=3){return {schema:"vegastack-labs.dev/browser-run-result",schemaVersion:"1.0.0",toolVersion:"test",command,runId:null,status:"succeeded",changed:false,recoveryEpoch:0,stateRevision:revision,snapshotDigest:null,releaseBuildId:"test",sourceRevision:null,planId:null,errors:[],data};}

test("delayed plan for draft A cannot attach beneath newer policy draft B",async({page})=>{
 await installReadFixture(page);
 const input=JSON.parse(readFileSync(__dirname+"/../../internal/linuxrole/testdata/role-input.json","utf8"));
 const request=JSON.parse(readFileSync(__dirname+"/../../internal/localapi/testdata/host-action.json","utf8"));
 Object.assign(request,{actionId:"debian.role.apply",hostId:input.hostId,callerUid:input.automationUid,actionInput:JSON.stringify(input)});request.consoleConfirmation.hostIdentityDigest=input.hostIdentityDigest;
 const drafts=[digest("a"),digest("b")].map(d=>({contentDigest:d,draftId:`host-action-${d.slice(7,39)}`,declarationId:`host-action-${d.slice(7,39)}`}));
 let draftCalls=0,planReads=0;let release!:()=>void;let started!:()=>void;
 const delayed=new Promise<void>(r=>{release=r});const planningStarted=new Promise<void>(r=>{started=r});
 await page.route("**/api/v1/host-actions/draft",async route=>{const body=route.request().postDataJSON();const originalRequestDigest=await hostRequestDigest("vegastack-labs.dev/host-action-request",body);const draft=drafts[draftCalls++];await route.fulfill({json:envelope("api.v1.host-actions.draft",{schema:"vegastack-labs.dev/host-action-submission",schemaVersion:"1.0.0",...draft,originalRequestDigest,stateRevision:3,recoveryEpoch:0})});});
 await page.route("**/plan-preparation",route=>route.fulfill({json:envelope("api.v1.declarations.plan-preparation.get",{schema:"vegastack-labs.dev/plan-preparation",schemaVersion:"1.0.0",declarationId:drafts[0].declarationId,declarationRevision:1,expectedStateRevision:3,recoveryEpoch:0,observationFingerprint:digest("c")})}));
 await page.route("**/api/v1/declarations/*/plans",async route=>{started();await delayed;const plan={...phase4AcceptancePlan,planId:"plan-delayed-a",declarationId:drafts[0].declarationId,binding:{...phase4AcceptancePlan.binding,declarationRevision:2,priorStateRevision:3,stateRevision:4,recoveryEpoch:0,observationFingerprint:digest("c")}};await route.fulfill({json:envelope("api.v1.plans.create",{plan,readablePlan:"Draft A plan",canonicalPlan:JSON.stringify(plan)},4)});});
 await page.route("**/api/v1/plans/plan-delayed-a",route=>{planReads++;return route.abort();});
 await page.goto("/nodes");await page.getByRole("button",{name:"Role and service handoff",exact:true}).click();
 const load=async()=>page.getByLabel("Prepared role policy file").setInputFiles({name:"role.json",mimeType:"application/json",buffer:Buffer.from(JSON.stringify(request))});
 await load();await page.getByRole("button",{name:"Prepare role draft",exact:true}).click();await expect(page.getByText(`Declaration: ${drafts[0].declarationId}`,{exact:true})).toBeVisible();
 await page.getByRole("button",{name:"Create exact plan",exact:true}).click();await planningStarted;
 request.idempotencyKey="new-role-draft-b";await load();await page.getByRole("button",{name:"Prepare role draft",exact:true}).click();await expect(page.getByText(`Declaration: ${drafts[1].declarationId}`,{exact:true})).toBeVisible();
 release();await expect(page.getByRole("button",{name:"Create exact plan",exact:true})).toBeEnabled();
 await expect(page.getByText(`Declaration: ${drafts[1].declarationId}`,{exact:true})).toBeVisible();expect(planReads).toBe(0);await expect(page.getByText("No exact server plan is available for this operation.",{exact:true})).toBeVisible();
});
