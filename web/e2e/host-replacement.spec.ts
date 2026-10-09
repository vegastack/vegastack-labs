import { test, expect } from "@playwright/test";
import { readFileSync } from "node:fs";
import { installReadFixture } from "./api-fixture";
const fixture=JSON.parse(readFileSync(__dirname+"/../test/fixtures/host-replacement.json","utf8"));
function envelope(command:string,data:unknown,code?:string){return {schema:"vegastack-labs.dev/browser-run-result",schemaVersion:"1.0.0",toolVersion:"test",command,runId:null,status:code?"failed":"succeeded",changed:false,recoveryEpoch:0,stateRevision:3,snapshotDigest:null,releaseBuildId:"test",sourceRevision:null,planId:null,errors:code?[{code,message:"Current authority required.",retryable:false}]:[],data};}

test("replacement preview preserves both identities and needs separate impact confirmation",async({page})=>{
 await installReadFixture(page);let calls=0;let captured:any;
 await page.route("**/api/v1/host-replacements",route=>{calls++;captured=route.request().postDataJSON();return route.fulfill({json:envelope("api.v1.host-replacements.prepare",{schema:"vegastack-labs.dev/host-replacement-submission",schemaVersion:"1.0.0",replacementId:"replacement-a",draftId:"replacement-draft",declarationId:"replacement-draft",contentDigest:fixture.oldIdentityDigest,stateRevision:3,recoveryEpoch:0})});});
 await page.goto("/nodes");
 await page.getByLabel("Prepared replacement request file").setInputFiles({name:"replacement.json",mimeType:"application/json",buffer:Buffer.from(JSON.stringify(fixture))});
 const impact=page.getByRole("region",{name:"Replacement impact"});
 await expect(impact).toContainText("Old host: old-host");await expect(impact).toContainText("New host: new-host");await expect(impact).toContainText("alias-a owned by old-host");
 await expect(page.getByRole("button",{name:"Prepare replacement draft",exact:true})).toBeDisabled();expect(calls).toBe(0);
 await page.getByLabel("I reviewed both hosts, the aliases and preserved data. This confirmation does not approve execution.").check();
 await page.getByRole("button",{name:"Prepare replacement draft",exact:true}).click();
 await expect(page.getByText("Declaration: replacement-draft",{exact:true})).toBeVisible();expect(calls).toBe(1);expect(captured).toEqual(fixture);
 await expect(page.getByRole("button",{name:"Execute exact plan",exact:true})).toHaveCount(0);
});

test("replacement source and partial verification never imply committed ownership",async({page})=>{
 await installReadFixture(page);
 const request={...fixture,restorationClass:"control-database",source:{schema:"vegastack-labs.dev/host-replacement-source-reference",schemaVersion:"1.0.0",pointId:"point-a",custodyReferenceId:"custody-a",manifestDigest:fixture.oldIdentityDigest,sourceBindingDigest:fixture.newIdentityDigest,custodyBindingDigest:fixture.oldTargetDigest}};
 const state={schema:"vegastack-labs.dev/host-replacement-state",schemaVersion:"1.0.0",replacementId:"replacement-a",declarationId:"replacement-draft",oldHostId:fixture.oldHostId,newHostId:fixture.newHostId,bindingDigest:fixture.oldIdentityDigest,oldIdentityDigest:fixture.oldIdentityDigest,newIdentityDigest:fixture.newIdentityDigest,roleBindingDigest:fixture.proposedRoleBindingDigest,declarationRevision:1,priorOwnershipGeneration:1,proposedOwnershipGeneration:2,roleIntentRevision:0,stateRevision:3,recoveryEpoch:0,status:"verification-required",restorationClass:"control-database",aliasBindings:fixture.aliasBindings,nextAction:"verify-restore",blockers:["destination-native-admission-required"],planId:null,runId:null,restorePlanId:"restore-a"};
 await page.route("**/api/v1/host-replacements/replacement-a",route=>route.fulfill({json:envelope("api.v1.host-replacements.get",state)}));
 await page.goto("/nodes");await page.getByLabel("Prepared replacement request file").setInputFiles({name:"control.json",mimeType:"application/json",buffer:Buffer.from(JSON.stringify(request))});
 await expect(page.getByRole("region",{name:"Replacement impact"})).toContainText("Recovery point: point-a; custody reference: custody-a");
 await page.getByLabel("Replacement ID",{exact:true}).fill("replacement-a");await page.getByRole("button",{name:"Inspect replacement",exact:true}).click();
 const current=page.getByRole("region",{name:"Current replacement state"});await expect(current).toContainText("Replacement status: verification-required");await expect(current).toContainText("Safe next action: verify-restore");await expect(current).toContainText("destination-native-admission-required");await expect(current).toContainText("Ownership transfer is incomplete");
 await expect(page.getByRole("button",{name:"Execute exact plan",exact:true})).toHaveCount(0);
});

for (const code of ["AUTHORIZATION_DENIED","PLAN_STALE"]) test(`replacement ${code} clears imported execution state without retry`,async({page})=>{
 await installReadFixture(page);let calls=0;
 await page.route("**/api/v1/host-replacements",route=>{calls++;return route.fulfill({status:code==="AUTHORIZATION_DENIED"?403:409,json:envelope("api.v1.host-replacements.prepare",null,code)});});
 await page.goto("/nodes");await page.getByLabel("Prepared replacement request file").setInputFiles({name:"request.json",mimeType:"application/json",buffer:Buffer.from(JSON.stringify(fixture))});await page.getByLabel("I reviewed both hosts, the aliases and preserved data. This confirmation does not approve execution.").check();await page.getByRole("button",{name:"Prepare replacement draft",exact:true}).click();
 await expect(page.getByText("Host workflow unavailable",{exact:true})).toBeVisible();await expect(page.getByLabel("Prepared replacement request file")).toHaveCount(0);expect(calls).toBe(1);
});
