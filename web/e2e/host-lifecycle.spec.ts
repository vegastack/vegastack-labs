import { test, expect, type Page } from "@playwright/test";
import { readFileSync } from "node:fs";
import { installReadFixture } from "./api-fixture";
const fixture=JSON.parse(readFileSync(__dirname+"/../../internal/localapi/testdata/host-target.json","utf8"));
const digest=`sha256:${"a".repeat(64)}`;
function envelope(command:string,data:unknown,code?:string){return {schema:"vegastack-labs.dev/browser-run-result",schemaVersion:"1.0.0",toolVersion:"test",command,runId:null,status:code?"failed":"succeeded",changed:false,recoveryEpoch:0,stateRevision:3,snapshotDigest:null,releaseBuildId:"test",sourceRevision:null,planId:null,errors:code?[{code,message:"Current authority required.",retryable:false}]:[],data};}
async function fillTarget(page:Page){
 const form=page.getByRole("button",{name:"Prepare target draft",exact:true}).locator("..");
 const values:Record<string,string>={"Target ID":fixture.target.targetId,"Exact target address":fixture.target.address,"SSH port":"22","Existing nonroot account":fixture.target.user,"Verified public SSH host key":fixture.target.hostKey,"Profile ID":fixture.target.profileId,"Credential reference ID":fixture.target.credentialReferenceId,"Credential material version":fixture.target.materialVersion,"Expected Debian version":fixture.target.expectedVersion,"Expected architecture":fixture.target.expectedArchitecture,"Current state revision":"1","Recovery epoch":"0"};
 for(const [label,value] of Object.entries(values))await form.getByLabel(label,{exact:true}).fill(value);
 return form;
}
test("preloaded target remains inert and stale plan clears prior forms",async({page},info)=>{
 await installReadFixture(page); let captured:any; let preparations=0;
 await page.route("**/api/v1/host-discovery-targets/draft",async route=>{captured=route.request().postDataJSON();preparations++;await route.fulfill({json:envelope("api.v1.host-discovery-targets.draft",{schema:"vegastack-labs.dev/host-discovery-target-draft-submission",schemaVersion:"1.0.0",draftId:"discovery-draft-one",declarationId:"discovery-draft-one",contentDigest:digest,stateRevision:3,recoveryEpoch:0})});});
 await page.route("**/api/v1/declarations/**/plan-preparation",route=>route.fulfill({status:409,json:envelope("api.v1.plans.prepare",null,"PLAN_STALE")}));
 await page.goto("/nodes");const form=await fillTarget(page);
 await form.getByLabel("Discovery credential mode").selectOption("preloaded-discovery");
 await form.getByLabel("Preloaded public key digest").fill(digest);await form.getByLabel("Administrator-confirmed exact target digest").fill(digest);
 await form.getByRole("button",{name:"Prepare target draft",exact:true}).click();
 await expect(page.getByText("No host action has been applied.")).toBeVisible();
 expect(captured.target.credentialMode).toBe("preloaded-discovery");expect(captured.consoleConfirmation.targetDigest).toBe(digest);expect(preparations).toBe(1);
 await expect(page.getByRole("button",{name:"Execute exact plan"})).toHaveCount(0);
 await page.getByText("No host action has been applied.").scrollIntoViewIfNeeded();
 await page.screenshot({path:info.outputPath("host-target-inert.png"),fullPage:true});
 await page.getByRole("button",{name:"Create exact plan",exact:true}).click();
 await expect(page.getByText("Host workflow unavailable")).toBeVisible();await expect(page.getByLabel("Exact target address",{exact:true})).toHaveCount(0);
 await page.screenshot({path:info.outputPath("host-stale-cleared.png"),fullPage:true});
});
test("temporary transport failure preserves input without retries",async({page})=>{
 await installReadFixture(page);let calls=0;
 await page.route("**/api/v1/host-discovery-targets/draft",route=>{calls++;return route.abort("failed");});
 await page.goto("/nodes");const form=await fillTarget(page);await form.getByRole("button",{name:"Prepare target draft",exact:true}).click();
 await expect(page.getByText("Host operation could not complete")).toBeVisible();await expect(form.getByLabel("Exact target address",{exact:true})).toHaveValue(fixture.target.address);expect(calls).toBe(1);
 await expect(page.getByLabel("Identity class",{exact:true})).toHaveValue("physical");await expect(page.getByLabel("Identity kind",{exact:true})).toHaveValue("product-serial");
});
test("bounded access policy import reviews exact host before any request",async({page})=>{
 await installReadFixture(page);let mutations=0;
 await page.route("**/api/v1/host-access/draft",route=>{mutations++;return route.abort();});
 await page.goto("/nodes");await page.getByRole("button",{name:"Access and firewall",exact:true}).click();
 const policy=JSON.parse(readFileSync(__dirname+"/../../internal/localapi/testdata/host-access.json","utf8"));
 policy.subject.actionId="debian.access.apply";policy.subject.hostId=policy.input.hostId;policy.subject.callerUid=policy.input.automationUid;policy.subject.consoleConfirmation.hostIdentityDigest=policy.input.hostIdentityDigest;
 await page.getByLabel("Prepared access policy file").setInputFiles({name:"policy.json",mimeType:"application/json",buffer:Buffer.from(JSON.stringify(policy))});
 await expect(page.getByText(`Host: ${policy.input.hostId}; target revision ${policy.subject.targetRevision}`)).toBeVisible();
 await expect(page.getByRole("button",{name:"Prepare hardening draft",exact:true})).toBeEnabled();expect(mutations).toBe(0);
 policy.input.privateKey="synthetic-forbidden-field";
 await page.getByLabel("Prepared access policy file").setInputFiles({name:"invalid.json",mimeType:"application/json",buffer:Buffer.from(JSON.stringify(policy))});
 await expect(page.getByText("The file is not a supported bounded Debian policy.",{exact:false})).toBeVisible();await expect(page.getByRole("button",{name:"Prepare hardening draft",exact:true})).toBeDisabled();expect(mutations).toBe(0);
});
test("revoked host read clears unsaved values and inspection state",async({page})=>{
 await installReadFixture(page);
 await page.route("**/api/v1/hosts/host-a",route=>route.fulfill({status:403,json:envelope("api.v1.hosts.get",null,"AUTHORIZATION_DENIED")}));
 await page.goto("/nodes");await fillTarget(page);
 await page.getByLabel("Managed host ID",{exact:true}).fill("host-a");await page.getByRole("button",{name:"Inspect registered host",exact:true}).click();
 await expect(page.getByText("Host workflow unavailable")).toBeVisible();await expect(page.getByLabel("Exact target address",{exact:true})).toHaveCount(0);
 await expect(page.getByRole("button",{name:"Create exact plan",exact:true})).toHaveCount(0);
});
test("registration submits bounded identity enums and seconds-only confirmation",async({page})=>{
 await installReadFixture(page);let captured:any;
 await page.route("**/api/v1/host-observations/observation-a",route=>route.fulfill({json:envelope("api.v1.host-observations.get",{schema:"vegastack-labs.dev/host-observation",schemaVersion:"1.0.0",observationId:"observation-a",targetId:"target-a",targetRevision:1,targetDigest:digest,collector:"collector-a",collectorVersion:"1.0.0",observedAt:"2026-10-08T00:00:00Z",expiresAt:"2026-10-08T00:15:00Z",status:"incomplete",facts:[],blockers:["hardening-unverified"],contentDigest:digest,stateRevision:3,recoveryEpoch:0})}));
 await page.route("**/api/v1/host-adoptions/draft",route=>{captured=route.request().postDataJSON();return route.fulfill({status:403,json:envelope("api.v1.host-adoptions.draft",null,"AUTHORIZATION_DENIED")});});
 await page.goto("/nodes");await page.getByLabel("Saved observation ID",{exact:true}).fill("observation-a");await page.getByRole("button",{name:"Inspect observation",exact:true}).click();
 await expect(page.getByText("Observation observation-a: incomplete")).toBeVisible();
 const form=page.getByRole("button",{name:"Prepare registration",exact:true}).locator("..");
 await form.getByLabel("New managed host ID",{exact:true}).fill("host-a");await form.getByLabel("Independently verified identity digest",{exact:true}).fill(digest);await form.getByLabel("Current state revision",{exact:true}).fill("3");
 await form.getByLabel("Identity class",{exact:true}).selectOption("qualified-virtual");await form.getByLabel("Identity kind",{exact:true}).selectOption("product-uuid");
 await form.getByRole("button",{name:"Prepare registration",exact:true}).click();
 await expect(page.getByText("Host workflow unavailable")).toBeVisible();expect(captured.confirmation.identityClass).toBe("qualified-virtual");expect(captured.confirmation.identityKind).toBe("product-uuid");expect(captured.confirmation.confirmedAt).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/);
});
