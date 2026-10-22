import { test, expect } from "@playwright/test";
import { installReadFixture } from "./api-fixture";
const host={schema:"vegastack-labs.dev/managed-host",schemaVersion:"1.0.0",hostId:"host-a",targetId:"target-a",observationId:"observation-a",profileId:"profile-a",identityClass:"physical",status:"adopted-unadmitted",stateRevision:3,recoveryEpoch:0};
function envelope(command:string,data:unknown) {return {schema:"vegastack-labs.dev/browser-run-result",schemaVersion:"1.0.0",toolVersion:"test",command,runId:null,status:"succeeded",changed:false,recoveryEpoch:0,stateRevision:3,snapshotDigest:null,releaseBuildId:"test",sourceRevision:null,planId:null,errors:[],data};}
test("registered hosts appear automatically and can be inspected without entering an ID",async({page},info)=>{
 await installReadFixture(page);let count=0;
 await page.route("**/api/v1/hosts",route=>{count++;return route.fulfill({json:envelope("api.v1.hosts.list",{schema:"vegastack-labs.dev/managed-host-list",schemaVersion:"1.0.0",hosts:[host],stateRevision:3,recoveryEpoch:0})});});
 await page.route("**/api/v1/hosts/host-a",route=>route.fulfill({json:envelope("api.v1.hosts.get",host)}));
 await page.route("**/api/v1/gates/host.*",route=>route.fulfill({status:503,json:{...envelope("api.v1.gates.get",null),status:"failed",errors:[{code:"DEPENDENCY_UNAVAILABLE",message:"Admission unavailable.",retryable:false}]}}));
 await page.goto("/nodes");
 await expect(page.getByRole("list",{name:"Registered host list"})).toContainText("host-a");
 await expect(page.getByRole("list",{name:"Registered host list"})).toContainText("Workload admission requires current checks");
 await page.screenshot({path:info.outputPath("registered-host-list.png"),fullPage:true});
 await page.getByRole("button",{name:"Inspect host-a",exact:true}).click();
 await expect(page.getByText("Host host-a: adopted-unadmitted",{exact:true})).toBeVisible();expect(count).toBe(1);
});
test("empty and unavailable registered lists are distinct and refresh explicitly",async({page})=>{
 await installReadFixture(page);let calls=0;
 await page.route("**/api/v1/hosts",route=>{calls++;if(calls===1)return route.abort("failed");return route.fulfill({json:envelope("api.v1.hosts.list",{schema:"vegastack-labs.dev/managed-host-list",schemaVersion:"1.0.0",hosts:[],stateRevision:3,recoveryEpoch:0})});});
 await page.goto("/nodes");await expect(page.getByText("Registered hosts could not be loaded.",{exact:true})).toBeVisible();expect(calls).toBe(1);
 await page.getByRole("button",{name:"Refresh registered hosts",exact:true}).click();
 await expect(page.getByText("No registered hosts are visible to your account.",{exact:true})).toBeVisible();expect(calls).toBe(2);
});
test("revoking collection access removes previously displayed registrations",async({page})=>{
 await installReadFixture(page);let revoked=false;
 await page.route("**/api/v1/hosts",route=>revoked?route.fulfill({status:403,json:{...envelope("api.v1.hosts.list",null),status:"failed",errors:[{code:"AUTHORIZATION_DENIED",message:"Current authority required.",retryable:false}]}}):route.fulfill({json:envelope("api.v1.hosts.list",{schema:"vegastack-labs.dev/managed-host-list",schemaVersion:"1.0.0",hosts:[host],stateRevision:3,recoveryEpoch:0})}));
 await page.goto("/nodes");await expect(page.getByRole("button",{name:"Inspect host-a",exact:true})).toBeVisible();revoked=true;
 await page.getByRole("button",{name:"Refresh registered hosts",exact:true}).click();
 await expect(page.getByRole("button",{name:"Inspect host-a",exact:true})).toHaveCount(0);
});
