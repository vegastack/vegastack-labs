import assert from "node:assert/strict";
import test from "node:test";
import { readFile } from "node:fs/promises";
import { stripTypeScriptTypes } from "node:module";
const fixture = JSON.parse(await readFile(new URL("./fixtures/host-replacement.json",import.meta.url),"utf8"));
const replacementFixture = () => structuredClone(fixture);
const source = await readFile(new URL("../lib/host-replacement-input.ts", import.meta.url), "utf8");
const javascript = stripTypeScriptTypes(source).replace('"../generated/read-api"', JSON.stringify(new URL("../generated/read-api.ts",import.meta.url).href));
const {readHostReplacement} = await import(`data:text/javascript;base64,${Buffer.from(javascript).toString("base64")}`);
test("finite freeze and fresh commit preserve exact immutable input",()=>{
 for(const operation of ["freeze","commit"]){const request=replacementFixture();request.operation=operation;assert.deepEqual(readHostReplacement(JSON.stringify(request)),request);}
});
test("replacement rejects unknown effects secrets mismatched identity and source",()=>{
 for(const change of [r=>{r.operation="erase"},r=>{r.privateKey="secret"},r=>{r.newHostId=r.oldHostId},r=>{r.osPreparation.hostIdentityDigest=r.oldIdentityDigest},r=>{r.aliasBindings[0].ownerHostId="other"},r=>{r.restorationClass="control-database"},r=>{r.payloadIds=["database"]}]) {const r=replacementFixture();change(r);assert.throws(()=>readHostReplacement(JSON.stringify(r)));}
 assert.throws(()=>readHostReplacement(" ".repeat(32769)));
});
