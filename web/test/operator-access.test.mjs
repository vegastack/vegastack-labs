import assert from "node:assert/strict";
import test from "node:test";
import { createReadClient, ReadClientError } from "../generated/read-api.ts";
const person = {
  schema: "vegastack-labs.dev/operator-person",
  schemaVersion: "1.0.0",
  principalId: "person-a",
  status: "active",
  grantRevision: 1,
};
const people = {
  schema: "vegastack-labs.dev/operator-people-page",
  schemaVersion: "1.0.0",
  people: [person],
  nextAfter: "",
  stateRevision: 3,
  recoveryEpoch: 0,
};
const envelope = (command, data) => ({
  schema: "vegastack-labs.dev/browser-run-result",
  schemaVersion: "1.0.0",
  toolVersion: "test",
  command,
  runId: null,
  status: "succeeded",
  changed: false,
  recoveryEpoch: 0,
  stateRevision: 3,
  snapshotDigest: null,
  releaseBuildId: "test",
  sourceRevision: null,
  planId: null,
  errors: [],
  data,
});
test("operator client uses bounded GET query and rejects private projection additions", async () => {
  let url;
  const client = createReadClient(async (input) => {
    url = input;
    return new Response(JSON.stringify(envelope("api.v1.people.list", people)));
  });
  const got = await client.listPeople({ after: "person-0", limit: 1 });
  assert.equal(got.data.people[0].principalId, "person-a");
  assert.equal(url, "/api/v1/people?after=person-0&limit=1");
  await assert.rejects(
    () => client.listPeople({ limit: 101 }),
    ReadClientError,
  );
  const bad = createReadClient(
    async () =>
      new Response(
        JSON.stringify(
          envelope("api.v1.people.list", {
            ...people,
            people: [{ ...person, externalSubject: "private-canary" }],
          }),
        ),
      ),
  );
  await assert.rejects(
    () => bad.listPeople(),
    (e) => e instanceof ReadClientError && e.code === "INTEGRITY_FAILURE",
  );
});
test("devices require explicit principal query and encoded continuation", async () => {
  let url;
  const client = createReadClient(async (input) => {
    url = input;
    return new Response(
      JSON.stringify(
        envelope("api.v1.devices.list", {
          schema: "vegastack-labs.dev/operator-device-list",
          schemaVersion: "1.0.0",
          devices: [],
          nextAfter: "",
          stateRevision: 3,
          recoveryEpoch: 0,
        }),
      ),
    );
  });
  await client.listDevices({
    principalId: "person-a",
    after: "device-a",
    limit: 5,
  });
  assert.equal(
    url,
    "/api/v1/devices?principalId=person-a&after=device-a&limit=5",
  );
});

test("operator client rejects another principal's devices and mismatched revision bindings", async () => {
  const list = { schema: "vegastack-labs.dev/operator-device-list", schemaVersion: "1.0.0", devices: [{ schema: "vegastack-labs.dev/operator-device", schemaVersion: "1.0.0", deviceId: "device-a", principalId: "private-person", status: "approved", deviceRevision: 1 }], nextAfter: "", stateRevision: 3, recoveryEpoch: 0 };
  const client = createReadClient(async () => new Response(JSON.stringify(envelope("api.v1.devices.list", list))));
  await assert.rejects(() => client.listDevices({ principalId: "person-a" }), e => e instanceof ReadClientError && e.code === "INTEGRITY_FAILURE");
  const mismatch = createReadClient(async () => new Response(JSON.stringify(envelope("api.v1.people.list", { ...people, stateRevision: 4 }))));
  await assert.rejects(() => mismatch.listPeople(), e => e instanceof ReadClientError && e.code === "INTEGRITY_FAILURE");
});

test("provider configuration cannot imply healthy connectivity", async () => {
 const list={schema:"vegastack-labs.dev/operator-provider-list",schemaVersion:"1.0.0",providers:[{schema:"vegastack-labs.dev/operator-provider",schemaVersion:"1.0.0",capability:"identity",configured:true,connectivity:"healthy"}],stateRevision:3,recoveryEpoch:0};
 const client=createReadClient(async()=>new Response(JSON.stringify(envelope("api.v1.providers.list",list))));
 await assert.rejects(()=>client.listProviders(),e=>e instanceof ReadClientError&&e.code==="INTEGRITY_FAILURE");
});
