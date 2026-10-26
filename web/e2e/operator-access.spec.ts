import { test, expect } from "@playwright/test";
import { installReadFixture } from "./api-fixture";
const contract = (name: string) => ({
  schema: `vegastack-labs.dev/operator-${name}`,
  schemaVersion: "1.0.0",
});
const person = {
  ...contract("person"),
  principalId: "person-a",
  status: "active",
  grantRevision: 1,
};
function envelope(command: string, data: unknown) {
  return {
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
  };
}
const people = (items: unknown[]) => ({
  ...contract("people-page"),
  people: items,
  nextAfter: "",
  stateRevision: 3,
  recoveryEpoch: 0,
});
const fail = (op: string, code: string, retryable = false) => ({
  ...envelope(op, {}),
  status: "failed",
  errors: [{ code, target: "operator-access", retryable }],
});

test("people reads real typed records, devices and grants with keyboard and narrow layout", async ({
  page,
}, info) => {
  await installReadFixture(page);
  await page.setViewportSize({ width: 390, height: 844 });
  await page.route("**/api/v1/people?**", (r) =>
    r.fulfill({ json: envelope("api.v1.people.list", people([person])) }),
  );
  await page.route("**/api/v1/devices?**", (r) =>
    r.fulfill({
      json: envelope("api.v1.devices.list", {
        ...contract("device-list"),
        devices: [
          {
            ...contract("device"),
            deviceId: "device-a",
            principalId: "person-a",
            status: "approved",
            deviceRevision: 2,
          },
        ],
        nextAfter: "",
        stateRevision: 3,
        recoveryEpoch: 0,
      }),
    }),
  );
  await page.route("**/api/v1/grants?**", (r) =>
    r.fulfill({
      json: envelope("api.v1.grants.list", {
        ...contract("grant-list"),
        grants: [
          {
            ...contract("grant"),
            grantId: "grant-a",
            principalId: "person-a",
            role: "reader",
            action: "read",
            capability: "host.read",
            resourceKind: "host",
            resourceId: "host-a",
            branch: "",
            status: "active",
            grantRevision: 1,
          },
        ],
        nextAfter: "",
        stateRevision: 3,
        recoveryEpoch: 0,
      }),
    }),
  );
  await page.goto("/people");
  const inspect = page.getByRole("button", {
    name: "Inspect person-a",
    exact: true,
  });
  await inspect.focus();
  await page.keyboard.press("Enter");
  await expect(
    page.getByRole("list", { name: "Devices", exact: true }),
  ).toContainText("device-a: approved; revision 2");
  await expect(
    page.getByRole("list", { name: "Grants", exact: true }),
  ).toContainText("host-a");
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= window.innerWidth,
    ),
  ).toBe(true);
  await page.screenshot({
    path: info.outputPath("people-current-narrow.png"),
    fullPage: true,
  });
});
test("denial clears previously loaded people and detail caches", async ({
  page,
}) => {
  await installReadFixture(page);
  let denied = false;
  await page.route("**/api/v1/people?**", (r) =>
    r.fulfill({ json: envelope("api.v1.people.list", people([person])) }),
  );
  await page.route("**/api/v1/devices?**", (r) =>
    r.fulfill(
      denied
        ? {
            status: 403,
            json: fail("api.v1.devices.list", "AUTHORIZATION_DENIED"),
          }
        : {
            json: envelope("api.v1.devices.list", {
              ...contract("device-list"),
              devices: [
                {
                  ...contract("device"),
                  deviceId: "device-a",
                  principalId: "person-a",
                  status: "approved",
                  deviceRevision: 1,
                },
              ],
              nextAfter: "",
              stateRevision: 3,
              recoveryEpoch: 0,
            }),
          },
    ),
  );
  await page.route("**/api/v1/grants?**", (r) =>
    r.fulfill({
      json: envelope("api.v1.grants.list", {
        ...contract("grant-list"),
        grants: [],
        nextAfter: "",
        stateRevision: 3,
        recoveryEpoch: 0,
      }),
    }),
  );
  await page.goto("/people");
  await page
    .getByRole("button", { name: "Inspect person-a", exact: true })
    .click();
  await expect(
    page.getByRole("list", { name: "Devices", exact: true }),
  ).toContainText("device-a");
  denied = true;
  await page
    .getByRole("button", { name: "Refresh devices", exact: true })
    .click();
  await expect(
    page.getByText("People access denied", { exact: true }),
  ).toBeVisible();
  await expect(
    page.getByRole("list", { name: "People list", exact: true }),
  ).toHaveCount(0);
  await expect(page.getByText("person-a", { exact: true })).toHaveCount(0);
  await expect(page.getByText(/device-a/)).toHaveCount(0);
});
test("empty, error and explicit refresh states remain distinct", async ({
  page,
}) => {
  await installReadFixture(page);
  let calls = 0;
  await page.route("**/api/v1/people?**", (r) =>
    ++calls === 1
      ? r.fulfill({
          status: 500,
          json: fail("api.v1.people.list", "INTEGRITY_FAILURE"),
        })
      : r.fulfill({ json: envelope("api.v1.people.list", people([])) }),
  );
  await page.goto("/people");
  await expect(
    page.getByText("People could not be read", { exact: true }),
  ).toBeVisible();
  await page
    .getByRole("button", { name: "Refresh People", exact: true })
    .click();
  await expect(
    page.getByText("No people are visible to your account.", { exact: true }),
  ).toBeVisible();
  expect(calls).toBe(2);
});
test("configured providers show unknown connectivity and absent providers unavailable", async ({
  page,
}, info) => {
  await installReadFixture(page);
  await page.route("**/api/v1/providers", (r) =>
    r.fulfill({
      json: envelope("api.v1.providers.list", {
        ...contract("provider-list"),
        providers: [
          {
            ...contract("provider"),
            capability: "identity",
            configured: true,
            connectivity: "unknown",
          },
          {
            ...contract("provider"),
            capability: "backup.offsite",
            configured: false,
            connectivity: "unavailable",
          },
        ],
        stateRevision: 3,
        recoveryEpoch: 0,
      }),
    }),
  );
  await page.goto("/providers");
  const providers = page.getByRole("list", { name: "Provider capabilities" });
  await expect(providers).toContainText("Connectivity: unknown");
  await expect(providers).toContainText("Not configured");
  await expect(providers).toContainText("Connectivity: unavailable");
  await expect(providers).not.toContainText("healthy");
  await page.screenshot({
    path: info.outputPath("providers-configured.png"),
    fullPage: true,
  });
});
