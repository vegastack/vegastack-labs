"use client";
import { FieldHelp } from "@/components/field-help";
import { useState } from "react";
import { PageHeader } from "@/components/ui/page-header";
import { Button } from "@/components/ui/button";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { ReadViewState } from "@/components/read-view-state";
import { usePeople, usePersonAccess } from "@/lib/operator-access-queries";

function State({ state, subject = "People" }: { state: string; subject?: string }) {
  const kind = state as
    | "loading"
    | "denied"
    | "unavailable"
    | "error"
    | "stale";
  return (
    <ReadViewState
      kind={kind}
      title={
        state === "denied"
          ? `${subject} access denied`
          : state === "loading"
            ? `Loading ${subject.toLowerCase()}`
            : `${subject} could not be read`
      }
      description={
        state === "denied"
          ? "Your account needs permission to view these people, devices and permissions. Ask an administrator for access."
          : state === "stale"
            ? "Showing retained records after a temporary failure. Refresh to check current state."
            : "Refresh to request current authorized records."
      }
    />
  );
}
export function PeopleView() {
  const [after, setAfter] = useState("");
  const [selected, setSelected] = useState<string | null>(null);
  const view = usePeople(after);
  const visible = view.state === "current" || view.state === "stale";
  return (
    <>
      <PageHeader
        title="People"
        description="Choose a person to see their registered devices and what they are allowed to do."
        actions={
          <Button
            variant="outline"
            loading={view.isFetching}
            onClick={() => {
              setSelected(null);
              view.refresh();
            }}
          >
            Refresh People
          </Button>
        }
      />
      {view.state !== "current" ? <State state={view.state} /> : null}
      {visible && view.data ? (
        <>
          <ul aria-label="People list" className="grid gap-4">
            {view.data.data.people.map((person) => (
              <li key={person.principalId}>
                <Card>
                  <CardHeader>
                    <CardTitle>{person.principalId}</CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-3 break-all">
                    <div>
                      Status: {person.status}
                      <details><summary className="cursor-pointer">Technical details</summary>Permission record version: {person.grantRevision}</details>
                    </div>
                    <Button
                      variant="outline"
                      onClick={() => setSelected(person.principalId)}
                    >
                      View access for {person.principalId}
                    </Button>
                  </CardContent>
                </Card>
              </li>
            ))}
          </ul>
          {!view.data.data.people.length ? (
            <p>No people are visible to your account.</p>
          ) : null}
          <div className="flex gap-2 py-4">
            {after ? (
              <Button
                variant="outline"
                onClick={() => {
                  setAfter("");
                  setSelected(null);
                }}
              >
                First people page
              </Button>
            ) : null}
            {view.data.data.nextAfter ? (
              <Button
                variant="outline"
                onClick={() => {
                  setAfter(view.data!.data.nextAfter);
                  setSelected(null);
                }}
              >
                Next people page
              </Button>
            ) : null}
          </div>
        </>
      ) : null}
      {visible && selected ? (
        <section aria-label={`Access for ${selected}`}>
          <h2 className="text-lg font-semibold break-all">
            Access for {selected}
          </h2>
          <PersonRecords
            key={`${selected}-devices`}
            principalId={selected}
            kind="devices"
          />
          <PersonRecords
            key={`${selected}-grants`}
            principalId={selected}
            kind="grants"
          />
        </section>
      ) : null}
    </>
  );
}
function PersonRecords({
  principalId,
  kind,
}: {
  principalId: string;
  kind: "devices" | "grants";
}) {
  const [after, setAfter] = useState("");
  const view = usePersonAccess(principalId, kind, after);
  const visible = view.state === "current" || view.state === "stale";
  const data = visible ? view.data?.data : undefined;
  return (
    <Card className="my-4">
      <CardHeader>
        <CardTitle>{kind === "devices" ? "Registered devices" : "Permissions"} <FieldHelp label={kind === "devices" ? "Registered devices" : "Permissions"}>{kind === "devices" ? "Devices recorded for this person. A record alone does not prove that a device is connected or trusted." : "A permission states which action this person can take, on which resource, and whether that permission is active. Ask an administrator if an expected permission is missing."}</FieldHelp></CardTitle>
        <Button
          variant="outline"
          loading={view.isFetching}
          onClick={view.refresh}
        >
          Refresh {kind}
        </Button>
      </CardHeader>
      <CardContent className="space-y-3 break-all">
        {view.state !== "current" ? <State state={view.state} subject={kind === "devices" ? "Devices" : "Grants"} /> : null}
        {data && "devices" in data ? (
          <ul aria-label="Devices">
            {data.devices.map((d) => (
              <li key={d.deviceId}>
                {d.deviceId}: {d.status}<details><summary className="cursor-pointer">Technical details</summary>Device record version: {d.deviceRevision}</details>
              </li>
            ))}
          </ul>
        ) : null}
        {data && "grants" in data ? (
          <ul aria-label="Grants">
            {data.grants.map((g) => (
              <li key={g.grantId}>
                {g.role}: {g.action} on {g.resourceKind}/{g.resourceId} · {g.status}
                <details><summary className="cursor-pointer">Technical details</summary>Permission ID: {g.grantId} · Capability: {g.capability} · Version: {g.grantRevision}{g.branch ? ` · Branch: ${g.branch}` : ""}</details>
              </li>
            ))}
          </ul>
        ) : null}
        {data &&
        (("devices" in data && data.devices.length === 0) ||
          ("grants" in data && data.grants.length === 0)) ? (
          <p>No {kind} are recorded for this person.</p>
        ) : null}
        {after ? (
          <Button variant="outline" onClick={() => setAfter("")}>
            First {kind} page
          </Button>
        ) : null}
        {data?.nextAfter ? (
          <Button variant="outline" onClick={() => setAfter(data.nextAfter)}>
            Next {kind} page
          </Button>
        ) : null}
      </CardContent>
    </Card>
  );
}
