"use client";
import { useState } from "react";
import { PageHeader } from "@/components/ui/page-header";
import { Button } from "@/components/ui/button";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { ReadViewState } from "@/components/read-view-state";
import { usePeople, usePersonAccess } from "@/lib/operator-access-queries";

function State({ state }: { state: string }) {
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
          ? "People access denied"
          : state === "loading"
            ? "Loading people"
            : "People could not be read"
      }
      description={
        state === "denied"
          ? "Current authorization is required to view people, devices and grants."
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
        description="People, devices and grants visible under your current policy read permissions."
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
                    <p>
                      Status: {person.status}; grant revision{" "}
                      {person.grantRevision}
                    </p>
                    <Button
                      variant="outline"
                      onClick={() => setSelected(person.principalId)}
                    >
                      Inspect {person.principalId}
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
        <CardTitle className="capitalize">{kind}</CardTitle>
        <Button
          variant="outline"
          loading={view.isFetching}
          onClick={view.refresh}
        >
          Refresh {kind}
        </Button>
      </CardHeader>
      <CardContent className="space-y-3 break-all">
        {view.state !== "current" ? <State state={view.state} /> : null}
        {data && "devices" in data ? (
          <ul aria-label="Devices">
            {data.devices.map((d) => (
              <li key={d.deviceId}>
                {d.deviceId}: {d.status}; revision {d.deviceRevision}
              </li>
            ))}
          </ul>
        ) : null}
        {data && "grants" in data ? (
          <ul aria-label="Grants">
            {data.grants.map((g) => (
              <li key={g.grantId}>
                {g.grantId}: {g.role} · {g.action} · {g.capability} ·{" "}
                {g.resourceKind}/{g.resourceId} · {g.status}; revision{" "}
                {g.grantRevision}
                {g.branch ? ` · ${g.branch}` : ""}
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
