"use client";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { useHostAdmission } from "@/lib/host-lifecycle-queries";

export function HostAdmission({ hostId, revision, epoch }: { hostId: string; revision: number; epoch: number }) {
  const baseline = useHostAdmission(hostId, "host.hardening-baseline", revision, epoch);
  const role = useHostAdmission(hostId, "host.role-admission", revision, epoch);
  const busy = baseline.isFetching || role.isFetching;
  return <Card><CardHeader><CardTitle>Workload admission</CardTitle><CardDescription>These are current server evaluations for {hostId}. A successful installation run does not imply admission.</CardDescription></CardHeader><CardContent className="space-y-3">
    {baseline.error || role.error ? <p role="alert">Admission could not be read. Workload qualification is unknown.</p> : null}
    {[{ label: "Baseline", query: baseline }, { label: "Role admission", query: role }].map(({ label, query }) => <div key={label} role="status">
      <p>{label}: {query.isFetching ? "Checking" : query.error ? "Unavailable" : query.data?.data.evaluation.outcome ?? "Not checked"}</p>
      {query.data && !query.error && !query.isFetching ? <><p>Reason: {query.data.data.evaluation.reasonCode}</p><p>Evidence: {query.data.data.evaluation.evidenceSource}; recovery epoch {query.data.data.evaluation.recoveryEpoch}</p></> : null}
    </div>)}
    <p>Missing or stale role evidence leaves this host unadmitted. Prepare the appropriate role collection or access probe plan below, then read the gates again.</p>
    <p>Provider capabilities and native acceptance remain separate requirements. Unsupported platforms cannot be qualified by this workflow.</p>
    <Button disabled={busy} variant="outline" onClick={() => { void baseline.refetch(); void role.refetch(); }}>Read current admission</Button>
  </CardContent></Card>;
}

export function InitialControlGuidance() {
  return <Card><CardHeader><CardTitle>First control service setup</CardTitle><CardDescription>Local administrator steps precede authenticated Console workflows.</CardDescription></CardHeader><CardContent className="space-y-3 text-sm">
    <ol className="list-decimal space-y-2 pl-5">
      <li>An administrator prepares the supported Linux host, dedicated nonroot account, protected paths, verified executable and local trust. Keep a working recovery path.</li>
      <li>Run <code>vsk-labs server prepare --file &lt;role-input.json&gt;</code> to inspect the exact account, directory and service files. Preparation is inert.</li>
      <li>Prepare the protected setup record and server profile with the existing Slack workspace/user mapping and secret references. Run <code>vsk-labs server run --config &lt;profile&gt; --setup &lt;record&gt;</code> in the foreground. The assigned human approves the exact setup through Slack.</li>
      <li>Once authenticated server authority exists, prepare the control role plan. Review and approve its exact changes, then prepare a separate <code>debian.control.handoff</code> plan bound to the existing process and database.</li>
      <li>After handoff, create a fresh <code>debian.control.handoff.verify</code> plan and collect current admission evidence. A running service alone is not workload admission.</li>
    </ol>
    <p>This page does not create accounts, configure Slack, initialize SQLite or grant administrator access. The macOS role workflow and future provider enrollment are unavailable here.</p>
  </CardContent></Card>;
}
