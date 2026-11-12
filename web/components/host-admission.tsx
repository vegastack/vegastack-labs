"use client";

import { FieldHelp } from "@/components/field-help";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { useHostAdmission } from "@/lib/host-lifecycle-queries";

export function HostAdmission({ hostId, revision, epoch }: { hostId: string; revision: number; epoch: number }) {
  const baseline = useHostAdmission(hostId, "host.hardening-baseline", revision, epoch);
  const role = useHostAdmission(hostId, "host.role-admission", revision, epoch);
  const busy = baseline.isFetching || role.isFetching;
  return <Card><CardHeader><CardTitle>Ready to run applications?</CardTitle><CardDescription>Check the recorded security and role requirements for {hostId}. Being registered or having software installed does not mean the machine is ready.</CardDescription></CardHeader><CardContent className="space-y-3">
    {baseline.error || role.error ? <p role="alert">Readiness checks could not be loaded. Do not assume this machine is ready.</p> : null}
    {[{ label: "Security requirements", query: baseline }, { label: "Assigned role requirements", query: role }].map(({ label, query }) => <div key={label} role="status">
      <p>{label}: {query.isFetching ? "Checking" : query.error ? "Unavailable" : query.data ? ({passed: "Required check passed", blocked: "Needs attention", stale: "Check is out of date", unknown: "Readiness is unknown", "not-applicable": "Not required for this machine"})[query.data.data.evaluation.outcome] : "Not checked"}</p>
      {query.data && !query.error && !query.isFetching ? <details><summary className="cursor-pointer text-sm">Check technical details</summary><p>Reason: {query.data.data.evaluation.reasonCode}</p><p>Evidence: {query.data.data.evaluation.evidenceSource}; recovery epoch {query.data.data.evaluation.recoveryEpoch}</p></details> : null}
    </div>)}
    <p>If a check is missing or out of date, ask an administrator to prepare the relevant security, role or connection check under Repair or configure a node. Review and approve its plan, then refresh these results.</p>
    <p>These checks cover the machine’s recorded requirements. The selected application or provider may have additional requirements; unsupported operating systems cannot be marked ready here.</p>
    <FieldHelp label="Machine readiness">Security checks cover the approved operating-system configuration. Role checks cover the job assigned to the machine. Both need current server-verified results; a saved draft, successful install or fixture result does not replace them.</FieldHelp>
    <Button disabled={busy} variant="outline" onClick={() => { void baseline.refetch(); void role.refetch(); }}>Refresh readiness checks</Button>
  </CardContent></Card>;
}

export function InitialControlGuidance() {
  return <Card><CardHeader><CardTitle>First control service setup</CardTitle><CardDescription>For infrastructure administrators creating the first control service. This requires local setup before the Console can manage it.</CardDescription></CardHeader><CardContent className="space-y-3 text-sm">
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
