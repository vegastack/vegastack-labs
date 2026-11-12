"use client";

import { formatConsoleTime } from "@/components/source-status";
import { HostReplacement } from "@/components/host-replacement";

import { FieldHelp } from "@/components/field-help";

import { useState, useRef, useId, type FormEvent } from "react";
import { HostAdmission, InitialControlGuidance } from "@/components/host-admission";
import { HostPolicyForm } from "@/components/host-policy-form";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { ExactPlanLauncher, type ExactPlanKind } from "@/components/exact-plan-launcher";
import { ReadViewState } from "@/components/read-view-state";
import { useReadFailure } from "@/components/query-provider";
import { classifyReadFailure } from "@/lib/read-queries";
import { useHostAdoption, useHostDiscovery, useHostObservation, useHostPlan, useHostTargetDraft, useManagedHost, useManagedHosts } from "@/lib/host-lifecycle-queries";

const FIELD_GUIDANCE: Record<string, string> = {
  hostId: "A unique name used to identify this machine in Labs, for example lab-test-01. For an existing machine, copy its name from Registered hosts.",
  targetId: "The connection record name for this one machine, for example lab-test-01-ssh. Reuse the exact saved name when discovering it later.",
  address: "The approved IP address or DNS name for this machine, for example 192.0.2.10. Do not enter a URL or a group of machines.",
  port: "The SSH port configured on the machine. Usually 22; confirm with its administrator.",
  user: "An existing nonroot SSH account on this machine, supplied by its administrator, for example lab-operator.",
  hostKey: "Copy the machine's PUBLIC SSH host key from an independently trusted console or administrator record. Never paste a private key or trust an unverified network scan.",
  profileId: "Copy the exact approved configuration profile ID from your administrator's onboarding record. This selects the supported operating-system checks.",
  credentialReferenceId: "Copy an existing credential reference ID from the approved server record. Enter the reference name only, never a password or private key.",
  materialVersion: "Copy the credential version attached to that reference. Ask your administrator if it is missing; do not guess or paste credential contents.",
  osVersion: "The Debian version actually installed, confirmed from the machine's trusted console or administrator record, for example 13.6.",
  architecture: "The machine architecture from the same verified record, for example amd64 or arm64. Use the exact supported value recorded for this target.",
  revision: "Copy the latest state revision from the current server record or administrator's preparation output. Refresh it after a change; this number prevents using outdated state.",
  epoch: "Copy the current recovery epoch from the same server record. It changes after recovery. Do not assume it is zero or reuse an old value.",
  targetRevision: "Copy the revision from the activated connection record after its plan has completed. A saved draft alone is not an activated target.",
  observationId: "Copy the observation ID returned by an earlier discovery. Opening that saved result does not connect to the machine.",
  identityDigest: "Copy the identity fingerprint independently verified against the physical serial or virtual machine UUID in the administrator's identity record. Do not type the serial number here or invent a fingerprint.",
  credentialPublicKeyDigest: "Copy the public-key fingerprint for the discovery-only key your administrator has already installed on this exact machine. Never paste the private key.",
  consoleTargetDigest: "Copy the complete target fingerprint independently confirmed at the machine's trusted console. It must cover this address, identity and discovery key; ask the administrator for this record.",
};
function Field({ name, label, value, number = false }: { name: string; label: string; value?: string; number?: boolean }) {
  const id = useId();
  return <div className="grid content-start gap-1 text-sm"><div className="flex items-start gap-2"><label htmlFor={id}>{label}</label><FieldHelp label={label}>{FIELD_GUIDANCE[name] ?? "Copy this exact value from the current administrator-approved machine record."}</FieldHelp></div><Input id={id} name={name} required defaultValue={value} type={number ? "number" : "text"} min={number ? 0 : undefined} autoComplete="off" /></div>;
}
function form(event: FormEvent<HTMLFormElement>) { event.preventDefault(); return new FormData(event.currentTarget); }
function text(data: FormData, name: string) { return String(data.get(name) ?? "").trim(); }
function number(data: FormData, name: string) { return Number(text(data, name)); }
function key(action: string) { return `console-host-${action}-${crypto.randomUUID()}`; }
function RevisionFields() { return <><Field name="revision" label="Current server state revision" number /><Field name="epoch" label="Current recovery epoch" number /></>; }

export function HostLifecycle({ hostId }: { hostId: string | null }) {
  const hostFailure = useReadFailure("hosts");
  const planFailure = useReadFailure("changes");
  const failure = hostFailure.failure ?? planFailure.failure;
  const clearFailure = hostFailure.clearFailure;
  // Unmount all forms and exact-plan state when scope/session/binding is revoked.
  if (failure) return <ReadViewState kind={classifyReadFailure(failure)} title="Host workflow unavailable" description="Read current state again before preparing a new plan. Previous execution and form state have been cleared." onRetry={clearFailure} />;
  return <HostLifecycleContent initialHostId={hostId} />;
}
function HostLifecycleContent({ initialHostId }: { initialHostId: string | null }) {
  const [hostId, setHostId] = useState(initialHostId);
  const [credentialMode,setCredentialMode]=useState<"qualified-reference"|"preloaded-discovery">("qualified-reference");
  const [observationId, setObservationId] = useState<string | null>(null);
  const [draft, setDraft] = useState<{ declarationId: string; digest: string; kind: ExactPlanKind } | null>(null);
  const selectedDraft = useRef<typeof draft>(null);
  const [plannedDraft, setPlannedDraft] = useState<{ declarationId: string; digest: string; planId: string } | null>(null);
  const planId = plannedDraft && draft && plannedDraft.declarationId === draft.declarationId && plannedDraft.digest === draft.digest ? plannedDraft.planId : null;
  const host = useManagedHost(hostId);
  const registered = useManagedHosts();
  const observation = useHostObservation(observationId);
  const target = useHostTargetDraft(); const discovery = useHostDiscovery(); const adoption = useHostAdoption(); const planning = useHostPlan();
  const error = target.error ?? discovery.error ?? adoption.error ?? planning.error ?? host.error ?? observation.error;
  const busy = target.isPending || discovery.isPending || adoption.isPending || planning.isPending;
  function saveDraft(data: { declarationId: string; contentDigest: string }, kind: ExactPlanKind) { const next = { declarationId: data.declarationId, digest: data.contentDigest, kind }; selectedDraft.current = next; setDraft(next); setPlannedDraft(null); }
  return <section aria-label="Host lifecycle" className="space-y-4">
    <Card><CardHeader><CardTitle>Registered hosts</CardTitle><CardDescription>Choose a registered machine to check whether it is ready to run applications. To add a machine, use the guided administrator steps below.</CardDescription></CardHeader><CardContent className="space-y-4">
      {registered.isPending ? <p role="status">Loading registered hosts…</p> : registered.error ? <div role="alert"><p>Registered hosts could not be loaded.</p><Button variant="outline" onClick={() => registered.refetch()} disabled={registered.isFetching}>Refresh registered hosts</Button></div> : <div className="space-y-3">
        {registered.data.data.hosts.length === 0 ? <p>No registered hosts are visible to your account.</p> : <ul className="space-y-2" aria-label="Registered host list">{registered.data.data.hosts.map(item => <li key={item.hostId} className="flex flex-wrap items-center justify-between gap-2 rounded-md border p-3"><div><p>{item.hostId}</p><p className="text-sm text-muted-foreground">Registered · Workload admission requires current checks</p></div><Button variant="outline" onClick={() => { setHostId(item.hostId); if (hostId === item.hostId) host.refetch(); }}>Inspect {item.hostId}</Button></li>)}</ul>}
        <Button variant="outline" onClick={() => registered.refetch()} disabled={registered.isFetching}>Refresh registered hosts</Button>
      </div>}
      <details><summary className="cursor-pointer text-sm font-medium">Inspect a host by ID</summary><form onSubmit={e => { const d = form(e); setHostId(text(d, "hostId")); }} className="flex flex-wrap items-end gap-2"><Field name="hostId" label="Registered machine name" value={hostId ?? ""} /><Button type="submit">Inspect registered host</Button></form></details>
      {host.data ? <div role="status"><p>Selected machine: {host.data.data.hostId}</p><p>Registration is recorded. Check security and role readiness below before running applications.</p><details><summary className="cursor-pointer text-sm">Registration technical details</summary><p>Status: {host.data.data.status}</p><p>Connection record: {host.data.data.targetId}; configuration profile: {host.data.data.profileId}</p></details></div> : null}
    </CardContent></Card>
    {error ? <ReadViewState kind={classifyReadFailure(error)} title="Host operation could not complete" description="No automatic retry was made. Review current state before submitting again; unsaved input remains available for temporary failures." /> : null}
    <details className="rounded-lg border border-border p-4"><summary className="cursor-pointer font-medium">Add or prepare a node</summary><p className="my-3 text-sm text-muted-foreground">Administrator steps: 1. Save connection details and approve their plan. 2. Connect to read machine details. 3. Verify its identity and prepare registration. Each change needs its own review and approval; nothing is installed by completing these forms.</p><div className="space-y-4">
    <Card><CardHeader><CardTitle>1. Save connection details</CardTitle><CardDescription>Have the machine’s address, SSH account, verified public host key and approved credential reference ready. Use the i buttons for each field. Saving a draft does not connect to the machine.</CardDescription></CardHeader><CardContent>
      <form className="grid gap-3 sm:grid-cols-2" onSubmit={async e => {
        const d = form(e);
        try { const result = await target.mutateAsync({ schema: "vegastack-labs.dev/host-discovery-target-draft-request", schemaVersion: "1.0.0", action: "activate", expectedTargetRevision: 0, expectedStateRevision: number(d,"revision"), idempotencyKey: key("target"), target: {
          schema: "vegastack-labs.dev/host-discovery-target", schemaVersion: "1.0.0", targetId: text(d,"targetId"), revision: 1, address: text(d,"address"), port: number(d,"port"), user: text(d,"user"), hostKey: text(d,"hostKey"), profileId: text(d,"profileId"), credentialReferenceId: text(d,"credentialReferenceId"), materialVersion: text(d,"materialVersion"), expectedOs: "debian", expectedVersion: text(d,"osVersion"), expectedArchitecture: text(d,"architecture"), inventoryDraftId: null, inventoryDraftRevision: 0, assetId: null, recoveryEpoch: number(d,"epoch"),
          ...(credentialMode === "preloaded-discovery" ? {credentialMode:"preloaded-discovery",credentialPublicKeyDigest:text(d,"credentialPublicKeyDigest")} : {}),
        }, ...(credentialMode === "preloaded-discovery" ? {consoleConfirmation:{schema:"vegastack-labs.dev/host-discovery-console-confirmation",schemaVersion:"1.0.0",method:"administrator-verified-console",targetDigest:text(d,"consoleTargetDigest")}} : {}) }); saveDraft(result.data,"host-target"); } catch { /* mutation state carries the error */ }
      }}>
        <FieldHelp label="Discovery login method">Choose a saved credential unless your administrator has already installed a discovery-only key and supplied the verified fingerprints. Neither option accepts a private key in this form.</FieldHelp><label className="grid gap-1 text-sm">Discovery login method<select aria-label="Discovery login method" value={credentialMode} onChange={e=>setCredentialMode(e.target.value === "preloaded-discovery" ? "preloaded-discovery" : "qualified-reference")} className="rounded-md border p-2"><option value="qualified-reference">Use an approved saved credential</option><option value="preloaded-discovery">Use a discovery key already installed by an administrator</option></select></label>
        {credentialMode === "preloaded-discovery" ? <><Field name="credentialPublicKeyDigest" label="Installed discovery key fingerprint" /><Field name="consoleTargetDigest" label="Console-verified connection fingerprint" /><p className="text-sm sm:col-span-2">Enter the digest of the complete target independently verified at its console, including this discovery-only key. This record grants no action privilege or workload admission.</p></> : null}
        <Field name="targetId" label="Connection record name" /><Field name="address" label="Machine address" /><Field name="port" label="SSH port" number value="22" /><Field name="user" label="SSH account name" /><Field name="hostKey" label="Verified public SSH host key" /><Field name="profileId" label="Approved configuration profile" /><Field name="credentialReferenceId" label="Saved credential reference" /><Field name="materialVersion" label="Saved credential version" /><Field name="osVersion" label="Installed Debian version" /><Field name="architecture" label="Machine architecture" /><RevisionFields /><Button type="submit" disabled={busy}>Prepare target draft</Button>
      </form>
    </CardContent></Card>
    <Card><CardHeader><CardTitle>2. Read machine details</CardTitle><CardDescription>After the connection-details plan has been approved and applied, enter that record’s name and revision to read the machine’s details over SSH. You can also open a saved report without connecting again.</CardDescription></CardHeader><CardContent className="space-y-4">
      <form className="grid gap-3 sm:grid-cols-2" onSubmit={async e => { const d=form(e); try { const r=await discovery.mutateAsync({schema:"vegastack-labs.dev/host-discovery-request",schemaVersion:"1.0.0",targetId:text(d,"targetId"),targetRevision:number(d,"targetRevision"),expectedStateRevision:number(d,"revision"),recoveryEpoch:number(d,"epoch"),idempotencyKey:key("discover")});setObservationId(r.data.observation.observationId); } catch {} }}>
        <Field name="targetId" label="Activated connection record name" /><Field name="targetRevision" label="Activated connection record revision" number /><RevisionFields /><Button type="submit" disabled={busy}>Connect and discover target</Button>
      </form>
      <form onSubmit={e=>{const d=form(e);setObservationId(text(d,"observationId"));}} className="flex flex-wrap items-end gap-2"><Field name="observationId" label="Saved observation ID" /><Button type="submit">Inspect observation</Button></form>
      {observation.data ? <div role="status"><p>Saved machine report loaded. Review its details before preparing registration.</p><p>Report expires {formatConsoleTime(observation.data.data.expiresAt)}</p><p>{observation.data.data.blockers.length ? "The report lists checks that need attention. Review them with your administrator." : "No blockers reported. Security and role readiness checks are still required."}</p><details><summary className="cursor-pointer text-sm">Machine report technical details</summary><p>Observation {observation.data.data.observationId}: {observation.data.data.status}</p><p>Connection record: {observation.data.data.targetId}</p><p>Blockers: {observation.data.data.blockers.join(", ") || "None reported"}</p></details></div> : null}
    </CardContent></Card>
    <Card><CardHeader><CardTitle>3. Register the verified machine</CardTitle><CardDescription>First load the saved machine report above. Confirm the physical serial number or approved VM identity independently, then supply its verified fingerprint. Registration still requires review, approval and application of its plan.</CardDescription></CardHeader><CardContent>
      <form className="grid gap-3 sm:grid-cols-2" onSubmit={async e=>{const d=form(e); const o=observation.data?.data;if(!o)return;try{const r=await adoption.mutateAsync({schema:"vegastack-labs.dev/host-adoption-request",schemaVersion:"1.0.0",hostId:text(d,"hostId"),observationId:o.observationId,observationDigest:o.contentDigest,idempotencyKey:key("adopt"),expectedStateRevision:number(d,"revision"),recoveryEpoch:o.recoveryEpoch,confirmation:{schema:"vegastack-labs.dev/host-identity-confirmation",schemaVersion:"1.0.0",targetDigest:o.targetDigest,targetRevision:o.targetRevision,identityDigest:text(d,"identityDigest"),identityClass:text(d,"identityClass") as "physical" | "qualified-virtual",identityKind:text(d,"identityKind") as "product-serial" | "product-uuid",confirmedAt:new Date().toISOString().replace(/\.\d{3}Z$/, "Z")}});saveDraft(r.data,"host-adoption");}catch{}}}>
        <Field name="hostId" label="New machine name" /><Field name="identityDigest" label="Verified machine identity fingerprint" /><FieldHelp label="Machine identity">Use Physical machine for a real computer and Qualified virtual machine only with its approved VM record. Confirm its serial number or UUID independently before using the matching fingerprint.</FieldHelp><label className="grid gap-1 text-sm">Identity class<select aria-label="Identity class" name="identityClass" defaultValue="physical" className="rounded-md border p-2"><option value="physical">Physical machine</option><option value="qualified-virtual">Qualified virtual machine</option></select></label><label className="grid gap-1 text-sm">Identity kind<select aria-label="Identity kind" name="identityKind" defaultValue="product-serial" className="rounded-md border p-2"><option value="product-serial">Product serial</option><option value="product-uuid">Product UUID</option></select></label><Field name="revision" label="Current server state revision" number /><Button type="submit" disabled={busy || !observation.data}>Prepare registration</Button>
      </form>
    </CardContent></Card>
    </div></details>
    {host.data ? <HostAdmission key={host.data.data.hostId} hostId={host.data.data.hostId} revision={host.data.data.stateRevision} epoch={host.data.data.recoveryEpoch} /> : null}
    <details className="rounded-lg border border-border p-4"><summary className="cursor-pointer font-medium">Repair or configure a node (administrator)</summary><p className="my-3 text-sm text-muted-foreground">First inspect the machine and its readiness checks above. Choose security settings to repair its configuration, or replacement only when moving its responsibilities to another machine. These advanced steps require an administrator-prepared file; they do not run automatically.</p><div className="space-y-4">
    <HostPolicyForm onPrepared={saveDraft} />
    <InitialControlGuidance />
    <HostReplacement onPrepared={saveDraft} />
    </div></details>
    {draft ? <Card><CardHeader><CardTitle>Draft prepared</CardTitle><CardDescription>No host action has been applied.</CardDescription></CardHeader><CardContent className="space-y-3"><p>Your draft is saved. Create a plan to review its exact changes before requesting approval.</p><details><summary className="cursor-pointer text-sm">Draft technical details</summary><p>Declaration: {draft.declarationId}</p><p className="break-all">Digest: {draft.digest}</p></details><Button disabled={busy} onClick={async()=>{try{const selected = draft; const p=await planning.mutateAsync(selected.declarationId); if (selectedDraft.current === selected) setPlannedDraft({ declarationId: selected.declarationId, digest: selected.digest, planId: p.planId });}catch{}}}>Create exact plan</Button><ExactPlanLauncher key={planId ?? draft.declarationId} kind={draft.kind} planId={planId} destructive /></CardContent></Card> : null}
  </section>;
}
