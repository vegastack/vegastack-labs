"use client";

import { useState, type FormEvent } from "react";
import { HostAdmission, InitialControlGuidance } from "@/components/host-admission";
import { HostPolicyForm } from "@/components/host-policy-form";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { ExactPlanLauncher, type ExactPlanKind } from "@/components/exact-plan-launcher";
import { ReadViewState } from "@/components/read-view-state";
import { useReadFailure } from "@/components/query-provider";
import { classifyReadFailure } from "@/lib/read-queries";
import { useHostAdoption, useHostDiscovery, useHostObservation, useHostPlan, useHostTargetDraft, useManagedHost } from "@/lib/host-lifecycle-queries";

function Field({ name, label, value, number = false }: { name: string; label: string; value?: string; number?: boolean }) {
  return <label className="grid gap-1 text-sm">{label}<Input name={name} required defaultValue={value} type={number ? "number" : "text"} min={number ? 0 : undefined} autoComplete="off" /></label>;
}
function form(event: FormEvent<HTMLFormElement>) { event.preventDefault(); return new FormData(event.currentTarget); }
function text(data: FormData, name: string) { return String(data.get(name) ?? "").trim(); }
function number(data: FormData, name: string) { return Number(text(data, name)); }
function key(action: string) { return `console-host-${action}-${crypto.randomUUID()}`; }
function RevisionFields() { return <><Field name="revision" label="Current state revision" number /><Field name="epoch" label="Recovery epoch" number /></>; }

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
  const [planId, setPlanId] = useState<string | null>(null);
  const host = useManagedHost(hostId);
  const observation = useHostObservation(observationId);
  const target = useHostTargetDraft(); const discovery = useHostDiscovery(); const adoption = useHostAdoption(); const planning = useHostPlan();
  const error = target.error ?? discovery.error ?? adoption.error ?? planning.error ?? host.error ?? observation.error;
  const busy = target.isPending || discovery.isPending || adoption.isPending || planning.isPending;
  function saveDraft(data: { declarationId: string; contentDigest: string }, kind: ExactPlanKind) { setDraft({ declarationId: data.declarationId, digest: data.contentDigest, kind }); setPlanId(null); }
  return <section aria-label="Host lifecycle" className="space-y-4">
    <Card><CardHeader><CardTitle>Registered hosts</CardTitle><CardDescription>Inventory drafts, discovery and registration are separate. Registration does not admit workloads.</CardDescription></CardHeader><CardContent className="space-y-4">
      <form onSubmit={e => { const d = form(e); setHostId(text(d, "hostId")); }} className="flex items-end gap-2"><Field name="hostId" label="Managed host ID" value={hostId ?? ""} /><Button type="submit">Inspect registered host</Button></form>
      {host.data ? <div role="status"><p>Host {host.data.data.hostId}: {host.data.data.status}</p><p>Target {host.data.data.targetId}; profile {host.data.data.profileId}</p><p>Registration is recorded. Admission requires current baseline and role checks.</p></div> : null}
    </CardContent></Card>
    {error ? <ReadViewState kind={classifyReadFailure(error)} title="Host operation could not complete" description="No automatic retry was made. Review current state before submitting again; unsaved input remains available for temporary failures." /> : null}
    <Card><CardHeader><CardTitle>Prepare discovery target</CardTitle><CardDescription>Save an inert target draft using an existing credential reference and an independently verified public SSH host key. This does not connect to the machine.</CardDescription></CardHeader><CardContent>
      <form className="grid gap-3 sm:grid-cols-2" onSubmit={async e => {
        const d = form(e);
        try { const result = await target.mutateAsync({ schema: "vegastack-labs.dev/host-discovery-target-draft-request", schemaVersion: "1.0.0", action: "activate", expectedTargetRevision: 0, expectedStateRevision: number(d,"revision"), idempotencyKey: key("target"), target: {
          schema: "vegastack-labs.dev/host-discovery-target", schemaVersion: "1.0.0", targetId: text(d,"targetId"), revision: 1, address: text(d,"address"), port: number(d,"port"), user: text(d,"user"), hostKey: text(d,"hostKey"), profileId: text(d,"profileId"), credentialReferenceId: text(d,"credentialReferenceId"), materialVersion: text(d,"materialVersion"), expectedOs: "debian", expectedVersion: text(d,"osVersion"), expectedArchitecture: text(d,"architecture"), inventoryDraftId: null, inventoryDraftRevision: 0, assetId: null, recoveryEpoch: number(d,"epoch"),
          ...(credentialMode === "preloaded-discovery" ? {credentialMode:"preloaded-discovery",credentialPublicKeyDigest:text(d,"credentialPublicKeyDigest")} : {}),
        }, ...(credentialMode === "preloaded-discovery" ? {consoleConfirmation:{schema:"vegastack-labs.dev/host-discovery-console-confirmation",schemaVersion:"1.0.0",method:"administrator-verified-console",targetDigest:text(d,"consoleTargetDigest")}} : {}) }); saveDraft(result.data,"host-target"); } catch { /* mutation state carries the error */ }
      }}>
        <label className="grid gap-1 text-sm">Discovery credential mode<select aria-label="Discovery credential mode" value={credentialMode} onChange={e=>setCredentialMode(e.target.value === "preloaded-discovery" ? "preloaded-discovery" : "qualified-reference")} className="rounded-md border p-2"><option value="qualified-reference">Qualified credential reference</option><option value="preloaded-discovery">Administrator-preloaded discovery key</option></select></label>
        {credentialMode === "preloaded-discovery" ? <><Field name="credentialPublicKeyDigest" label="Preloaded public key digest" /><Field name="consoleTargetDigest" label="Administrator-confirmed exact target digest" /><p className="text-sm sm:col-span-2">Enter the digest of the complete target independently verified at its console, including this discovery-only key. This record grants no action privilege or workload admission.</p></> : null}
        <Field name="targetId" label="Target ID" /><Field name="address" label="Exact target address" /><Field name="port" label="SSH port" number value="22" /><Field name="user" label="Existing nonroot account" /><Field name="hostKey" label="Verified public SSH host key" /><Field name="profileId" label="Profile ID" /><Field name="credentialReferenceId" label="Credential reference ID" /><Field name="materialVersion" label="Credential material version" /><Field name="osVersion" label="Expected Debian version" /><Field name="architecture" label="Expected architecture" /><RevisionFields /><Button type="submit" disabled={busy}>Prepare target draft</Button>
      </form>
    </CardContent></Card>
    <Card><CardHeader><CardTitle>Discovery observation</CardTitle><CardDescription>Discovery makes a read-only connection to one already activated target. Inspecting a saved observation makes no host connection.</CardDescription></CardHeader><CardContent className="space-y-4">
      <form className="grid gap-3 sm:grid-cols-2" onSubmit={async e => { const d=form(e); try { const r=await discovery.mutateAsync({schema:"vegastack-labs.dev/host-discovery-request",schemaVersion:"1.0.0",targetId:text(d,"targetId"),targetRevision:number(d,"targetRevision"),expectedStateRevision:number(d,"revision"),recoveryEpoch:number(d,"epoch"),idempotencyKey:key("discover")});setObservationId(r.data.observation.observationId); } catch {} }}>
        <Field name="targetId" label="Activated target ID" /><Field name="targetRevision" label="Activated target revision" number /><RevisionFields /><Button type="submit" disabled={busy}>Connect and discover target</Button>
      </form>
      <form onSubmit={e=>{const d=form(e);setObservationId(text(d,"observationId"));}} className="flex items-end gap-2"><Field name="observationId" label="Saved observation ID" /><Button type="submit">Inspect observation</Button></form>
      {observation.data ? <div role="status"><p>Observation {observation.data.data.observationId}: {observation.data.data.status}</p><p>Target: {observation.data.data.targetId}; expires {observation.data.data.expiresAt}</p><p>Blockers: {observation.data.data.blockers.join(", ") || "None reported; qualification remains separate."}</p></div> : null}
    </CardContent></Card>
    <Card><CardHeader><CardTitle>Prepare registration</CardTitle><CardDescription>An administrator verifies the exact identity against the saved observation. The resulting registration draft still needs plan approval and apply.</CardDescription></CardHeader><CardContent>
      <form className="grid gap-3 sm:grid-cols-2" onSubmit={async e=>{const d=form(e); const o=observation.data?.data;if(!o)return;try{const r=await adoption.mutateAsync({schema:"vegastack-labs.dev/host-adoption-request",schemaVersion:"1.0.0",hostId:text(d,"hostId"),observationId:o.observationId,observationDigest:o.contentDigest,idempotencyKey:key("adopt"),expectedStateRevision:number(d,"revision"),recoveryEpoch:o.recoveryEpoch,confirmation:{schema:"vegastack-labs.dev/host-identity-confirmation",schemaVersion:"1.0.0",targetDigest:o.targetDigest,targetRevision:o.targetRevision,identityDigest:text(d,"identityDigest"),identityClass:text(d,"identityClass") as "physical" | "qualified-virtual",identityKind:text(d,"identityKind") as "product-serial" | "product-uuid",confirmedAt:new Date().toISOString().replace(/\.\d{3}Z$/, "Z")}});saveDraft(r.data,"host-adoption");}catch{}}}>
        <Field name="hostId" label="New managed host ID" /><Field name="identityDigest" label="Independently verified identity digest" /><label className="grid gap-1 text-sm">Identity class<select aria-label="Identity class" name="identityClass" defaultValue="physical" className="rounded-md border p-2"><option value="physical">Physical machine</option><option value="qualified-virtual">Qualified virtual machine</option></select></label><label className="grid gap-1 text-sm">Identity kind<select aria-label="Identity kind" name="identityKind" defaultValue="product-serial" className="rounded-md border p-2"><option value="product-serial">Product serial</option><option value="product-uuid">Product UUID</option></select></label><Field name="revision" label="Current state revision" number /><Button type="submit" disabled={busy || !observation.data}>Prepare registration</Button>
      </form>
    </CardContent></Card>
    {host.data ? <HostAdmission key={host.data.data.hostId} hostId={host.data.data.hostId} revision={host.data.data.stateRevision} epoch={host.data.data.recoveryEpoch} /> : null}
    <HostPolicyForm onPrepared={saveDraft} />
    <InitialControlGuidance />
    {draft ? <Card><CardHeader><CardTitle>Draft prepared</CardTitle><CardDescription>No host action has been applied.</CardDescription></CardHeader><CardContent className="space-y-3"><p>Declaration: {draft.declarationId}</p><p className="break-all">Digest: {draft.digest}</p><Button disabled={busy} onClick={async()=>{try{const p=await planning.mutateAsync(draft.declarationId);setPlanId(p.planId);}catch{}}}>Create exact plan</Button><ExactPlanLauncher key={planId ?? draft.declarationId} kind={draft.kind} planId={planId} destructive /></CardContent></Card> : null}
  </section>;
}
