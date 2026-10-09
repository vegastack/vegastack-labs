"use client";

import { useState } from "react";
import Link from "next/link";
import { RunProgress } from "@/components/run-progress";
import type { HostReplacementRequest } from "@/generated/read-api";
import { ExactPlanLauncher, type ExactPlanKind } from "@/components/exact-plan-launcher";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { readHostReplacement } from "@/lib/host-replacement-input";
import { useHostReplacement, useHostReplacementDraft } from "@/lib/host-replacement-queries";

export function HostReplacement({ onPrepared }: { onPrepared: (draft: { declarationId: string; contentDigest: string }, kind: ExactPlanKind) => void }) {
  const [request, setRequest] = useState<HostReplacementRequest | null>(null);
  const [invalid, setInvalid] = useState(false);
  const [confirmed, setConfirmed] = useState(false);
  const [id, setId] = useState<string | null>(null);
  const submission = useHostReplacementDraft();
  const state = useHostReplacement(id);
  const current = !state.error && !state.isFetching ? state.data?.data : undefined;
  return <Card><CardHeader><CardTitle>Host replacement and recovery</CardTitle><CardDescription>Freeze ownership, establish fences, restore when required, verify, qualify, then commit ownership with a fresh approved plan. Each stage remains server-owned.</CardDescription></CardHeader><CardContent className="space-y-4">
    <label className="grid gap-1 text-sm">Prepared replacement request file<input type="file" accept="application/json,.json" onChange={async e => {
      const file = e.target.files?.[0]; setRequest(null); setInvalid(false); setConfirmed(false);
      if (!file) return;
      try { if (file.size > 32768) throw new Error(); setRequest(readHostReplacement(await file.text())); } catch { setInvalid(true); }
    }} /></label>
    {invalid ? <p role="alert">Unsupported replacement request. Use the bounded freeze or commit contract with reference IDs, never secrets. No request was sent.</p> : null}
    {request ? <section aria-label="Replacement impact" className="space-y-2 text-sm break-all">
      <p>Replacement: {request.replacementId}; operation: {request.operation}</p>
      <p>Old host: {request.oldHostId}; identity: {request.oldIdentityDigest}</p><p>New host: {request.newHostId}; identity: {request.newIdentityDigest}</p>
      <p>Old target revision {request.oldTargetRevision}: {request.oldTargetDigest}; SSH key {request.oldSshHostKeyDigest}</p><p>New target revision {request.newTargetRevision}: {request.newTargetDigest}; SSH key {request.newSshHostKeyDigest}</p>
      <p>Profile: {request.profileId}; lock: {request.profileLockDigest}</p><p>Role declaration: {request.roleDeclarationId} revision {request.roleDeclarationRevision} → {request.proposedRoleDeclarationId} revision {request.proposedRoleDeclarationRevision}</p>
      <p>Aliases: {request.aliasBindings.map(a => `${a.aliasId} owned by ${a.ownerHostId}, revision ${a.ownerRevision}, generation ${a.ownershipGeneration}`).join("; ")}</p>
      <p>Restoration class: {request.restorationClass}</p>
      {request.source ? <><p>Recovery point: {request.source.pointId}; custody reference: {request.source.custodyReferenceId}</p><p>Source binding: {request.source.sourceBindingDigest}; manifest: {request.source.manifestDigest}</p></> : <p>No database restore is requested for this stateless role.</p>}
      <p>Preserved volumes: {request.volumeIds.join(", ") || "None declared"}; resources: {request.resourceIds.join(", ") || "None declared"}; payloads: {request.payloadIds.join(", ") || "None declared"}</p><p>Preserved preimage: {request.preservedPreimageDigest}</p>
      <p>Current state revision {request.expectedStateRevision}; recovery epoch {request.recoveryEpoch}; expected declaration revision {request.expectedDeclarationRevision}</p>
      <p>{request.operation === "freeze" ? "The approved freeze stops new work through these aliases. It does not transfer ownership or erase the old host." : "Commit transfers the exact frozen aliases only after current destination admission, fences and any required restore verification pass."}</p>
      <label className="flex gap-2"><input type="checkbox" checked={confirmed} onChange={e => setConfirmed(e.target.checked)} />I reviewed both hosts, the aliases and preserved data. This confirmation does not approve execution.</label>
    </section> : null}
    {submission.error ? <p role="alert">Replacement preparation failed. No automatic retry was made. Read current state and resolve its blockers before preparing another request.</p> : null}
    <Button disabled={!request || !confirmed || submission.isPending} onClick={async () => { if (!request || !confirmed) return; try { const result = await submission.mutateAsync(request); onPrepared(result.data, "host-replacement"); } catch {} }}>Prepare replacement draft</Button>
    <form className="flex items-end gap-2" onSubmit={e => { e.preventDefault(); const value = String(new FormData(e.currentTarget).get("replacementId") ?? "").trim(); if (value === id) void state.refetch(); else setId(value); }}>
      <label className="grid gap-1 text-sm">Replacement ID<Input name="replacementId" required autoComplete="off" /></label><Button type="submit" disabled={state.isFetching}>Inspect replacement</Button>
    </form>
    {state.error ? <p role="alert">Replacement state is unavailable. Completion and ownership are unknown.</p> : null}
    {current ? <section aria-label="Current replacement state" className="space-y-2 text-sm">
      <p>Replacement status: {current.status}</p><p>Old host: {current.oldHostId}; new host: {current.newHostId}</p><p>Ownership generation: {current.priorOwnershipGeneration} → {current.proposedOwnershipGeneration}</p>
      <p>Safe next action: {current.nextAction}</p><p>Blockers: {current.blockers.join(", ") || "None reported"}</p><p>Recorded state revision {current.stateRevision}; recorded recovery epoch {current.recoveryEpoch}; current server recovery epoch {state.data?.recoveryEpoch}</p>
      <p>Aliases: {current.aliasBindings.map(a => a.aliasId).join(", ")}</p>
      {current.status !== "committed" ? <p>Ownership transfer is incomplete. A restored or running service alone does not complete replacement.</p> : <p>The server records the ownership transfer as committed. Native acceptance and provider admission remain separate.</p>}
      {current.runId ? <RunProgress key={current.runId} runId={current.runId} /> : null}
      {current.restorePlanId ? <p>Restore plan: {current.restorePlanId}. Inspect its verification and safe next action in <Link href="/backups" className="underline">Backups and recovery</Link>.</p> : null}
      {current.planId && !current.runId ? <ExactPlanLauncher key={`${current.planId}:${current.recoveryEpoch}`} kind="host-replacement" planId={current.planId} destructive /> : null}
    </section> : null}
    <p className="text-sm">Use <Link href="/backups" className="underline">Backups and recovery</Link> for existing recovery-point selection and restore status. Recovery-required work follows the server’s safe next action; this page never restarts, retries a restore or reimages a machine automatically. Import a fresh commit request after the prerequisites are verified.</p>
  </CardContent></Card>;
}
