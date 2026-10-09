"use client";

import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { useHostAccessDraft, useHostActionDraft } from "@/lib/host-lifecycle-queries";
import { hostPolicySummary, readHostPolicy, type LoadedHostPolicy } from "@/lib/host-policy-input";
import type { ExactPlanKind } from "@/components/exact-plan-launcher";

export function HostPolicyForm({ onPrepared }: { onPrepared: (draft: { declarationId: string; contentDigest: string }, kind: ExactPlanKind) => void }) {
  const [kind, setKind] = useState<"access" | "baseline">("baseline");
  const [policy, setPolicy] = useState<LoadedHostPolicy | null>(null);
  const [fileError, setFileError] = useState(false);
  const action = useHostActionDraft(); const access = useHostAccessDraft();
  const summary = policy ? hostPolicySummary(policy) : null;
  return <Card><CardHeader><CardTitle>Hardening and recheck</CardTitle><CardDescription>Load a prepared Debian policy file with exact package/profile pins and credential references. Review its target before preparing an inert draft. The server validates and renders it; loading does not contact a host.</CardDescription></CardHeader><CardContent className="space-y-3">
    <div className="flex gap-2"><Button variant={kind === "baseline" ? "solid" : "outline"} onClick={()=>{setKind("baseline");setPolicy(null);setFileError(false);}}>Baseline or recheck</Button><Button variant={kind === "access" ? "solid" : "outline"} onClick={()=>{setKind("access");setPolicy(null);setFileError(false);}}>Access and firewall</Button></div>
    <label className="grid gap-1 text-sm">Prepared {kind} policy file<input key={kind} type="file" accept="application/json,.json" onChange={async e=>{const file=e.target.files?.[0];setPolicy(null);setFileError(false);if(!file)return;try{if(file.size>(kind==="access"?1048576:131072))throw new Error();setPolicy(readHostPolicy(kind,await file.text()));}catch{setFileError(true);}}} /></label>
    {fileError ? <p role="alert">The file is not a supported bounded Debian policy. No request was sent. Use reference IDs, never secret material.</p> : null}
    {summary ? <div className="space-y-1 text-sm"><p>Action: {summary.action}</p><p>Host: {summary.hostId}; target revision {summary.targetRevision}</p><p className="break-all">Pinned target: {summary.targetDigest}</p><p>Profile: {summary.profileId}</p><p className="break-all">Profile lock: {summary.profileLockDigest}</p><p>State revision {summary.stateRevision}; recovery epoch {summary.recoveryEpoch}</p><p>Other exact targets: {summary.auxiliaryHosts.join(", ") || "None in this access sequence"}</p><p>Administrator console confirmation in the policy is checked by the server. It does not replace automated qualification.</p></div> : null}
    {action.error || access.error ? <p role="alert">Draft preparation failed. No automatic retry was made. Inspect current state before retrying.</p> : null}
    <Button disabled={!policy || action.isPending || access.isPending} onClick={async()=>{if(!policy)return;try{if(policy.kind==="access"){const r=await access.mutateAsync(policy.request);onPrepared(r.data,"host-access");}else{const r=await action.mutateAsync(policy.request);onPrepared(r.data,"host-action");}}catch{}}}>Prepare hardening draft</Button>
  </CardContent></Card>;
}
