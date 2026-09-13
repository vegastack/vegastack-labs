"use client";

import type { ApprovalStatus as ApprovalStatusData } from "@/generated/read-api";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

const labels = { pending: "Pending", approved: "Approved", rejected: "Rejected", expired: "Expired" } as const;
const intents = { pending: "warning", approved: "success", rejected: "destructive", expired: "destructive" } as const;

export function ApprovalStatus({ approval }: { approval: ApprovalStatusData }) {
  return <Card data-approval-status={approval.status}>
    <CardHeader><CardTitle>Slack approval status</CardTitle></CardHeader>
    <CardContent className="space-y-4">
      <div aria-live="polite" role="status" className="flex flex-wrap items-center gap-3"><Badge bordered dot intent={intents[approval.status]}>{labels[approval.status]}</Badge><span className="text-sm">{approval.authorizationCurrent ? "Authorization is current" : "Authorization is not current"}</span></div>
      <dl className="grid gap-3 text-sm sm:grid-cols-2">
        <div><dt className="text-muted-foreground">Approval owner</dt><dd className="font-medium">Assigned maintainer</dd></div>
        <div><dt className="text-muted-foreground">Channel</dt><dd className="font-medium">Slack</dd></div>
        <div><dt className="text-muted-foreground">Expires</dt><dd className="break-all font-medium">{approval.expiresAt}</dd></div>
        <div><dt className="text-muted-foreground">Observed</dt><dd className="break-all font-medium">{approval.observedAt}</dd></div>
      </dl>
      <p className="text-sm text-muted-foreground">This page only observes the server result. Approval happens outside the browser.</p>
    </CardContent>
  </Card>;
}
