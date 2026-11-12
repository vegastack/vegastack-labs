"use client";

import { formatConsoleTime } from "@/components/source-status";

import type { ApprovalStatus as ApprovalStatusData } from "@/generated/read-api";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { PropertyList, PropertyLabel, PropertyRow, PropertyValue } from "@/components/ui/property-list";

const labels = { pending: "Pending", approved: "Approved", rejected: "Rejected", expired: "Expired" } as const;
const intents = { pending: "warning", approved: "success", rejected: "destructive", expired: "destructive" } as const;

export function ApprovalStatus({ approval }: { approval: ApprovalStatusData }) {
  return <Card data-approval-status={approval.status}>
    <CardHeader><CardTitle>Slack approval status</CardTitle></CardHeader>
    <CardContent className="space-y-4">
      <div aria-live="polite" role="status" className="flex flex-wrap items-center gap-3"><Badge bordered dot intent={intents[approval.status]}>{labels[approval.status]}</Badge><span className="text-sm">{approval.authorizationCurrent ? "Approval is still valid" : "Approval needs to be checked again"}</span></div>
      <PropertyList>
        <PropertyRow><PropertyLabel>Who approves</PropertyLabel><PropertyValue>Assigned maintainer</PropertyValue></PropertyRow>
        <PropertyRow><PropertyLabel>Channel</PropertyLabel><PropertyValue>Slack</PropertyValue></PropertyRow>
        <PropertyRow><PropertyLabel>Expires</PropertyLabel><PropertyValue className="break-all">{formatConsoleTime(approval.expiresAt)}</PropertyValue></PropertyRow>
        <PropertyRow><PropertyLabel>Last checked</PropertyLabel><PropertyValue className="break-all">{formatConsoleTime(approval.observedAt)}</PropertyValue></PropertyRow>
      </PropertyList>
      <p className="text-sm text-muted-foreground">Approve the request in Slack. This page updates from the Labs server; it cannot approve a change for you.</p>
    </CardContent>
  </Card>;
}
