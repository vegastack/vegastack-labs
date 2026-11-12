"use client";

import { FieldHelp } from "@/components/field-help";
import { useState } from "react";
import Link from "next/link";
import { PageHeader } from "@/components/ui/page-header";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { ReadViewState, type ReadStateKind } from "@/components/read-view-state";
import { formatConsoleTime } from "@/components/source-status";
import { ReadPagination } from "@/components/read-pagination";
import { useServices, useService, useServiceObservation, useServiceConfiguration, useServiceDeployment, useServiceRecovery } from "@/lib/service-queries";

function formatMemory(bytes: number): string {
  return `${(bytes / (1024 * 1024)).toLocaleString("en-IN", { maximumFractionDigits: 1 })} MiB`;
}

function ServiceState({ state }: { state: ReadStateKind }) {
  return <ReadViewState kind={state} title={state === "denied" ? "Services access denied" : state === "loading" ? "Loading services" : state === "stale" ? "Service records are stale" : "Services could not be read"} description={state === "denied" ? "Current authorization is required to view service records and observations." : state === "stale" ? "Showing retained data after a temporary failure. Provider availability and current state have not been confirmed. Refresh to check again." : "Refresh to request current authorized records."} />;
}

export function ServicesView() {
  const [pages, setPages] = useState([""]);
  const [selected, setSelected] = useState<string | null>(null);
  const view = useServices(pages[pages.length - 1] ?? "");
  const visible = view.state === "current" || view.state === "stale";
  const list = visible ? view.data?.data : undefined;
  return <>
    <PageHeader title="Services" description="Choose an application to see its saved settings, where it runs, and the last recorded deployment result." actions={<Button variant="outline" loading={view.isFetching} onClick={view.refresh}>Refresh Services</Button>} />
    <p className="text-sm text-muted-foreground">To add an existing application, prepare its import with the vsk-labs command line tool, then review the proposed change in <Link prefetch={false} href="/changes" className="underline">Changes</Link>. Saving an application record does not deploy it or confirm its machine is ready.</p>
    {view.state !== "current" ? <ServiceState state={view.state} /> : null}
    {list ? <>
      {!list.services.length ? <ReadViewState kind="empty" title="No services visible" description="No registered service environments are visible under your current permissions." /> : <ul aria-label="Registered services" className="grid gap-4">
        {list.services.map(service => <li key={service.definition.serviceId}><Card>
          <CardHeader><CardTitle className="break-all">{service.definition.serviceId}</CardTitle></CardHeader>
          <CardContent className="space-y-3 break-all">
            <Badge intent="info">{service.registrationStatus}</Badge>
            <p>Environment: {service.definition.environmentId}</p>
            <p>Owner: {service.definition.ownerId} · Host: {service.definition.hostId}</p>
            <p>Machine readiness: {service.hostAdmission} <FieldHelp label="Machine readiness">This records whether the selected machine has passed the required checks for hosting workloads. Adding a machine record does not pass those checks.</FieldHelp></p>
            <Button variant="outline" aria-expanded={selected === service.definition.serviceId} onClick={() => setSelected(selected === service.definition.serviceId ? null : service.definition.serviceId)}>View {service.definition.serviceId}</Button>
          </CardContent>
        </Card></li>)}
      </ul>}
      <ReadPagination label="Services" hasPrevious={pages.length > 1} hasNext={Boolean(list.nextAfter)} busy={view.isFetching} onPrevious={() => { setSelected(null); setPages(previous => previous.slice(0, -1)); }} onNext={() => { setSelected(null); setPages(previous => [...previous, list.nextAfter ?? ""]); }} />
    </> : null}
    {list && selected ? <ServiceDetail key={selected} serviceId={selected} /> : null}
  </>;
}

function ServiceDetail({ serviceId }: { serviceId: string }) {
  const detail = useService(serviceId);
  const observation = useServiceObservation(serviceId);
 const configuration = useServiceConfiguration(serviceId);
 const deployment = useServiceDeployment(serviceId);
 const recovery = useServiceRecovery(serviceId);
 const settings = configuration.state === "current" || configuration.state === "stale" ? configuration.data?.data : undefined;
 const deployed = deployment.state === "current" || deployment.state === "stale" ? deployment.data?.data : undefined;
 const recovered = recovery.state === "current" || recovery.state === "stale" ? recovery.data?.data : undefined;
  const record = detail.state === "current" || detail.state === "stale" ? detail.data?.data : undefined;
  const observed = observation.state === "current" || observation.state === "stale" ? observation.data?.data : undefined;
  return <section aria-label="Service detail" className="space-y-4">
    <Card><CardHeader><CardTitle>Recorded deployment result</CardTitle><Button variant="outline" loading={deployment.isFetching} onClick={deployment.refresh}>Refresh deployment result</Button></CardHeader><CardContent className="space-y-2 break-all">
      {deployment.state !== "current" ? <ServiceState state={deployment.state} /> : null}
      <p className="text-sm text-muted-foreground">This is the result at the recorded verification time, not continuous live monitoring.</p>
      {deployed ? <><p>Deployment: {deployed.status} · {deployed.request.action}</p><p>Running: {deployed.running ? "Yes" : "No"} · Healthy: {deployed.healthy ? "Yes" : "No"}</p><details><summary className="cursor-pointer font-medium">Technical details</summary><div className="mt-3 space-y-2"><p>Attempt running digest: {deployed.runningDigest}</p><p>Provider stage: {deployed.providerStage} · Receipt: {deployed.providerReceiptId || "none"}</p><p>Configuration in this attempt: {deployed.request.binding.configurationDigest}</p><p>Plan: {deployed.planId} · Run: {deployed.runId}</p></div></details><p>Completed: {formatConsoleTime(deployed.completedAt)}</p><p className="text-sm text-muted-foreground">Only a succeeded result verifies this attempt’s digest, settings and health at the recorded time. Partial effects require a new reviewed recovery or deployment plan.</p></> : null}
    </CardContent></Card>
    <details className="rounded-lg border border-border p-4"><summary className="cursor-pointer font-medium">Registration details</summary><div className="mt-3">
    <Card><CardHeader><CardTitle>Registration details</CardTitle><Button variant="outline" loading={detail.isFetching} onClick={detail.refresh}>Refresh registration</Button></CardHeader><CardContent className="space-y-2 break-all">
      {detail.state !== "current" ? <ServiceState state={detail.state} /> : null}
      {record ? <><p>Service: {record.definition.serviceId}</p><p>Environment: {record.definition.environmentId}</p><p>Owner: {record.definition.ownerId}</p><p>Host: {record.definition.hostId}</p><p>Binding: {record.definition.bindingId}</p><p>Registration: {record.registrationStatus}; revision {record.revision}</p><p>Registered: {formatConsoleTime(record.registeredAt)}</p><p>Machine readiness: {record.hostAdmission}</p></> : null}
    </CardContent></Card>
    </div></details>
    <details className="rounded-lg border border-border p-4"><summary className="cursor-pointer font-medium">Saved settings and machine choice</summary><div className="mt-3">
    <Card><CardHeader><CardTitle>Saved settings and machine choice</CardTitle><Button variant="outline" loading={configuration.isFetching} onClick={configuration.refresh}>Refresh settings</Button></CardHeader><CardContent className="space-y-2 break-all">
      {configuration.state !== "current" ? <ServiceState state={configuration.state} /> : null}
      {settings ? <><p>Can the selected machine run this application: {settings.placementState}</p><details><summary className="cursor-pointer">Technical details</summary>Placement reason: {settings.placementReason}</details><p>Checked: {formatConsoleTime(settings.observedAt)}</p>{settings.configuration ? <>
        <p>Environment class: {settings.configuration.environmentClass}</p><p>CPU limit: {settings.configuration.cpuQuotaPercent / 100} CPU · Memory: {formatMemory(settings.configuration.memoryBytes)}</p><p>Storage reservation: {formatMemory(settings.configuration.storageBytes)} · Port: {settings.configuration.port}</p><p>Network access: {settings.configuration.exposure}</p><p>Health: {settings.configuration.healthPath} · expected HTTP {settings.configuration.healthExpectedStatus}</p><p>Data: {settings.configuration.dataClass} · Backup policy: {settings.configuration.backupPolicyId || "none"}</p><p>Migration: {settings.configuration.migration} · Rollback: {settings.configuration.rollback}</p><p>Saved secret references: {settings.configuration.secretReferenceIds.length}</p><details><summary className="cursor-pointer">Technical details</summary><p>Configuration digest: {settings.configurationDigest}</p></details><p className="text-sm text-muted-foreground">Desired settings take effect only through an acknowledged deployment plan. Eligibility reflects current checks for this explicitly chosen host.</p>
      </> : <p>No service settings declared.</p>}</> : null}
    </CardContent></Card>
    </div></details>
    <details className="rounded-lg border border-border p-4"><summary className="cursor-pointer font-medium">Data recovery result</summary><div className="mt-3">
    <Card><CardHeader><CardTitle>Data recovery result</CardTitle><Button variant="outline" loading={recovery.isFetching} onClick={recovery.refresh}>Refresh recovery</Button></CardHeader><CardContent className="space-y-2 break-all">
      {recovery.state !== "current" ? <ServiceState state={recovery.state} /> : null}
      {recovered ? <><p>Recovery: {recovered.status} · {recovered.request.action}</p><p>Backup point: {recovered.backupPointId || "none"}</p><p>Consistent restore verified: {recovered.isolatedRestoreVerified ? "Yes" : "No"}</p><p>Source resumed: {recovered.sourceResumed ? "Yes" : "No"} · Target writers enabled: {recovered.targetWritersEnabled ? "Yes" : "No"}</p><p>Next action: {recovered.nextAction}</p><p>Plan: {recovered.planId} · Run: {recovered.runId}</p><p>Completed: {formatConsoleTime(recovered.completedAt)}</p></> : null}
    </CardContent></Card>
    </div></details>
    <details className="rounded-lg border border-border p-4"><summary className="cursor-pointer font-medium">Reports from connected services</summary><div className="mt-3">
    <Card><CardHeader><CardTitle>Reports from connected services</CardTitle><Button variant="outline" loading={observation.isFetching} onClick={observation.refresh}>Refresh observations</Button></CardHeader><CardContent className="space-y-3 break-all">
      {observation.state !== "current" ? <ServiceState state={observation.state} /> : null}
      {observed ? <>
        <p>Observed: {formatConsoleTime(observed.observedAt)}</p>
        <p>Hosting observation: {observed.hostingState}</p><details><summary className="cursor-pointer">Technical details</summary>Hosting reason: {observed.hostingReason}</details>
        <p>Coolify reported status: {observed.providerStatus || "unknown"}</p>
        <p>Configured image: {observed.configuredImage || "unknown"}</p>
        <p>Actual running digest: {observed.runningDigestState}</p>
        <p>Application health: {observed.healthState}</p>
        <p>Artifact observation: {observed.artifactState}</p><details><summary className="cursor-pointer">Technical details</summary>Artifact reason: {observed.artifactReason}</details>
        <p>Harbor artifact digest: {observed.artifactDigest || "unknown"}</p>
        <p>Artifact kind: {observed.artifactKind}</p>
        <p>Scan: {observed.scanState}</p>
        <p>Signature: {observed.signatureState}</p>
        <p>Build origin: {observed.provenanceState}</p>
        <p>Machine readiness: {observed.hostAdmission}</p>
        <p className="text-sm text-muted-foreground">A provider report or configured image does not verify the running image, application health, signature, provenance or host security.</p>
      </> : null}
    </CardContent></Card>
    </div></details>
  </section>;
}
