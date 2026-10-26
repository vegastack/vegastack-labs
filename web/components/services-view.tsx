"use client";

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
    <PageHeader title="Services" description="Registered service environments and read-only provider observations within your current access." actions={<Button variant="outline" loading={view.isFetching} onClick={view.refresh}>Refresh Services</Button>} />
    <p className="text-sm text-muted-foreground">Prepare an import with the CLI, then review its exact plan in <Link href="/changes" className="underline">Changes</Link>. Registration does not verify deployment or host admission.</p>
    {view.state !== "current" ? <ServiceState state={view.state} /> : null}
    {list ? <>
      {!list.services.length ? <ReadViewState kind="empty" title="No services visible" description="No registered service environments are visible under your current permissions." /> : <ul aria-label="Registered services" className="grid gap-4">
        {list.services.map(service => <li key={service.definition.serviceId}><Card>
          <CardHeader><CardTitle className="break-all">{service.definition.serviceId}</CardTitle></CardHeader>
          <CardContent className="space-y-3 break-all">
            <Badge intent="info">{service.registrationStatus}</Badge>
            <p>Environment: {service.definition.environmentId}</p>
            <p>Owner: {service.definition.ownerId} · Host: {service.definition.hostId}</p>
            <p>Host admission: {service.hostAdmission}</p>
            <Button variant="outline" aria-expanded={selected === service.definition.serviceId} onClick={() => setSelected(selected === service.definition.serviceId ? null : service.definition.serviceId)}>Inspect {service.definition.serviceId}</Button>
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
    <Card><CardHeader><CardTitle>Registration details</CardTitle><Button variant="outline" loading={detail.isFetching} onClick={detail.refresh}>Refresh registration</Button></CardHeader><CardContent className="space-y-2 break-all">
      {detail.state !== "current" ? <ServiceState state={detail.state} /> : null}
      {record ? <><p>Service: {record.definition.serviceId}</p><p>Environment: {record.definition.environmentId}</p><p>Owner: {record.definition.ownerId}</p><p>Host: {record.definition.hostId}</p><p>Binding: {record.definition.bindingId}</p><p>Registration: {record.registrationStatus}; revision {record.revision}</p><p>Registered: {formatConsoleTime(record.registeredAt)}</p><p>Host admission: {record.hostAdmission}</p></> : null}
    </CardContent></Card>
    <Card><CardHeader><CardTitle>Desired settings and placement</CardTitle><Button variant="outline" loading={configuration.isFetching} onClick={configuration.refresh}>Refresh settings</Button></CardHeader><CardContent className="space-y-2 break-all">
      {configuration.state !== "current" ? <ServiceState state={configuration.state} /> : null}
      {settings ? <><p>Explicit target eligibility: {settings.placementState} · {settings.placementReason}</p><p>Checked: {formatConsoleTime(settings.observedAt)}</p>{settings.configuration ? <>
        <p>Environment class: {settings.configuration.environmentClass}</p><p>CPU quota: {settings.configuration.cpuQuotaPercent}% · Memory: {settings.configuration.memoryBytes} bytes</p><p>Storage reservation: {settings.configuration.storageBytes} bytes · Port: {settings.configuration.port}</p><p>Exposure: {settings.configuration.exposure}</p><p>Health: {settings.configuration.healthPath} · expected HTTP {settings.configuration.healthExpectedStatus}</p><p>Data: {settings.configuration.dataClass} · Backup policy: {settings.configuration.backupPolicyId || "none"}</p><p>Migration: {settings.configuration.migration} · Rollback: {settings.configuration.rollback}</p><p>Workload secret references: {settings.configuration.secretReferenceIds.length}</p><p>Desired configuration: {settings.configurationDigest}</p><p className="text-sm text-muted-foreground">Desired settings take effect only through an acknowledged deployment plan. Eligibility reflects current checks for this explicitly chosen host.</p>
      </> : <p>No service settings declared.</p>}</> : null}
    </CardContent></Card>
    <Card><CardHeader><CardTitle>Verified deployment result</CardTitle><Button variant="outline" loading={deployment.isFetching} onClick={deployment.refresh}>Refresh runtime result</Button></CardHeader><CardContent className="space-y-2 break-all">
      {deployment.state !== "current" ? <ServiceState state={deployment.state} /> : null}
      {deployed ? <><p>Deployment: {deployed.status} · {deployed.request.action}</p><p>Attempt running digest: {deployed.runningDigest}</p><p>Running: {String(deployed.running)} · Healthy: {String(deployed.healthy)}</p><p>Provider stage: {deployed.providerStage} · Receipt: {deployed.providerReceiptId || "none"}</p><p>Configuration in this attempt: {deployed.request.binding.configurationDigest}</p><p>Plan: {deployed.planId} · Run: {deployed.runId}</p><p>Completed: {formatConsoleTime(deployed.completedAt)}</p><p className="text-sm text-muted-foreground">Only a succeeded result verifies this attempt’s digest, settings and health at the recorded time. Partial effects require a new reviewed recovery or deployment plan.</p></> : null}
    </CardContent></Card>
    <Card><CardHeader><CardTitle>Data recovery result</CardTitle><Button variant="outline" loading={recovery.isFetching} onClick={recovery.refresh}>Refresh recovery</Button></CardHeader><CardContent className="space-y-2 break-all">
      {recovery.state !== "current" ? <ServiceState state={recovery.state} /> : null}
      {recovered ? <><p>Recovery: {recovered.status} · {recovered.request.action}</p><p>Backup point: {recovered.backupPointId || "none"}</p><p>Consistent restore verified: {String(recovered.isolatedRestoreVerified)}</p><p>Source resumed: {String(recovered.sourceResumed)} · Target writers enabled: {String(recovered.targetWritersEnabled)}</p><p>Next action: {recovered.nextAction}</p><p>Plan: {recovered.planId} · Run: {recovered.runId}</p><p>Completed: {formatConsoleTime(recovered.completedAt)}</p></> : null}
    </CardContent></Card>
    <Card><CardHeader><CardTitle>Provider observations</CardTitle><Button variant="outline" loading={observation.isFetching} onClick={observation.refresh}>Refresh observations</Button></CardHeader><CardContent className="space-y-3 break-all">
      {observation.state !== "current" ? <ServiceState state={observation.state} /> : null}
      {observed ? <>
        <p>Observed: {formatConsoleTime(observed.observedAt)}</p>
        <p>Hosting observation: {observed.hostingState} · {observed.hostingReason}</p>
        <p>Coolify reported status: {observed.providerStatus || "unknown"}</p>
        <p>Configured image: {observed.configuredImage || "unknown"}</p>
        <p>Actual running digest: {observed.runningDigestState}</p>
        <p>Application health: {observed.healthState}</p>
        <p>Artifact observation: {observed.artifactState} · {observed.artifactReason}</p>
        <p>Harbor artifact digest: {observed.artifactDigest || "unknown"}</p>
        <p>Artifact kind: {observed.artifactKind}</p>
        <p>Scan: {observed.scanState}</p>
        <p>Signature: {observed.signatureState}</p>
        <p>Provenance: {observed.provenanceState}</p>
        <p>Host admission: {observed.hostAdmission}</p>
        <p className="text-sm text-muted-foreground">A provider report or configured image does not verify the running image, application health, signature, provenance or host security.</p>
      </> : null}
    </CardContent></Card>
  </section>;
}
