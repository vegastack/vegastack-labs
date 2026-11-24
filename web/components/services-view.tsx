"use client";

import { useState } from "react";
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
  return <ReadViewState kind={state} title={state === "denied" ? "Applications access denied" : state === "loading" ? "Loading applications" : state === "stale" ? "Saved information is out of date" : "Application information could not be loaded"} description={state === "denied" ? "Your account cannot view these application records. Ask an administrator for access." : state === "stale" ? "These records are from the last successful read. Refresh to check for newer information; the application’s current status has not been confirmed." : "Use Refresh to try loading the latest information."} />;
}

export function ServicesView() {
  const [pages, setPages] = useState([""]);
  const [selected, setSelected] = useState<string | null>(null);
  const view = useServices(pages[pages.length - 1] ?? "");
  const visible = view.state === "current" || view.state === "stale";
  const list = visible ? view.data?.data : undefined;
  return <>
    <PageHeader title="Applications" description="Choose an application to see its status and last deployment." actions={<Button variant="outline" loading={view.isFetching} onClick={view.refresh}>Refresh information</Button>} />
    {view.state !== "current" ? <ServiceState state={view.state} /> : null}
    {list ? <>
      {!list.services.length ? <ReadViewState kind="empty" title="No applications visible" description="No applications are visible to your account. Ask your administrator to add one or check your access." /> : <ul aria-label="Registered services" className="grid gap-4">
        {list.services.map(service => <li key={service.definition.serviceId} className="space-y-4"><Card>
          <CardHeader><CardTitle className="break-all">{service.definition.serviceId}</CardTitle></CardHeader>
          <CardContent className="space-y-3 break-all">
            <p>Machine: {service.definition.hostId}</p>
            <Button variant="outline" aria-expanded={selected === service.definition.serviceId} onClick={() => setSelected(selected === service.definition.serviceId ? null : service.definition.serviceId)}>View {service.definition.serviceId}</Button>
          </CardContent>
        </Card>{selected === service.definition.serviceId ? <ServiceDetail key={selected} serviceId={selected} /> : null}</li>)}
      </ul>}
      <ReadPagination label="Services" hasPrevious={pages.length > 1} hasNext={Boolean(list.nextAfter)} busy={view.isFetching} onPrevious={() => { setSelected(null); setPages(previous => previous.slice(0, -1)); }} onNext={() => { setSelected(null); setPages(previous => [...previous, list.nextAfter ?? ""]); }} />
    </> : null}
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
  const deploymentMessage = deployed?.status === "succeeded"
    ? "Last deployment completed successfully."
    : deployed?.status === "partial" ? "The last deployment did not finish completely."
    : deployed?.status === "failed" ? "The last deployment failed."
    : deployed ? "The last deployment needs attention." : null;
  return <section aria-label="Service detail" className="space-y-4">
    <Card>
      <CardContent>
        <section aria-label="Application summary" className="space-y-4">
          <div className="space-y-2">
            <Badge intent="warning">Current health: Not confirmed</Badge>
            {observation.state === "loading" ? <p role="status">Loading the latest available report…</p>
              : observation.state === "current" && observed?.hostingState === "unavailable"
                ? <p>Labs could not get a status report from the hosting service.</p>
                : observation.state === "current" && observed?.hostingState === "observed"
                  ? <p>A hosting report is available, but it does not confirm the running application’s health.</p>
                  : <p>A reliable current status is unavailable.</p>}
          </div>
          <div className="space-y-1">
            <p className="font-medium">Last deployment</p>
            {deployment.state === "loading" ? <p role="status">Loading the last result…</p>
              : deployment.state !== "current" ? <p>The last result could not be refreshed. Any saved result below may be out of date.</p>
                : deployment.data === null ? <p>No deployment result has been recorded.</p> : null}
            {deployed ? <>
              <p>{deploymentMessage}</p>
              <p>Recorded on {formatConsoleTime(deployed.completedAt)}</p>
              {deployed.status === "succeeded" ? <p>{deployed.running && deployed.healthy ? "The application was running and healthy at that time." : "Running health was not confirmed by that result."} Its status now is not confirmed.</p> : null}
            </> : null}
          </div>
          <p><span className="font-medium">Next step: </span>{deployed && deployed.status !== "succeeded"
            ? "Ask your administrator to investigate the incomplete deployment before trying again."
            : "Ask your administrator to check the application if you need its current running status."}</p>
        </section>
      </CardContent>
    </Card>
    <details className="rounded-lg border border-border p-4">
      <summary className="cursor-pointer font-medium">Administrator details</summary>
      <p className="my-3 text-sm text-muted-foreground">Exact records for troubleshooting. Adding or deploying an application currently requires administrator preparation through vsk-labs and the existing approval flow.</p>
      <div className="space-y-4 break-all">
    <Card><CardHeader><CardTitle>Recorded deployment result</CardTitle></CardHeader><CardContent className="space-y-2 break-all">
      {deployment.state !== "current" ? <ServiceState state={deployment.state} /> : null}
      {deployment.state === "current" && deployment.data === null ? <p>No deployment result has been recorded.</p> : null}

      {deployed ? <><p>Deployment: {deployed.status} · {deployed.request.action}</p><p>Running: {deployed.running ? "Yes" : "No"} · Healthy: {deployed.healthy ? "Yes" : "No"}</p><div><div className="mt-3 space-y-2"><p>Attempt running digest: {deployed.runningDigest}</p><p>Provider stage: {deployed.providerStage} · Receipt: {deployed.providerReceiptId || "none"}</p><p>Configuration in this attempt: {deployed.request.binding.configurationDigest}</p><p>Plan: {deployed.planId} · Run: {deployed.runId}</p></div></div><p>Completed: {formatConsoleTime(deployed.completedAt)}</p></> : null}
    </CardContent></Card>
    <section>
    <Card><CardHeader><CardTitle>Registration details</CardTitle></CardHeader><CardContent className="space-y-2 break-all">
      {detail.state !== "current" ? <ServiceState state={detail.state} /> : null}
      {record ? <><p>Service: {record.definition.serviceId}</p><p>Environment: {record.definition.environmentId}</p><p>Owner: {record.definition.ownerId}</p><p>Host: {record.definition.hostId}</p><p>Binding: {record.definition.bindingId}</p><p>Registration: {record.registrationStatus}; revision {record.revision}</p><p>Registered: {formatConsoleTime(record.registeredAt)}</p><p>Machine readiness: {record.hostAdmission}</p></> : null}
    </CardContent></Card>
    </section>
    <section>
    <Card><CardHeader><CardTitle>Saved settings and machine choice</CardTitle></CardHeader><CardContent className="space-y-2 break-all">
      {configuration.state !== "current" ? <ServiceState state={configuration.state} /> : null}
      {settings ? <><p>Can the selected machine run this application: {settings.placementState}</p><div>Placement reason: {settings.placementReason}</div><p>Checked: {formatConsoleTime(settings.observedAt)}</p>{settings.configuration ? <>
        <p>Environment class: {settings.configuration.environmentClass}</p><p>CPU limit: {settings.configuration.cpuQuotaPercent / 100} CPU · Memory: {formatMemory(settings.configuration.memoryBytes)}</p><p>Storage reservation: {formatMemory(settings.configuration.storageBytes)} · Port: {settings.configuration.port}</p><p>Network access: {settings.configuration.exposure}</p><p>Health: {settings.configuration.healthPath} · expected HTTP {settings.configuration.healthExpectedStatus}</p><p>Data: {settings.configuration.dataClass} · Backup policy: {settings.configuration.backupPolicyId || "none"}</p><p>Migration: {settings.configuration.migration} · Rollback: {settings.configuration.rollback}</p><p>Saved secret references: {settings.configuration.secretReferenceIds.length}</p><div><p>Configuration digest: {settings.configurationDigest}</p></div><p className="text-sm text-muted-foreground">Saved settings take effect only after an approved deployment runs. Machine readiness applies to the selected machine and its recorded checks.</p>
      </> : <p>No application settings have been saved. Ask an administrator to prepare them before deployment.</p>}</> : null}
    </CardContent></Card>
    </section>
    <section>
    <Card><CardHeader><CardTitle>Data recovery result</CardTitle></CardHeader><CardContent className="space-y-2 break-all">
      {recovery.state !== "current" ? <ServiceState state={recovery.state} /> : null}
      {recovery.state === "current" && recovery.data === null ? <p>No data recovery result has been recorded.</p> : null}
      {recovered ? <><p>Recovery: {recovered.status} · {recovered.request.action}</p><p>Backup point: {recovered.backupPointId || "none"}</p><p>Consistent restore verified: {recovered.isolatedRestoreVerified ? "Yes" : "No"}</p><p>Source resumed: {recovered.sourceResumed ? "Yes" : "No"} · Target writers enabled: {recovered.targetWritersEnabled ? "Yes" : "No"}</p><p>Next action: {recovered.nextAction}</p><p>Plan: {recovered.planId} · Run: {recovered.runId}</p><p>Completed: {formatConsoleTime(recovered.completedAt)}</p></> : null}
    </CardContent></Card>
    </section>
    <section>
    <Card><CardHeader><CardTitle>Reports from connected services</CardTitle></CardHeader><CardContent className="space-y-3 break-all">
      {observation.state !== "current" ? <ServiceState state={observation.state} /> : null}
      {observed ? <>
        <p>Report received: {formatConsoleTime(observed.observedAt)}</p>
        <p>Hosting observation: {observed.hostingState}</p><div>Hosting reason: {observed.hostingReason}</div>
        <p>Coolify reported status: {observed.providerStatus || "unknown"}</p>
        <p>Configured image: {observed.configuredImage || "unknown"}</p>
        <p>Actual running digest: {observed.runningDigestState}</p>
        <p>Application health: {observed.healthState}</p>
        <p>Artifact observation: {observed.artifactState}</p><div>Artifact reason: {observed.artifactReason}</div>
        <p>Harbor artifact digest: {observed.artifactDigest || "unknown"}</p>
        <p>Artifact kind: {observed.artifactKind}</p>
        <p>Scan: {observed.scanState}</p>
        <p>Signature: {observed.signatureState}</p>
        <p>Build origin: {observed.provenanceState}</p>
        <p>Machine readiness: {observed.hostAdmission}</p>
        <p className="text-sm text-muted-foreground">A provider report or configured image does not verify the running image, application health, signature, provenance or host security.</p>
      </> : null}
    </CardContent></Card>
    </section>
      </div>
    </details>
  </section>;
}
