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
import { useServices, useService, useServiceObservation } from "@/lib/service-queries";

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
  const record = detail.state === "current" || detail.state === "stale" ? detail.data?.data : undefined;
  const observed = observation.state === "current" || observation.state === "stale" ? observation.data?.data : undefined;
  return <section aria-label="Service detail" className="space-y-4">
    <Card><CardHeader><CardTitle>Registration details</CardTitle><Button variant="outline" loading={detail.isFetching} onClick={detail.refresh}>Refresh registration</Button></CardHeader><CardContent className="space-y-2 break-all">
      {detail.state !== "current" ? <ServiceState state={detail.state} /> : null}
      {record ? <><p>Service: {record.definition.serviceId}</p><p>Environment: {record.definition.environmentId}</p><p>Owner: {record.definition.ownerId}</p><p>Host: {record.definition.hostId}</p><p>Binding: {record.definition.bindingId}</p><p>Registration: {record.registrationStatus}; revision {record.revision}</p><p>Registered: {formatConsoleTime(record.registeredAt)}</p><p>Host admission: {record.hostAdmission}</p></> : null}
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
