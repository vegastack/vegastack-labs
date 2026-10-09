import { decodePhase4Contract, type HostActionRequest, type HostAccessDraftRequest, type DebianBaselineInput } from "../generated/read-api";

export const baselineActions = ["debian.baseline.apply", "debian.baseline.collect", "debian.aide.initialize", "debian.aide.refresh", "debian.volume.observe", "debian.volume-recovery.verify"] as const;
export type LoadedHostPolicy = { kind: "access"; request: HostAccessDraftRequest } | { kind: "baseline"; request: HostActionRequest };

// Import a prepared, typed policy file; this is not a shell or arbitrary action editor.
export function readHostPolicy(kind: "access" | "baseline", raw: string): LoadedHostPolicy {
  if (new TextEncoder().encode(raw).length > (kind === "access" ? 1048576 : 131072)) throw new Error("Policy file exceeds its bounded size.");
  const value: unknown = JSON.parse(raw);
  if (kind === "access") {
    const request = decodePhase4Contract("vegastack-labs.dev/host-access-draft-request", value) as unknown as HostAccessDraftRequest;
    decodePhase4Contract("vegastack-labs.dev/debian-access-input", JSON.parse(request.subject.actionInput));
    // Probe requests are parsed and fixed by the existing server access compiler.
    for (const step of request.probes) {
      const schema = step.kind === "collect" ? "vegastack-labs.dev/debian-access-input" : "vegastack-labs.dev/access-probe-input";
      decodePhase4Contract(schema, JSON.parse(step.request.actionInput));
    }
    return { kind, request };
  }
  const request = decodePhase4Contract("vegastack-labs.dev/host-action-request", value) as unknown as HostActionRequest;
  if (!(baselineActions as readonly string[]).includes(request.actionId)) throw new Error("Select a supported Debian baseline action.");
  decodePhase4Contract(request.actionId === "debian.volume-recovery.verify" ? "vegastack-labs.dev/volume-recovery-input" : "vegastack-labs.dev/debian-baseline-input", JSON.parse(request.actionInput));
  return { kind, request };
}
export function hostPolicySummary(policy: LoadedHostPolicy) {
  const request = policy.kind === "access" ? policy.request.subject : policy.request;
  const input = policy.kind === "access" ? policy.request.input : JSON.parse(request.actionInput) as DebianBaselineInput;
  return { hostId: request.hostId, targetDigest: request.targetDigest, targetRevision: request.targetRevision, action: policy.kind === "access" ? "Apply access policy, probe, then confirm" : request.actionId, profileId: input.profileId, profileLockDigest: input.profileLockDigest, stateRevision: request.expectedStateRevision, recoveryEpoch: request.recoveryEpoch, auxiliaryHosts: policy.kind === "access" ? [...new Set(policy.request.probes.map(p => p.request.hostId))] : [] };
}
