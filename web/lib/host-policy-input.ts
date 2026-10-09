import { decodePhase4Contract, type HostActionRequest, type HostAccessDraftRequest, type DebianBaselineInput, type LinuxRoleInput } from "../generated/read-api";

export const baselineActions = ["debian.baseline.apply", "debian.baseline.collect", "debian.aide.initialize", "debian.aide.refresh", "debian.volume.observe", "debian.volume-recovery.verify"] as const;
export const roleActions = ["debian.role.apply", "debian.role.collect", "debian.control.handoff", "debian.control.handoff.verify"] as const;
export type LoadedHostPolicy = { kind: "access"; request: HostAccessDraftRequest } | { kind: "baseline" | "role"; request: HostActionRequest };

// Import a prepared, typed policy file; this is not a shell or arbitrary action editor.
export function readHostPolicy(kind: "access" | "baseline" | "role", raw: string): LoadedHostPolicy {
  if (new TextEncoder().encode(raw).length > (kind === "access" ? 1048576 : 131072)) throw new Error("Policy file exceeds its bounded size.");
  const value: unknown = JSON.parse(raw);
  if (kind === "access") {
    const request = decodePhase4Contract("vegastack-labs.dev/host-access-draft-request", value) as unknown as HostAccessDraftRequest;
    decodePhase4Contract("vegastack-labs.dev/debian-access-input", request.input);
    if (request.subject.actionId !== "debian.access.apply" || request.subject.hostId !== request.input.hostId || request.subject.consoleConfirmation.hostIdentityDigest !== request.input.hostIdentityDigest || request.subject.callerUid !== request.input.automationUid) throw new Error("Access subject does not match the policy.");
    validateCompiledAccessInput(request.subject.actionInput);
    // Probe requests are parsed and fixed by the existing server access compiler.
    for (const step of request.probes) {
      if (step.kind === "collect") validateCompiledAccessInput(step.request.actionInput);
      else decodePhase4Contract("vegastack-labs.dev/access-probe-input", JSON.parse(step.request.actionInput));
    }
    return { kind, request };
  }
  const request = decodePhase4Contract("vegastack-labs.dev/host-action-request", value) as unknown as HostActionRequest;
  if (kind === "role") {
    if (!(roleActions as readonly string[]).includes(request.actionId)) throw new Error("Select a supported Linux role action.");
    const input = decodePhase4Contract("vegastack-labs.dev/linux-role-input", JSON.parse(request.actionInput)) as unknown as LinuxRoleInput;
    if (request.hostId !== input.hostId || request.callerUid !== input.automationUid || request.consoleConfirmation.hostIdentityDigest !== input.hostIdentityDigest) throw new Error("Role subject does not match the prepared policy.");
    if ((request.actionId === "debian.control.handoff" || request.actionId === "debian.control.handoff.verify") !== Boolean(input.handoff)) throw new Error("The exact control handoff binding is required only for handoff operations.");
    return { kind, request };
  }
  if (!(baselineActions as readonly string[]).includes(request.actionId)) throw new Error("Select a supported Debian baseline action.");
  decodePhase4Contract(request.actionId === "debian.volume-recovery.verify" ? "vegastack-labs.dev/volume-recovery-input" : "vegastack-labs.dev/debian-baseline-input", JSON.parse(request.actionInput));
  return { kind, request };
}
export function hostPolicySummary(policy: LoadedHostPolicy) {
  const request = policy.kind === "access" ? policy.request.subject : policy.request;
  const input = policy.kind === "access" ? policy.request.input : JSON.parse(request.actionInput) as DebianBaselineInput;
  return { hostId: request.hostId, targetDigest: request.targetDigest, targetRevision: request.targetRevision, action: policy.kind === "access" ? "Apply access policy, probe, then confirm" : request.actionId, profileId: input.profileId, profileLockDigest: input.profileLockDigest, stateRevision: request.expectedStateRevision, recoveryEpoch: request.recoveryEpoch, auxiliaryHosts: policy.kind === "access" ? [...new Set(policy.request.probes.map(p => p.request.hostId))] : [] };
}

function validateCompiledAccessInput(raw: string) {
  const input: unknown = JSON.parse(raw);
  // The server compiler replaces this placeholder with the typed Input policy.
  if (input && typeof input === "object" && !Array.isArray(input) && Object.keys(input).length === 0) return;
  decodePhase4Contract("vegastack-labs.dev/debian-access-input", input);
}

export function hostRoleSummary(policy: LoadedHostPolicy) {
  if (policy.kind !== "role") return null;
  const input = JSON.parse(policy.request.actionInput) as LinuxRoleInput;
  return { role: input.roleId, accounts: input.accounts, directories: input.directories, resources: input.resources, networkRequired: input.networkingRequired, handoff: input.handoff };
}
