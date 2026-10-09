import { decodePhase4Contract, type HostReplacementRequest } from "../generated/read-api";

// Structural preview only. The server resolves current identities, ownership,
// source custody, preserved preimages and admission independently.
export function readHostReplacement(raw: string): HostReplacementRequest {
  if (new TextEncoder().encode(raw).length > 32768) throw new Error("Replacement file exceeds its bounded size.");
  const request = decodePhase4Contract("vegastack-labs.dev/host-replacement-request", JSON.parse(raw)) as unknown as HostReplacementRequest;
  if (request.oldHostId === request.newHostId || request.oldIdentityDigest === request.newIdentityDigest || request.osPreparation.hostIdentityDigest !== request.newIdentityDigest) throw new Error("Replacement identities must be distinct and match preparation.");
  if (request.restorationClass === "control-database" ? !request.source : Boolean(request.source) || request.payloadIds.length !== 0) throw new Error("The restoration class must match its source.");
  if (request.aliasBindings.some(a => a.ownerHostId !== request.oldHostId || a.ownerIdentityDigest !== request.oldIdentityDigest)) throw new Error("Alias owners must match the old host.");
  return request;
}
