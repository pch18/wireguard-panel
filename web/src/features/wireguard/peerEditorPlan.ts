import type {
  IPAssignment,
  IPPlan,
  WireGuardInterface,
} from "./api";
import { parseCIDR, parseIPAddress } from "./ipAddress.ts";

export type PeerEditorPlan = Pick<
  IPPlan,
  "allowedRanges" | "reservedAddresses" | "assignments"
>;

function fallbackAllowedRanges(config: WireGuardInterface) {
  return config.clientAllowedIPs.flatMap((value) => {
    const parsed = parseCIDR(value);
    return parsed ? [parsed.canonical] : [];
  });
}

function fallbackReservedAddresses(config: WireGuardInterface) {
  return config.address.flatMap((value) => {
    const separator = value.lastIndexOf("/");
    const parsed = parseIPAddress(
      separator >= 0 ? value.slice(0, separator) : value,
    );
    if (!parsed) return [];
    return [`${parsed.canonical}/${parsed.family === 4 ? 32 : 128}`];
  });
}

function fallbackAssignments(config: WireGuardInterface): IPAssignment[] {
  return config.peers.flatMap((peer) =>
    peer.allowedIPs.flatMap((value) => {
      const parsed = parseCIDR(value);
      return parsed
        ? [
            {
              allowedIP: parsed.canonical,
              peerPublicKey: peer.publicKey,
              peerName: peer.name,
            },
          ]
        : [];
    }),
  );
}

// The IP-plan endpoint is advisory and can arrive after the Interface itself.
// Build the same essential plan from the current backend configuration so the
// editor never changes validation semantics merely because that request was
// slow or unavailable.
export function peerEditorPlan(
  config: WireGuardInterface,
  plan?: IPPlan,
): PeerEditorPlan {
  if (plan?.revision === config.revision) {
    return {
      allowedRanges: plan.allowedRanges,
      reservedAddresses: plan.reservedAddresses,
      assignments: plan.assignments,
    };
  }
  return {
    allowedRanges: fallbackAllowedRanges(config),
    reservedAddresses: fallbackReservedAddresses(config),
    assignments: fallbackAssignments(config),
  };
}
