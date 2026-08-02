import type {
  InterfaceInput,
  PeerInput,
  WireGuardInterface,
  WireGuardPeer,
} from "./api";

function normalizedList(values: readonly string[]) {
  const result: string[] = [];
  const seen = new Set<string>();
  for (const value of values) {
    for (const part of value.split(",")) {
      const normalized = part.trim();
      if (!normalized || seen.has(normalized)) continue;
      seen.add(normalized);
      result.push(normalized);
    }
  }
  return result;
}

function sameList(left: readonly string[], right: readonly string[]) {
  const normalizedLeft = normalizedList(left);
  const normalizedRight = normalizedList(right);
  return (
    normalizedLeft.length === normalizedRight.length &&
    normalizedLeft.every((value, index) => value === normalizedRight[index])
  );
}

export function interfaceMatchesInput(
  config: WireGuardInterface,
  input: InterfaceInput,
) {
  return (
    config.privateKey === input.privateKey.trim() &&
    sameList(config.address, input.address) &&
    config.listenPort === input.listenPort &&
    sameList(config.dns, input.dns) &&
    config.mtu === input.mtu &&
    config.clientEndpoint === input.clientEndpoint.trim() &&
    sameList(config.clientAllowedIPs, input.clientAllowedIPs)
  );
}

export function peerMatchesInput(peer: WireGuardPeer, input: PeerInput) {
  return (
    peer.name === input.name.trim() &&
    peer.privateKey === input.privateKey.trim() &&
    peer.publicKey === input.publicKey.trim() &&
    peer.presharedKey === input.presharedKey.trim() &&
    sameList(peer.allowedIPs, input.allowedIPs) &&
    peer.endpoint === input.endpoint.trim() &&
    peer.persistentKeepalive === input.persistentKeepalive
  );
}
