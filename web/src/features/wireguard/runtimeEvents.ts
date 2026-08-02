import type {
  InterfaceRuntimeState,
  InterfaceRuntimeStatus,
  InterfaceTrafficEvent,
  PeerRuntimeStatus,
} from "./api";

const emptyPeer = (publicKey: string): PeerRuntimeStatus => ({
  publicKey,
  available: false,
  active: false,
  currentEndpoint: "",
  receivedBytes: 0,
  sentBytes: 0,
  receiveBytesPerSecond: 0,
  sendBytesPerSecond: 0,
  activeDurationSeconds: 0,
  inactiveDurationSeconds: 0,
});

export function mergeRuntimeState(
  current: InterfaceRuntimeStatus | undefined,
  event: InterfaceRuntimeState,
): InterfaceRuntimeStatus {
  const currentPeers = new Map(
    current?.peers.map((peer) => [peer.publicKey, peer]) ?? [],
  );
  return {
    ...event,
    peers: event.peers.map((state) => ({
      ...(currentPeers.get(state.publicKey) ?? emptyPeer(state.publicKey)),
      ...state,
    })),
  };
}

export function mergeRuntimeTraffic(
  current: InterfaceRuntimeStatus | undefined,
  event: InterfaceTrafficEvent,
): InterfaceRuntimeStatus {
  const trafficPeers = new Map(
    event.peers.map((peer) => [peer.publicKey, peer]),
  );
  const currentPeers = current?.peers ?? [];
  const seen = new Set<string>();
  const peers = currentPeers.map((peer) => {
    seen.add(peer.publicKey);
    return {
      ...peer,
      ...trafficPeers.get(peer.publicKey),
    };
  });
  for (const traffic of event.peers) {
    if (!seen.has(traffic.publicKey)) {
      peers.push({
        ...emptyPeer(traffic.publicKey),
        ...traffic,
      });
    }
  }
  return {
    interfaceID: event.interfaceID,
    interfaceName: event.interfaceName,
    configurationRevision: event.configurationRevision,
    runtimeControllable: current?.runtimeControllable,
    runtimeStateAvailable: current?.runtimeStateAvailable,
    running: current?.running,
    collectorAvailable: current?.collectorAvailable ?? true,
    message: current?.message,
    sampledAt: event.sampledAt ?? current?.sampledAt,
    peers,
  };
}
