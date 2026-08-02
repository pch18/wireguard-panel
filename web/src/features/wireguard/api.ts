import {
  ApiError,
  jsonRequest,
  notifySessionExpired,
  request,
} from "../../app/apiClient";
import { peerPublicKeyPath } from "./peerPath";
export {
  digitsOnly,
  interfaceNameOnly,
  linesToValues,
  nextInterfaceName,
  valuesToInline,
  valuesToLines,
} from "./formUtils";
export { peerPublicKeyPath } from "./peerPath";

export type WireGuardPeer = {
  name: string;
  privateKey: string;
  publicKey: string;
  presharedKey: string;
  allowedIPs: string[];
  endpoint: string;
  persistentKeepalive?: number;
};

export type WireGuardInterface = {
  id: string;
  filename: string;
  revision: string;
  privateKey: string;
  address: string[];
  listenPort?: number;
  dns: string[];
  mtu?: number;
  clientEndpoint: string;
  clientAllowedIPs: string[];
  peers: WireGuardPeer[];
  validationErrors?: string[];
};

export type InterfaceProblem = {
  id: string;
  filename: string;
  message: string;
};

export type InterfaceInventory = {
  interfaces: WireGuardInterface[];
  occupiedNames: string[];
  problems: InterfaceProblem[];
};

export type InterfaceInput = Omit<
  WireGuardInterface,
  "id" | "filename" | "revision" | "peers" | "validationErrors"
>;

export type PeerInput = {
  name: string;
  privateKey: string;
  publicKey: string;
  presharedKey: string;
  allowedIPs: string[];
  endpoint: string;
  persistentKeepalive?: number;
};

export type MTUProbeResult = {
  target: string;
  method: "icmp-echo-df";
  pathMTU: number;
  wireGuardMTU: number;
  overheadBytes: number;
};

export const interfacesChangedEvent = "wireguard-panel:interfaces-changed";

function notifyInterfacesChanged() {
  if (typeof window !== "undefined") {
    window.dispatchEvent(new Event(interfacesChangedEvent));
  }
}

async function refreshInterfacesAfter<T>(operation: Promise<T>) {
  try {
    return await operation;
  } finally {
    // A network interruption can happen after the server has committed a
    // mutation but before the response reaches the browser. Always reconcile
    // the inventory instead of assuming that a rejected fetch means no change.
    notifyInterfacesChanged();
  }
}

export type IPPlan = {
  revision: string;
  networks: IPNetworkPlan[];
  allowedRanges: string[];
  reservedAddresses: string[];
  assignments: IPAssignment[];
  conflicts: IPConflict[];
};

export type IPAssignment = {
  allowedIP: string;
  peerPublicKey: string;
  peerName: string;
};

export type IPNetworkPlan = {
  network: string;
  interfaceAddresses: string[];
  allocatedAddresses: string[];
  suggestedAddress: string;
  suggestedAllowedIP: string;
  availableForPlanning: boolean;
};

export type IPConflict = {
  kind: string;
  address: string;
  peerPublicKey?: string;
  message: string;
};

export type InterfaceRuntimeStatus = {
  interfaceID: string;
  interfaceName: string;
  configurationRevision: string;
  runtimeControllable?: boolean;
  runtimeStateAvailable?: boolean;
  running?: boolean;
  collectorAvailable: boolean;
  message?: string;
  sampledAt?: string;
  peers: PeerRuntimeStatus[];
};

export type PeerRuntimeStatus = {
  publicKey: string;
  available: boolean;
  active: boolean;
  currentEndpoint: string;
  lastHandshakeAt?: string;
  receivedBytes: number;
  sentBytes: number;
  receiveBytesPerSecond: number;
  sendBytesPerSecond: number;
  activeDurationSeconds: number;
  inactiveDurationSeconds: number;
};

export type TrafficPoint = {
  sampledAt: string;
  receiveBytesPerSecond: number;
  sendBytesPerSecond: number;
};

export type InterfaceTrafficEvent = {
  kind: "history" | "update";
  status: InterfaceRuntimeStatus;
  interfaceTraffic: TrafficPoint[];
  peerTraffic: Record<string, TrafficPoint[]>;
};

export const blankInterface = (): InterfaceInput => ({
  privateKey: "",
  address: [],
  listenPort: undefined,
  dns: [],
  mtu: undefined,
  clientEndpoint: "",
  clientAllowedIPs: [],
});

export const blankPeer = (): PeerInput => ({
  name: "",
  privateKey: "",
  publicKey: "",
  presharedKey: "",
  allowedIPs: [],
  endpoint: "",
  persistentKeepalive: undefined,
});

export function probeWireGuardMTU() {
  return request<MTUProbeResult>("/api/v1/wireguard/mtu-probe", {
    method: "POST",
  });
}

export function listInterfaces() {
  return request<InterfaceInventory>("/api/v1/interfaces");
}

function interfacePath(id: string) {
  return encodeURIComponent(id);
}

export function getInterface(id: string) {
  return request<WireGuardInterface>(`/api/v1/interfaces/${interfacePath(id)}`);
}

export function createInterface(name: string, input: InterfaceInput) {
  return refreshInterfacesAfter(
    request<WireGuardInterface>(
      "/api/v1/interfaces",
      jsonRequest("POST", { name, ...input }),
    ),
  );
}

export function renameInterface(
  id: string,
  revision: string,
  name: string,
) {
  return refreshInterfacesAfter(
    request<WireGuardInterface>(
      `/api/v1/interfaces/${interfacePath(id)}/rename`,
      revisionJSONRequest("POST", revision, { name }),
    ),
  );
}

export function updateInterface(
  id: string,
  revision: string,
  input: InterfaceInput,
  restartConfirmed = false,
) {
  return refreshInterfacesAfter(
    request<WireGuardInterface>(
      `/api/v1/interfaces/${interfacePath(id)}`,
      revisionJSONRequest("PUT", revision, input, restartConfirmed),
    ),
  );
}

export function deleteInterface(id: string, revision: string) {
  return refreshInterfacesAfter(
    request<void>(`/api/v1/interfaces/${interfacePath(id)}`, {
      method: "DELETE",
      headers: revisionHeader(revision),
    }),
  );
}

export function createPeer(
  interfaceID: string,
  revision: string,
  input: PeerInput,
  restartConfirmed = false,
) {
  return refreshInterfacesAfter(
    request<WireGuardInterface>(
      `/api/v1/interfaces/${interfacePath(interfaceID)}/peers`,
      revisionJSONRequest("POST", revision, input, restartConfirmed),
    ),
  );
}

export function updatePeer(
  interfaceID: string,
  originalPublicKey: string,
  revision: string,
  input: PeerInput,
  restartConfirmed = false,
) {
  return refreshInterfacesAfter(
    request<WireGuardInterface>(
      `/api/v1/interfaces/${interfacePath(interfaceID)}/peers/${peerPublicKeyPath(originalPublicKey)}`,
      revisionJSONRequest("PUT", revision, input, restartConfirmed),
    ),
  );
}

export function deletePeer(
  interfaceID: string,
  publicKey: string,
  revision: string,
  restartConfirmed = false,
) {
  return refreshInterfacesAfter(
    request<WireGuardInterface>(
      `/api/v1/interfaces/${interfacePath(interfaceID)}/peers/${peerPublicKeyPath(publicKey)}`,
      {
        method: "DELETE",
        headers: mutationHeaders(revision, restartConfirmed),
      },
    ),
  );
}

export function getIPPlan(interfaceID: string) {
  return request<IPPlan>(`/api/v1/interfaces/${interfacePath(interfaceID)}/ip-plan`);
}

export function getRuntimeStatus(interfaceID: string) {
  return request<InterfaceRuntimeStatus>(
    `/api/v1/interfaces/${interfacePath(interfaceID)}/status`,
  );
}

export function runtimeEventsURL(interfaceID: string) {
  return `/api/v1/interfaces/${interfacePath(interfaceID)}/events`;
}

export function startInterface(interfaceID: string, revision: string) {
  return request<WireGuardInterface>(
    `/api/v1/interfaces/${interfacePath(interfaceID)}/start`,
    { method: "POST", headers: revisionHeader(revision) },
  );
}

export function stopInterface(interfaceID: string, revision: string) {
  return request<WireGuardInterface>(
    `/api/v1/interfaces/${interfacePath(interfaceID)}/stop`,
    { method: "POST", headers: revisionHeader(revision) },
  );
}

export function restartInterface(interfaceID: string, revision: string) {
  return request<WireGuardInterface>(
    `/api/v1/interfaces/${interfacePath(interfaceID)}/restart`,
    { method: "POST", headers: revisionHeader(revision) },
  );
}

export function importInterfaceConfig(config: string) {
  return refreshInterfacesAfter(
    request<WireGuardInterface>(
      "/api/v1/interfaces/import",
      jsonRequest("POST", { config }),
    ),
  );
}

export function replaceInterfaceConfig(
  interfaceID: string,
  revision: string,
  config: string,
  restartConfirmed = false,
) {
  return refreshInterfacesAfter(
    request<WireGuardInterface>(
      `/api/v1/interfaces/${interfacePath(interfaceID)}/import`,
      revisionJSONRequest("PUT", revision, { config }, restartConfirmed),
    ),
  );
}

export function importPeerConfig(
  interfaceID: string,
  revision: string,
  config: string,
  restartConfirmed = false,
) {
  return refreshInterfacesAfter(
    request<WireGuardInterface>(
      `/api/v1/interfaces/${interfacePath(interfaceID)}/peers/import`,
      revisionJSONRequest("POST", revision, { config }, restartConfirmed),
    ),
  );
}

export function getInterfaceConfig(interfaceID: string) {
  return requestText(`/api/v1/interfaces/${interfacePath(interfaceID)}/config`);
}

export function getRawInterfaceConfig(interfaceID: string) {
  return requestText(
    `/api/v1/interfaces/${interfacePath(interfaceID)}/raw-config`,
  );
}

export function getPeerConfig(interfaceID: string, publicKey: string) {
  return requestText(
    `/api/v1/interfaces/${interfacePath(interfaceID)}/peers/${peerPublicKeyPath(publicKey)}/config`,
  );
}

export function getClientConfigPreview(
  interfaceID: string,
  publicKey: string,
) {
  return requestText(
    `/api/v1/interfaces/${interfacePath(interfaceID)}/peers/${peerPublicKeyPath(publicKey)}/client-config`,
  );
}

async function requestText(path: string) {
  const response = await fetch(path, {
    credentials: "same-origin",
    headers: { Accept: "text/plain" },
  });
  if (!response.ok) {
    const body = (await response.json().catch(() => ({}))) as {
      error?: { code?: string; message?: string };
    };
    if (response.status === 401) notifySessionExpired();
    throw new ApiError(
      body.error?.message || `请求失败（${response.status}）`,
      response.status,
      body.error?.code,
    );
  }
  return response.text();
}

export function interfaceToInput(config: WireGuardInterface): InterfaceInput {
  return {
    privateKey: config.privateKey,
    address: [...config.address],
    listenPort: config.listenPort,
    dns: [...config.dns],
    mtu: config.mtu,
    clientEndpoint: config.clientEndpoint,
    clientAllowedIPs: [...config.clientAllowedIPs],
  };
}

export function peerToInput(peer: WireGuardPeer): PeerInput {
  return {
    name: peer.name,
    privateKey: peer.privateKey,
    publicKey: peer.publicKey,
    presharedKey: peer.presharedKey,
    allowedIPs: [...peer.allowedIPs],
    endpoint: peer.endpoint,
    persistentKeepalive: peer.persistentKeepalive,
  };
}

function revisionHeader(revision: string) {
  return { "If-Match": `"${revision}"` };
}

function mutationHeaders(revision: string, restartConfirmed: boolean) {
  return {
    ...revisionHeader(revision),
    ...(restartConfirmed
      ? { "X-WireGuard-Restart-Confirmed": "true" }
      : {}),
  };
}

function revisionJSONRequest(
  method: string,
  revision: string,
  body: unknown,
  restartConfirmed = false,
): RequestInit {
  const init = jsonRequest(method, body);
  return {
    ...init,
    headers: {
      ...init.headers,
      ...mutationHeaders(revision, restartConfirmed),
    },
  };
}
