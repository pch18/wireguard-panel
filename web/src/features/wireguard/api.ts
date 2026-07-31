import {
  ApiError,
  jsonRequest,
  notifySessionExpired,
  request,
} from "../../app/apiClient";
export { linesToValues, valuesToLines } from "./formUtils";

export type WireGuardPeer = {
  id: string;
  name: string;
  privateKey: string;
  publicKey: string;
  presharedKey: string;
  allowedIPs: string[];
  endpoint: string;
  persistentKeepalive?: number;
  clientAddress: string[];
  clientPersistentKeepalive?: number;
  systemGenerated: boolean;
};

export type WireGuardInterface = {
  id: number;
  filename: string;
  revision: string;
  name: string;
  privateKey: string;
  address: string[];
  listenPort?: number;
  fwMark: string;
  dns: string[];
  mtu?: number;
  table: string;
  preUp: string[];
  postUp: string[];
  preDown: string[];
  postDown: string[];
  saveConfig: boolean;
  clientEndpoint: string;
  clientDNS: string[];
  clientAllowedIPs: string[];
  clientPersistentKeepalive?: number;
  peers: WireGuardPeer[];
};

export type InterfaceInput = Omit<
  WireGuardInterface,
  "id" | "filename" | "revision" | "peers"
>;

export type PeerInput = {
  name: string;
  privateKey: string;
  publicKey: string;
  presharedKey: string;
  allowedIPs: string[];
  endpoint: string;
  persistentKeepalive?: number;
  clientAddress: string[];
  clientPersistentKeepalive?: number;
  generateKeyPair: boolean;
  generatePresharedKey: boolean;
};

export type IPPlan = {
  networks: IPNetworkPlan[];
  conflicts: IPConflict[];
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
  peerID?: string;
  message: string;
};

export type InterfaceRuntimeStatus = {
  interfaceID: number;
  interfaceName: string;
  collectorAvailable: boolean;
  message?: string;
  sampledAt?: string;
  peers: PeerRuntimeStatus[];
};

export type PeerRuntimeStatus = {
  peerID: string;
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
  history: TrafficPoint[];
};

export type TrafficPoint = {
  timestamp: string;
  receivedBytes: number;
  sentBytes: number;
};

export const blankInterface = (): InterfaceInput => ({
  name: "",
  privateKey: "",
  address: [],
  listenPort: undefined,
  fwMark: "",
  dns: [],
  mtu: undefined,
  table: "",
  preUp: [],
  postUp: [],
  preDown: [],
  postDown: [],
  saveConfig: false,
  clientEndpoint: "",
  clientDNS: [],
  clientAllowedIPs: [],
  clientPersistentKeepalive: 25,
});

export const blankPeer = (): PeerInput => ({
  name: "",
  privateKey: "",
  publicKey: "",
  presharedKey: "",
  allowedIPs: [],
  endpoint: "",
  persistentKeepalive: undefined,
  clientAddress: [],
  clientPersistentKeepalive: 25,
  generateKeyPair: true,
  generatePresharedKey: false,
});

export async function listInterfaces() {
  const response = await request<{ interfaces: WireGuardInterface[] }>(
    "/api/v1/interfaces",
  );
  return response.interfaces;
}

export function getInterface(id: number) {
  return request<WireGuardInterface>(`/api/v1/interfaces/${id}`);
}

export function createInterface(input: InterfaceInput) {
  return request<WireGuardInterface>(
    "/api/v1/interfaces",
    jsonRequest("POST", input),
  );
}

export function updateInterface(
  id: number,
  revision: string,
  input: InterfaceInput,
) {
  return request<WireGuardInterface>(
    `/api/v1/interfaces/${id}`,
    revisionJSONRequest("PUT", revision, input),
  );
}

export function deleteInterface(id: number, revision: string) {
  return request<void>(`/api/v1/interfaces/${id}`, {
    method: "DELETE",
    headers: revisionHeader(revision),
  });
}

export function createPeer(
  interfaceID: number,
  revision: string,
  input: PeerInput,
) {
  return request<WireGuardInterface>(
    `/api/v1/interfaces/${interfaceID}/peers`,
    revisionJSONRequest("POST", revision, input),
  );
}

export function updatePeer(
  interfaceID: number,
  peerID: string,
  revision: string,
  input: PeerInput,
) {
  return request<WireGuardInterface>(
    `/api/v1/interfaces/${interfaceID}/peers/${encodeURIComponent(peerID)}`,
    revisionJSONRequest("PUT", revision, input),
  );
}

export function deletePeer(
  interfaceID: number,
  peerID: string,
  revision: string,
) {
  return request<WireGuardInterface>(
    `/api/v1/interfaces/${interfaceID}/peers/${encodeURIComponent(peerID)}`,
    {
      method: "DELETE",
      headers: revisionHeader(revision),
    },
  );
}

export function getIPPlan(interfaceID: number) {
  return request<IPPlan>(`/api/v1/interfaces/${interfaceID}/ip-plan`);
}

export function getRuntimeStatus(interfaceID: number) {
  return request<InterfaceRuntimeStatus>(
    `/api/v1/interfaces/${interfaceID}/status`,
  );
}

export async function downloadClientConfig(
  interfaceID: number,
  peerID: string,
) {
  const response = await fetch(
    `/api/v1/interfaces/${interfaceID}/peers/${encodeURIComponent(peerID)}/client-config`,
    {
      credentials: "same-origin",
      headers: { Accept: "text/plain" },
    },
  );
  if (!response.ok) {
    const body = (await response.json().catch(() => ({}))) as {
      error?: { code?: string; message?: string };
    };
    if (response.status === 401) notifySessionExpired();
    throw new ApiError(
      body.error?.message || `客户端配置生成失败（${response.status}）`,
      response.status,
      body.error?.code,
    );
  }
  const disposition = response.headers.get("Content-Disposition") ?? "";
  const match = /filename="([^"]+)"/i.exec(disposition);
  const filename = match?.[1] || `wireguard-peer-${peerID}.conf`;
  const url = URL.createObjectURL(await response.blob());
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.append(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
  return filename;
}

export function interfaceToInput(config: WireGuardInterface): InterfaceInput {
  return {
    name: config.name,
    privateKey: config.privateKey,
    address: [...config.address],
    listenPort: config.listenPort,
    fwMark: config.fwMark,
    dns: [...config.dns],
    mtu: config.mtu,
    table: config.table,
    preUp: [...config.preUp],
    postUp: [...config.postUp],
    preDown: [...config.preDown],
    postDown: [...config.postDown],
    saveConfig: config.saveConfig,
    clientEndpoint: config.clientEndpoint,
    clientDNS: [...config.clientDNS],
    clientAllowedIPs: [...config.clientAllowedIPs],
    clientPersistentKeepalive: config.clientPersistentKeepalive,
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
    clientAddress: [...peer.clientAddress],
    clientPersistentKeepalive: peer.clientPersistentKeepalive,
    generateKeyPair: false,
    generatePresharedKey: false,
  };
}

function revisionHeader(revision: string) {
  return { "If-Match": `"${revision}"` };
}

function revisionJSONRequest(
  method: string,
  revision: string,
  body: unknown,
): RequestInit {
  const init = jsonRequest(method, body);
  return {
    ...init,
    headers: {
      ...init.headers,
      ...revisionHeader(revision),
    },
  };
}
