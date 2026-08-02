import type {
  InterfaceInput,
  PeerInput,
  WireGuardInterface,
  WireGuardPeer,
} from "./api";

export type RuntimeApplyMode = "file" | "hot" | "restart";

export type RuntimeChangeImpact = {
  mode: RuntimeApplyMode;
  changes: string[];
  requiresConfirmation: boolean;
};

function sameValues(left: readonly string[], right: readonly string[]) {
  return (
    left.length === right.length &&
    left.every((value, index) => value === right[index])
  );
}

function sameOptionalNumber(left?: number, right?: number) {
  return left === right;
}

function hasDefaultRoute(values: readonly string[]) {
  return values.some((value) => {
    const [address, prefix, extra] = value.trim().toLowerCase().split("/");
    if (prefix !== "0" || extra !== undefined || !address) return false;
    if (address.includes(":")) return /^[0-9a-f:.]+$/.test(address);
    const octets = address.split(".");
    return (
      octets.length === 4 &&
      octets.every((octet) => /^\d{1,3}$/.test(octet) && Number(octet) <= 255)
    );
  });
}

function interfaceHasDefaultRoute(peers: readonly WireGuardPeer[]) {
  return peers.some((peer) => hasDefaultRoute(peer.allowedIPs));
}

function mtuNeedsRestart(before?: number, after?: number) {
  return before !== after && after === undefined;
}

export function analyzeInterfaceChange(
  current: WireGuardInterface,
  next: InterfaceInput,
): RuntimeChangeImpact {
  const changes: string[] = [];
  let mode: RuntimeApplyMode = "file";

  if (current.privateKey !== next.privateKey) {
    mode = "hot";
    changes.push(
      "PrivateKey：将立即更换 Interface 身份；所有客户端必须改用新的服务端公钥，否则会失联。",
    );
  }
  if (!sameValues(current.address, next.address)) {
    mode = "hot";
    changes.push(
      "Address：将在线调整接口地址和路由；仍使用旧地址的连接可能中断。",
    );
  }
  if (!sameOptionalNumber(current.listenPort, next.listenPort)) {
    if (mode === "file") mode = "hot";
    if (next.listenPort === undefined) {
      changes.push(
        "Listen Port：将在线切换为随机端口；客户端必须同步新的 Endpoint 才能重新连接。",
      );
    } else {
      changes.push(
        "Listen Port：将立即切换监听端口；客户端 Endpoint 未同步时将无法重新连接。",
      );
    }
  }
  if (!sameValues(current.dns, next.dns)) {
    mode = "restart";
    changes.push(
      "DNS：保存时会短暂停止并重新启动 Interface。",
    );
  }
  if (!sameOptionalNumber(current.mtu, next.mtu)) {
    if (mtuNeedsRestart(current.mtu, next.mtu)) {
      mode = "restart";
      changes.push(
        "MTU：切回自动值时会短暂停止并重新启动 Interface。",
      );
    } else {
      if (mode === "file") mode = "hot";
      changes.push("MTU：将在线更新链路 MTU；不合适的值可能导致部分流量不可达。");
    }
  }

  return {
    mode,
    changes,
    requiresConfirmation: mode === "restart",
  };
}

export function analyzePeerChange(
  currentInterface: WireGuardInterface,
  original: WireGuardPeer | undefined,
  next: PeerInput,
): RuntimeChangeImpact {
  const peers = original
    ? currentInterface.peers.map((peer) =>
        peer.publicKey === original.publicKey ? { ...peer, ...next } : peer,
      )
    : [...currentInterface.peers, next];
  const defaultRouteChanged =
    interfaceHasDefaultRoute(currentInterface.peers) !==
    interfaceHasDefaultRoute(peers);
  const changes: string[] = [];

  if (defaultRouteChanged) {
    changes.push(
      "默认路由：保存时会短暂停止并重新启动 Interface，以重建策略路由。",
    );
  }
  if (original?.publicKey !== undefined && original.publicKey !== next.publicKey) {
    changes.push("PublicKey：将立即替换 Peer 身份，原密钥对应的客户端会断开。");
  }
  if (
    original?.presharedKey !== undefined &&
    original.presharedKey !== next.presharedKey
  ) {
    changes.push("PresharedKey：客户端未同步相同密钥时，该 Peer 会失联。");
  }
  if (original && !sameValues(original.allowedIPs, next.allowedIPs)) {
    changes.push("AllowedIPs：将立即改变该 Peer 的路由，现有通信可能中断。");
  }
  if (original && original.endpoint !== next.endpoint) {
    changes.push(
      next.endpoint
        ? "Endpoint：将立即改变服务端向该 Peer 发送流量的初始目标地址。"
        : "Endpoint：将移除固定初始地址；当前已认证并学习到的漫游地址可能继续保留。",
    );
  }

  return {
    mode: defaultRouteChanged
      ? "restart"
      : peerInputAffectsRuntime(original, next)
        ? "hot"
        : "file",
    changes,
    requiresConfirmation: defaultRouteChanged,
  };
}

export function peerDeletionNeedsRestart(
  currentInterface: WireGuardInterface,
  publicKey: string,
) {
  return (
    interfaceHasDefaultRoute(currentInterface.peers) !==
    interfaceHasDefaultRoute(
      currentInterface.peers.filter((peer) => peer.publicKey !== publicKey),
    )
  );
}

export function interfaceInputAffectsRuntime(
  current: WireGuardInterface,
  next: InterfaceInput,
) {
  return analyzeInterfaceChange(current, next).mode !== "file";
}

export function peerInputAffectsRuntime(
  current: WireGuardPeer | undefined,
  next: PeerInput,
) {
  if (!current) return true;
  return (
    current.publicKey !== next.publicKey ||
    current.presharedKey !== next.presharedKey ||
    !sameValues(current.allowedIPs, next.allowedIPs) ||
    current.endpoint !== next.endpoint ||
    current.persistentKeepalive !== next.persistentKeepalive
  );
}
