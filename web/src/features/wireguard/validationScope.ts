export type ValidationPeer = {
  name: string;
  allowedIPs: string[];
};

export type ScopedValidationErrors = {
  interfaceErrors: string[];
  peerErrors: string[][];
};

function trimValidationPrefix(message: string) {
  return message.replace(/^WireGuard (?:配置无效|配置冲突):\s*/, "");
}

export function scopeValidationErrors(
  messages: readonly string[],
  peers: readonly ValidationPeer[],
): ScopedValidationErrors {
  const interfaceErrors: string[] = [];
  const peerErrors = peers.map(() => [] as string[]);

  for (const message of messages) {
    if (
      message.includes("AllowedIPs") &&
      (message.includes("客户端路由范围") || message.includes("路由范围约束"))
    ) {
      continue;
    }
    const indexed = /^Peer (\d+)（.*?）：\s*(.*)$/.exec(message);
    if (indexed) {
      const peerIndex = Number(indexed[1]) - 1;
      if (peerIndex >= 0 && peerIndex < peers.length) {
        peerErrors[peerIndex].push(trimValidationPrefix(indexed[2]));
        continue;
      }
    }

    const matchingIndexes = peers.flatMap((peer, index) =>
      message.includes(`Peer ${JSON.stringify(peer.name)} 的`) ? [index] : [],
    );
    const narrowedIndexes =
      matchingIndexes.length > 1
        ? matchingIndexes.filter((index) =>
            peers[index].allowedIPs.some((allowedIP) =>
              message.includes(allowedIP),
            ),
          )
        : matchingIndexes;
    const targetIndexes = narrowedIndexes.length
      ? narrowedIndexes
      : matchingIndexes;
    if (targetIndexes.length) {
      for (const peerIndex of targetIndexes) {
        const peerPrefix = `Peer ${JSON.stringify(peers[peerIndex].name)} 的 `;
        const prefixAt = message.indexOf(peerPrefix);
        peerErrors[peerIndex].push(
          trimValidationPrefix(message.slice(prefixAt + peerPrefix.length)),
        );
      }
      continue;
    }

    interfaceErrors.push(message);
  }

  return { interfaceErrors, peerErrors };
}
