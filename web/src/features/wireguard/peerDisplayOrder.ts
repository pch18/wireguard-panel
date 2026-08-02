type PeerWithAllowedIPs = {
  allowedIPs: string[];
};

type SortKey =
  | { kind: "missing" }
  | { kind: "valid"; family: 4 | 6; address: string; prefix: number }
  | { kind: "invalid"; value: string };

const addressCollator = new Intl.Collator(undefined, {
  numeric: true,
  sensitivity: "base",
});

function firstAllowedIP(peer: PeerWithAllowedIPs) {
  return peer.allowedIPs.find((value) => value.trim() !== "")?.trim();
}

function sortKey(peer: PeerWithAllowedIPs): SortKey {
  const value = firstAllowedIP(peer);
  if (!value) return { kind: "missing" };

  const parts = value.split("/");
  if (parts.length !== 2 || !/^\d{1,3}$/.test(parts[1])) {
    return { kind: "invalid", value };
  }
  const address = parts[0].toLowerCase();
  const family = address.includes(":") ? 6 : 4;
  const prefix = Number(parts[1]);
  const validPrefix = prefix >= 0 && prefix <= (family === 4 ? 32 : 128);
  const validAddress =
    family === 4
      ? address.split(".").length === 4 &&
        address
          .split(".")
          .every(
            (segment) =>
              /^\d{1,3}$/.test(segment) && Number(segment) <= 255,
          )
      : /^[0-9a-f:.]+$/.test(address);
  if (!validPrefix || !validAddress) return { kind: "invalid", value };

  return {
    kind: "valid",
    family,
    address,
    prefix,
  };
}

function compareKeys(left: SortKey, right: SortKey) {
  const rank = { missing: 0, valid: 1, invalid: 2 } as const;
  const rankDifference = rank[left.kind] - rank[right.kind];
  if (rankDifference !== 0) return rankDifference;

  if (left.kind === "valid" && right.kind === "valid") {
    if (left.family !== right.family) return left.family - right.family;
    const addressDifference = addressCollator.compare(
      left.address,
      right.address,
    );
    if (addressDifference !== 0) return addressDifference;
    return left.prefix - right.prefix;
  }
  if (left.kind === "invalid" && right.kind === "invalid") {
    return addressCollator.compare(left.value, right.value);
  }
  return 0;
}

export function sortPeerEntriesByFirstAllowedIP<T extends PeerWithAllowedIPs>(
  peers: readonly T[],
) {
  return peers
    .map((peer, originalIndex) => ({
      peer,
      originalIndex,
      key: sortKey(peer),
    }))
    .sort((left, right) => {
      const comparison = compareKeys(left.key, right.key);
      return comparison || left.originalIndex - right.originalIndex;
    })
    .map(({ peer, originalIndex }) => ({ peer, originalIndex }));
}
