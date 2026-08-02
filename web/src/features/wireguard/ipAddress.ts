export type IPFamily = 4 | 6;

export type ParsedCIDR = {
  family: IPFamily;
  prefix: number;
  network: bigint;
  end: bigint;
  canonical: string;
};

export type AddressRow = {
  id: string;
  family: IPFamily;
  prefix: number | null;
  segments: Array<number | null>;
};

export type SegmentOption = {
  value: number;
  disabled: boolean;
  reason?: "range" | "conflict";
};

export function availableIPFamilies(allowedRanges: ParsedCIDR[]): IPFamily[] {
  if (allowedRanges.length === 0) return [4, 6];
  return ([4, 6] as IPFamily[]).filter((family) =>
    allowedRanges.some((range) => range.family === family),
  );
}

const IPV4_BITS = 32;
const IPV6_BITS = 128;

function totalBits(family: IPFamily) {
  return family === 4 ? IPV4_BITS : IPV6_BITS;
}

export function segmentBits(family: IPFamily) {
  return family === 4 ? 8 : 4;
}

export function segmentCount(family: IPFamily) {
  return totalBits(family) / segmentBits(family);
}

function fullMask(bits: number) {
  return (1n << BigInt(bits)) - 1n;
}

function networkMask(bits: number, prefix: number) {
  if (prefix === 0) return 0n;
  return fullMask(bits) ^ ((1n << BigInt(bits - prefix)) - 1n);
}

function parseIPv4(value: string) {
  const parts = value.split(".");
  if (parts.length !== 4) return null;
  let address = 0n;
  for (const part of parts) {
    if (!/^(0|[1-9]\d{0,2})$/.test(part)) return null;
    const octet = Number(part);
    if (octet > 255) return null;
    address = (address << 8n) | BigInt(octet);
  }
  return address;
}

function expandIPv4Tail(value: string) {
  const lastColon = value.lastIndexOf(":");
  const tail = value.slice(lastColon + 1);
  if (!tail.includes(".")) return value;
  const address = parseIPv4(tail);
  if (address === null) return null;
  const high = Number((address >> 16n) & 0xffffn).toString(16);
  const low = Number(address & 0xffffn).toString(16);
  return `${value.slice(0, lastColon + 1)}${high}:${low}`;
}

function parseIPv6(value: string) {
  const expandedTail = expandIPv4Tail(value.toLowerCase());
  if (expandedTail === null || expandedTail === "") return null;
  const doubleColon = expandedTail.indexOf("::");
  if (doubleColon !== -1 && doubleColon !== expandedTail.lastIndexOf("::")) {
    return null;
  }

  const readSide = (side: string) => {
    if (side === "") return [];
    const groups = side.split(":");
    if (groups.some((group) => !/^[0-9a-f]{1,4}$/.test(group))) return null;
    return groups.map((group) => Number.parseInt(group, 16));
  };

  let groups: number[];
  if (doubleColon === -1) {
    const parsed = readSide(expandedTail);
    if (!parsed || parsed.length !== 8) return null;
    groups = parsed;
  } else {
    const left = readSide(expandedTail.slice(0, doubleColon));
    const right = readSide(expandedTail.slice(doubleColon + 2));
    if (!left || !right || left.length + right.length >= 8) return null;
    groups = [
      ...left,
      ...Array.from({ length: 8 - left.length - right.length }, () => 0),
      ...right,
    ];
  }

  let address = 0n;
  for (const group of groups) {
    address = (address << 16n) | BigInt(group);
  }
  return address;
}

function formatIPv4(address: bigint) {
  return [24n, 16n, 8n, 0n]
    .map((shift) => Number((address >> shift) & 0xffn))
    .join(".");
}

export function formatIPv6(address: bigint) {
  const groups = Array.from({ length: 8 }, (_, index) =>
    Number((address >> BigInt((7 - index) * 16)) & 0xffffn),
  );
  let bestStart = -1;
  let bestLength = 0;
  for (let index = 0; index < groups.length; ) {
    if (groups[index] !== 0) {
      index += 1;
      continue;
    }
    let end = index;
    while (end < groups.length && groups[end] === 0) end += 1;
    if (end - index > bestLength && end - index >= 2) {
      bestStart = index;
      bestLength = end - index;
    }
    index = end;
  }
  if (bestStart === -1) {
    return groups.map((group) => group.toString(16)).join(":");
  }
  const left = groups
    .slice(0, bestStart)
    .map((group) => group.toString(16))
    .join(":");
  const right = groups
    .slice(bestStart + bestLength)
    .map((group) => group.toString(16))
    .join(":");
  return `${left}::${right}`;
}

export function formatAddress(address: bigint, family: IPFamily) {
  return family === 4 ? formatIPv4(address) : formatIPv6(address);
}

export function parseIPAddress(value: string, expectedFamily?: IPFamily) {
  const normalized = value.trim();
  if (normalized === "") return null;
  const family: IPFamily = normalized.includes(":") ? 6 : 4;
  if (expectedFamily !== undefined && family !== expectedFamily) return null;
  const address = family === 4 ? parseIPv4(normalized) : parseIPv6(normalized);
  if (address === null) return null;
  return {
    family,
    address,
    canonical: formatAddress(address, family),
  };
}

export function parseCIDR(value: string): ParsedCIDR | null {
  const parts = value.trim().split("/");
  if (parts.length !== 2 || !/^(0|[1-9]\d{0,2})$/.test(parts[1])) {
    return null;
  }
  const family: IPFamily = parts[0].includes(":") ? 6 : 4;
  const bits = totalBits(family);
  const prefix = Number(parts[1]);
  if (prefix < 0 || prefix > bits) return null;
  const parsedAddress = parseIPAddress(parts[0], family);
  if (!parsedAddress) return null;
  const address = parsedAddress.address;
  const network = address & networkMask(bits, prefix);
  const end = network | (fullMask(bits) ^ networkMask(bits, prefix));
  return {
    family,
    prefix,
    network,
    end,
    canonical: `${formatAddress(network, family)}/${prefix}`,
  };
}

export function parseCIDRs(values: string[]) {
  return values.flatMap((value) => {
    const parsed = parseCIDR(value);
    return parsed ? [parsed] : [];
  });
}

function addressSegments(address: bigint, family: IPFamily) {
  const bits = segmentBits(family);
  const count = segmentCount(family);
  const unitMask = (1n << BigInt(bits)) - 1n;
  return Array.from({ length: count }, (_, index) =>
    Number(
      (address >> BigInt((count - index - 1) * bits)) & unitMask,
    ),
  );
}

export function blankAddressRow(id: string, family: IPFamily = 4): AddressRow {
  return {
    id,
    family,
    prefix: null,
    segments: Array.from({ length: segmentCount(family) }, () => null),
  };
}

export function addressRowFromCIDR(id: string, value: string): AddressRow | null {
  const parsed = parseCIDR(value);
  if (!parsed) return null;
  return {
    id,
    family: parsed.family,
    prefix: parsed.prefix,
    segments: addressSegments(parsed.network, parsed.family),
  };
}

function alignUp(value: bigint, step: bigint) {
  const remainder = value % step;
  return remainder === 0n ? value : value + step - remainder;
}

function possibleInIntervals(
  low: bigint,
  high: bigint,
  subnetSize: bigint,
  allowed: ParsedCIDR[],
  occupied: ParsedCIDR[],
) {
  const forbidden = occupied
    .map((range) => ({
      low: range.network > subnetSize - 1n ? range.network - subnetSize + 1n : 0n,
      high: range.end,
    }))
    .sort((a, b) => (a.low < b.low ? -1 : a.low > b.low ? 1 : 0));

  for (const range of allowed) {
    if (range.end - range.network + 1n < subnetSize) continue;
    const intervalLow = low > range.network ? low : range.network;
    const lastStart = range.end - subnetSize + 1n;
    const intervalHigh = high < lastStart ? high : lastStart;
    if (intervalLow > intervalHigh) continue;
    let candidate = alignUp(intervalLow, subnetSize);
    for (const conflict of forbidden) {
      if (candidate > intervalHigh) break;
      if (conflict.high < candidate) continue;
      if (conflict.low > candidate) return true;
      candidate = alignUp(conflict.high + 1n, subnetSize);
    }
    if (candidate <= intervalHigh) return true;
  }
  return false;
}

function partialInterval(
  family: IPFamily,
  segments: Array<number | null>,
  throughIndex: number,
) {
  const bits = segmentBits(family);
  let value = 0n;
  for (let index = 0; index <= throughIndex; index += 1) {
    const segment = segments[index];
    if (segment === null || segment === undefined) return null;
    value = (value << BigInt(bits)) | BigInt(segment);
  }
  const remaining = totalBits(family) - (throughIndex + 1) * bits;
  const low = value << BigInt(remaining);
  return {
    low,
    high: low | ((1n << BigInt(remaining)) - 1n),
  };
}

function permittedRanges(family: IPFamily, allowedRanges: ParsedCIDR[]) {
  const sameFamily = allowedRanges.filter((range) => range.family === family);
  if (allowedRanges.length > 0) return sameFamily;
  const bits = totalBits(family);
  return [{
    family,
    prefix: 0,
    network: 0n,
    end: fullMask(bits),
    canonical: family === 4 ? "0.0.0.0/0" : "::/0",
  } satisfies ParsedCIDR];
}

function optionCanComplete(
  family: IPFamily,
  prefix: number,
  segments: Array<number | null>,
  index: number,
  allowedRanges: ParsedCIDR[],
  _occupiedRanges: ParsedCIDR[],
) {
  const interval = partialInterval(family, segments, index);
  if (!interval) return { range: false, available: false };
  const subnetSize = 1n << BigInt(totalBits(family) - prefix);
  const allowed = permittedRanges(family, allowedRanges);
  const inRange = possibleInIntervals(
    interval.low,
    interval.high,
    subnetSize,
    allowed,
    [],
  );
  return {
    range: inRange,
    available: inRange,
  };
}

export function prefixAvailability(
  family: IPFamily,
  prefix: number,
  allowedRanges: ParsedCIDR[],
  _occupiedRanges: ParsedCIDR[],
) {
  const bits = totalBits(family);
  const subnetSize = 1n << BigInt(bits - prefix);
  const allowed = permittedRanges(family, allowedRanges);
  const inRange = possibleInIntervals(0n, fullMask(bits), subnetSize, allowed, []);
  return {
    range: inRange,
    available: inRange,
  };
}

export function availablePrefixes(
  family: IPFamily,
  allowedRanges: ParsedCIDR[],
  occupiedRanges: ParsedCIDR[],
) {
  const maximum = totalBits(family);
  return Array.from({ length: maximum + 1 }, (_, prefix) => prefix).filter(
    (prefix) =>
      prefixAvailability(family, prefix, allowedRanges, occupiedRanges)
        .available,
  );
}

export function prefixesIncludingCurrent(
  available: number[],
  current: number | null,
) {
  if (current === null || available.includes(current)) return available;
  return [current, ...available];
}

export function segmentOptions(
  row: AddressRow,
  index: number,
  allowedRanges: ParsedCIDR[],
  occupiedRanges: ParsedCIDR[],
): SegmentOption[] {
  if (row.prefix === null) return [];
  const bits = segmentBits(row.family);
  const startBit = index * bits;
  const networkBits = Math.max(0, Math.min(bits, row.prefix - startBit));
  const step = 2 ** (bits - networkBits);
  const maximum = 2 ** bits;
  if (networkBits === 0) return [{ value: 0, disabled: false }];
  return Array.from({ length: maximum / step }, (_, optionIndex) => {
    const value = optionIndex * step;
    const segments = row.segments.slice();
    segments[index] = value;
    const result = optionCanComplete(
      row.family,
      row.prefix as number,
      segments,
      index,
      allowedRanges,
      occupiedRanges,
    );
    return {
      value,
      disabled: !result.available,
      reason: !result.range ? "range" : !result.available ? "conflict" : undefined,
    };
  });
}

export function selectableSegmentOptions(options: SegmentOption[]) {
  return options.filter((option) => option.reason !== "range");
}

export function normalizeAddressRow(
  source: AddressRow,
  allowedRanges: ParsedCIDR[],
  occupiedRanges: ParsedCIDR[],
) {
  const row: AddressRow = {
    ...source,
    segments: source.segments.slice(0, segmentCount(source.family)),
  };
  while (row.segments.length < segmentCount(row.family)) row.segments.push(null);
  if (row.prefix === null) {
    row.segments.fill(null);
    return row;
  }
  const bits = segmentBits(row.family);
  let previousComplete = true;
  for (let index = 0; index < row.segments.length; index += 1) {
    const isHostOnly = index * bits >= row.prefix;
    if (isHostOnly) {
      row.segments[index] = 0;
      continue;
    }
    if (!previousComplete) {
      row.segments[index] = null;
      continue;
    }
    const options = segmentOptions(row, index, allowedRanges, occupiedRanges);
    const enabled = options.filter((option) => !option.disabled);
    const current = row.segments[index];
    if (!enabled.some((option) => option.value === current)) {
      row.segments[index] = enabled[0]?.value ?? null;
    }
    previousComplete = row.segments[index] !== null;
  }
  return row;
}

export function addressRowComplete(row: AddressRow) {
  if (row.prefix === null) return false;
  const bits = segmentBits(row.family);
  return row.segments.every(
    (segment, index) => index * bits >= (row.prefix as number) || segment !== null,
  );
}

export function addressRowToCIDR(row: AddressRow) {
  if (!addressRowComplete(row) || row.prefix === null) return null;
  const bits = segmentBits(row.family);
  let address = 0n;
  for (const segment of row.segments) {
    address = (address << BigInt(bits)) | BigInt(segment ?? 0);
  }
  return `${formatAddress(address, row.family)}/${row.prefix}`;
}

export function cidrOverlaps(first: ParsedCIDR, second: ParsedCIDR) {
  return (
    first.family === second.family &&
    first.network <= second.end &&
    second.network <= first.end
  );
}

export function cidrContainedByAny(cidr: ParsedCIDR, ranges: ParsedCIDR[]) {
  if (ranges.length === 0) return true;
  const sameFamily = ranges.filter((range) => range.family === cidr.family);
  return sameFamily.some(
    (range) =>
      range.network <= cidr.network &&
      range.end >= cidr.end,
  );
}

export function cidrValueContainedByAny(
  value: string,
  ranges: ParsedCIDR[],
) {
  if (ranges.length === 0) return true;
  const parsed = parseCIDR(value);
  return parsed !== null && cidrContainedByAny(parsed, ranges);
}

export function interfaceAddressContainedByAny(
  value: string,
  ranges: ParsedCIDR[],
) {
  if (ranges.length === 0) return true;
  const parsed = parseIPAddress(value.split("/", 1)[0]);
  return (
    parsed !== null &&
    ranges.some(
      (range) =>
        range.family === parsed.family &&
        range.network <= parsed.address &&
        range.end >= parsed.address,
    )
  );
}

export function validateAddressCIDR(
  address: string,
  prefix: number,
  family: IPFamily,
  allowedRanges: ParsedCIDR[],
  occupiedRanges: ParsedCIDR[],
) {
  const familyLabel = family === 4 ? "IPv4" : "IPv6";
  if (address.trim() === "") {
    return { cidr: null, error: `请输入 ${familyLabel} 地址` };
  }
  const parsed = parseCIDR(`${address.trim()}/${prefix}`);
  if (!parsed || parsed.family !== family) {
    return { cidr: null, error: `${familyLabel} 地址格式无效` };
  }
  if (!cidrContainedByAny(parsed, allowedRanges)) {
    return { cidr: null, error: "地址超出路由范围约束" };
  }
  if (
    occupiedRanges.some(
      (occupied) => occupied.canonical === parsed.canonical,
    )
  ) {
    return { cidr: null, error: "地址与 Interface 或其他 Peer 重复" };
  }
  return { cidr: parsed.canonical, error: "" };
}
