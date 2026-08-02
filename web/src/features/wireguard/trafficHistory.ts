import type { TrafficPoint } from "./api";

export const trafficRetentionMilliseconds = 60 * 60_000;

export function mergeTrafficPoints(
  current: TrafficPoint[],
  incoming: TrafficPoint[],
  retentionMilliseconds = trafficRetentionMilliseconds,
) {
  const points = new Map<number, TrafficPoint>();
  for (const point of [...current, ...incoming]) {
    const sampledAt = Date.parse(point.sampledAt);
    if (
      !Number.isFinite(sampledAt) ||
      !Number.isFinite(point.receiveBytesPerSecond) ||
      !Number.isFinite(point.sendBytesPerSecond)
    ) {
      continue;
    }
    points.set(sampledAt, {
      ...point,
      receiveBytesPerSecond: Math.max(0, point.receiveBytesPerSecond),
      sendBytesPerSecond: Math.max(0, point.sendBytesPerSecond),
    });
  }
  const timestamps = [...points.keys()].sort((left, right) => left - right);
  const newest = timestamps.at(-1);
  if (newest === undefined) return [];
  const cutoff = newest - retentionMilliseconds;
  return timestamps
    .filter((timestamp) => timestamp >= cutoff)
    .map((timestamp) => points.get(timestamp)!);
}

export function mergePeerTraffic(
  current: Map<string, TrafficPoint[]>,
  incoming: Record<string, TrafficPoint[]>,
  replace = false,
) {
  const next = replace ? new Map<string, TrafficPoint[]>() : new Map(current);
  for (const [publicKey, points] of Object.entries(incoming)) {
    next.set(
      publicKey,
      mergeTrafficPoints(replace ? [] : next.get(publicKey) ?? [], points),
    );
  }
  return next;
}
