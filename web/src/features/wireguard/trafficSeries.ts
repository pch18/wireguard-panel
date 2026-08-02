export const trafficSampleIntervalMilliseconds = 5_000;
export const trafficGapToleranceMilliseconds =
  trafficSampleIntervalMilliseconds * 1.5;

export type TimedTrafficPoint = {
  timestamp: number;
  sampledAt: string;
  receiveBytesPerSecond: number;
  sendBytesPerSecond: number;
};

type TrafficBucket = TimedTrafficPoint & { measured: boolean };

function zeroBucket(timestamp: number): TrafficBucket {
  return {
    timestamp,
    sampledAt: new Date(timestamp).toISOString(),
    receiveBytesPerSecond: 0,
    sendBytesPerSecond: 0,
    measured: false,
  };
}

export function resampleTrafficSeries(
  points: TimedTrafficPoint[],
  start: number,
  end: number,
  intervalMilliseconds = trafficSampleIntervalMilliseconds,
  maximumCompensatedMissingBuckets = 2,
): TimedTrafficPoint[] {
  if (end < start || intervalMilliseconds <= 0) return [];
  const firstTimestamp =
    Math.ceil(start / intervalMilliseconds) * intervalMilliseconds;
  const lastTimestamp =
    Math.floor(end / intervalMilliseconds) * intervalMilliseconds;
  if (lastTimestamp < firstTimestamp) return [];

  const measured = new Map<
    number,
    { receive: number; send: number; count: number }
  >();
  for (const point of points) {
    const timestamp =
      Math.round(point.timestamp / intervalMilliseconds) *
      intervalMilliseconds;
    if (timestamp < firstTimestamp || timestamp > lastTimestamp) continue;
    const bucket = measured.get(timestamp) ?? { receive: 0, send: 0, count: 0 };
    bucket.receive += Math.max(0, point.receiveBytesPerSecond);
    bucket.send += Math.max(0, point.sendBytesPerSecond);
    bucket.count++;
    measured.set(timestamp, bucket);
  }

  const buckets: TrafficBucket[] = [];
  for (
    let timestamp = firstTimestamp;
    timestamp <= lastTimestamp;
    timestamp += intervalMilliseconds
  ) {
    const value = measured.get(timestamp);
    if (!value) {
      buckets.push(zeroBucket(timestamp));
      continue;
    }
    buckets.push({
      timestamp,
      sampledAt: new Date(timestamp).toISOString(),
      receiveBytesPerSecond: value.receive / value.count,
      sendBytesPerSecond: value.send / value.count,
      measured: true,
    });
  }

  let previousMeasuredIndex = -1;
  for (let index = 0; index < buckets.length; index++) {
    if (!buckets[index].measured) continue;
    const missingCount = index - previousMeasuredIndex - 1;
    if (
      previousMeasuredIndex >= 0 &&
      missingCount > 0 &&
      missingCount <= maximumCompensatedMissingBuckets
    ) {
      const previous = buckets[previousMeasuredIndex];
      const next = buckets[index];
      for (let offset = 1; offset <= missingCount; offset++) {
        const progress = offset / (missingCount + 1);
        const bucket = buckets[previousMeasuredIndex + offset];
        bucket.receiveBytesPerSecond =
          previous.receiveBytesPerSecond +
          (next.receiveBytesPerSecond - previous.receiveBytesPerSecond) *
            progress;
        bucket.sendBytesPerSecond =
          previous.sendBytesPerSecond +
          (next.sendBytesPerSecond - previous.sendBytesPerSecond) * progress;
      }
    }
    previousMeasuredIndex = index;
  }

  if (previousMeasuredIndex >= 0) {
    const previous = buckets[previousMeasuredIndex];
    const compensatedEnd = Math.min(
      buckets.length - 1,
      previousMeasuredIndex + maximumCompensatedMissingBuckets,
    );
    for (
      let index = previousMeasuredIndex + 1;
      index <= compensatedEnd;
      index++
    ) {
      buckets[index].receiveBytesPerSecond = previous.receiveBytesPerSecond;
      buckets[index].sendBytesPerSecond = previous.sendBytesPerSecond;
    }
  }

  return buckets.map(({ measured: _measured, ...point }) => point);
}

export function smoothTrafficSeries(
  points: TimedTrafficPoint[],
): TimedTrafficPoint[] {
  const weights = [1, 2, 1];
  return points.map((point, index) => {
    let receive = 0;
    let send = 0;
    let totalWeight = 0;
    for (let offset = -1; offset <= 1; offset++) {
      const neighbor = points[index + offset];
      if (!neighbor) continue;
      const weight = weights[offset + 1];
      receive += neighbor.receiveBytesPerSecond * weight;
      send += neighbor.sendBytesPerSecond * weight;
      totalWeight += weight;
    }
    return {
      ...point,
      receiveBytesPerSecond: receive / totalWeight,
      sendBytesPerSecond: send / totalWeight,
    };
  });
}

export function prepareTrafficSeries(
  points: TimedTrafficPoint[],
  start: number,
  end: number,
) {
  return smoothTrafficSeries(resampleTrafficSeries(points, start, end));
}
