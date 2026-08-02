export type PeerTrafficSample = {
  sampledAt: number;
  receivedBytes: number;
  sentBytes: number;
};

export type PeerWindowedRate = {
  receiveBytesPerSecond: number;
  sendBytesPerSecond: number;
};

export type PeerRateWindowResult = PeerWindowedRate & {
  samples: PeerTrafficSample[];
};

const defaultWindowMilliseconds = 10_000;
const defaultBufferMilliseconds = 2_500;

export function updatePeerRateWindow(
  previous: PeerTrafficSample[],
  current: PeerTrafficSample,
  fallback: PeerWindowedRate,
  windowMilliseconds = defaultWindowMilliseconds,
  bufferMilliseconds = defaultBufferMilliseconds,
): PeerRateWindowResult {
  if (!Number.isFinite(current.sampledAt)) {
    return { ...fallback, samples: previous };
  }

  let samples = previous.filter(
    (sample) =>
      sample.sampledAt <= current.sampledAt &&
      current.sampledAt - sample.sampledAt <=
        windowMilliseconds + bufferMilliseconds,
  );
  const last = samples.at(-1);
  if (last?.sampledAt === current.sampledAt) {
    samples = [...samples.slice(0, -1), current];
  } else {
    samples = [...samples, current];
  }

  const target = current.sampledAt - windowMilliseconds;
  let comparison = samples[0];
  for (const sample of samples) {
    if (sample.sampledAt > target) break;
    comparison = sample;
  }
  if (!comparison || comparison.sampledAt === current.sampledAt) {
    return { ...fallback, samples };
  }
  if (
    current.receivedBytes < comparison.receivedBytes ||
    current.sentBytes < comparison.sentBytes
  ) {
    return { ...fallback, samples: [current] };
  }

  const elapsedSeconds = (current.sampledAt - comparison.sampledAt) / 1_000;
  if (elapsedSeconds <= 0) return { ...fallback, samples };
  return {
    receiveBytesPerSecond:
      (current.receivedBytes - comparison.receivedBytes) / elapsedSeconds,
    sendBytesPerSecond:
      (current.sentBytes - comparison.sentBytes) / elapsedSeconds,
    samples,
  };
}
