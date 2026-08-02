export const runtimeObservationMaxAgeMilliseconds = 15_000;

export function isRuntimeObservationFresh(
  observedAt: number,
  nowMs: number,
  maxAgeMilliseconds = runtimeObservationMaxAgeMilliseconds,
) {
  return (
    Number.isFinite(observedAt) &&
    observedAt > 0 &&
    Number.isFinite(nowMs) &&
    nowMs >= observedAt &&
    nowMs - observedAt <= maxAgeMilliseconds
  );
}
