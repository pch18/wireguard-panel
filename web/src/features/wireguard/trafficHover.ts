export function nearestTrafficPoint<T extends { timestamp: number }>(
  points: T[],
  targetTimestamp: number,
) {
  let nearest: T | undefined;
  let nearestDistance = Number.POSITIVE_INFINITY;
  for (const point of points) {
    const distance = Math.abs(point.timestamp - targetTimestamp);
    if (distance < nearestDistance) {
      nearest = point;
      nearestDistance = distance;
    }
  }
  return nearest;
}
