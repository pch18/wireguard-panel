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

export type HoverTrafficPoint = {
  timestamp: number;
  sampledAt: string;
  receiveBytesPerSecond: number;
  sendBytesPerSecond: number;
};

function clamp(value: number, minimum: number, maximum: number) {
  return Math.max(minimum, Math.min(maximum, value));
}

export function trafficPlotPosition(
  timestamp: number,
  start: number,
  end: number,
  width: number,
  inset: number,
) {
  const plotWidth = Math.max(1, width - inset * 2);
  const progress = clamp(
    (timestamp - start) / Math.max(1, end - start),
    0,
    1,
  );
  return (inset + progress * plotWidth) / width;
}

export function trafficTimestampAtPosition(
  pointerPosition: number,
  start: number,
  end: number,
  width: number,
  inset: number,
) {
  const plotWidth = Math.max(1, width - inset * 2);
  const pointerX = clamp(pointerPosition, 0, 1) * width;
  const progress = clamp((pointerX - inset) / plotWidth, 0, 1);
  return start + progress * Math.max(1, end - start);
}

export function trafficPointAtTimestamp<T extends HoverTrafficPoint>(
  points: T[],
  targetTimestamp: number,
  maximumSampleDistance: number,
): T | HoverTrafficPoint {
  const nearest = nearestTrafficPoint(points, targetTimestamp);
  if (
    nearest &&
    Math.abs(nearest.timestamp - targetTimestamp) <= maximumSampleDistance
  ) {
    return nearest;
  }
  return {
    timestamp: targetTimestamp,
    sampledAt: new Date(targetTimestamp).toISOString(),
    receiveBytesPerSecond: 0,
    sendBytesPerSecond: 0,
  };
}

type TooltipAnchorBounds = {
  top: number;
  right: number;
  bottom: number;
  left: number;
};

export function trafficTooltipPosition(
  bounds: TooltipAnchorBounds,
  pointerY: number,
  viewportWidth: number,
  viewportHeight: number,
  tooltipWidth = 176,
  tooltipHeight = 64,
  gap = 8,
) {
  const maximumLeft = Math.max(gap, viewportWidth - tooltipWidth - gap);
  const maximumTop = Math.max(gap, viewportHeight - tooltipHeight - gap);
  const centeredTop = clamp(
    pointerY - tooltipHeight / 2,
    gap,
    maximumTop,
  );
  if (viewportWidth - bounds.right >= tooltipWidth + gap) {
    return { left: bounds.right + gap, top: centeredTop };
  }
  if (bounds.left >= tooltipWidth + gap) {
    return { left: bounds.left - tooltipWidth - gap, top: centeredTop };
  }

  const centeredLeft = clamp(
    (bounds.left + bounds.right - tooltipWidth) / 2,
    gap,
    maximumLeft,
  );
  if (bounds.top >= tooltipHeight + gap) {
    return { left: centeredLeft, top: bounds.top - tooltipHeight - gap };
  }
  return {
    left: centeredLeft,
    top: Math.min(bounds.bottom + gap, maximumTop),
  };
}
