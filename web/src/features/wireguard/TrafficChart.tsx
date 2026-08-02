import { useState, type PointerEvent } from "react";
import { createPortal } from "react-dom";
import type { TrafficPoint } from "./api";
import {
  trafficPlotPosition,
  trafficPointAtTimestamp,
  trafficTimestampAtPosition,
  trafficTooltipPosition,
} from "./trafficHover";
import {
  prepareTrafficSeries,
  trafficGapToleranceMilliseconds,
  trafficSampleIntervalMilliseconds,
} from "./trafficSeries";

type Props = {
  points: TrafficPoint[];
  nowMs: number;
  compact?: boolean;
  showHorizontalAxis?: boolean;
  windowMinutes?: number;
  currentRateAvailable?: boolean;
};

const width = 640;
const overviewHeight = 150;
const compactHeight = 72;

type ParsedPoint = TrafficPoint & { timestamp: number };
type TooltipPosition = { left: number; top: number };

export function formatBytes(value: number) {
  const units = ["B", "KiB", "MiB", "GiB", "TiB"];
  let result = Math.max(0, value);
  let unit = 0;
  while (result >= 1024 && unit < units.length - 1) {
    result /= 1024;
    unit++;
  }
  return `${result >= 10 || unit === 0 ? result.toFixed(0) : result.toFixed(1)} ${units[unit]}`;
}

export function formatRate(value: number) {
  return `${formatBytes(value)}/s`;
}

function formatCompactAxisRate(value: number) {
  const units = ["B/s", "K/s", "M/s", "G/s", "T/s"];
  let result = Math.max(0, value);
  let unit = 0;
  while (result >= 1024 && unit < units.length - 1) {
    result /= 1024;
    unit++;
  }
  if (result === 0) return "0";
  return `${result >= 10 || unit === 0 ? result.toFixed(0) : result.toFixed(1)}${units[unit]}`;
}

function linePath(
  points: ParsedPoint[],
  select: (point: ParsedPoint) => number,
  start: number,
  end: number,
  ceiling: number,
  height: number,
  inset: number,
) {
  const x = (timestamp: number) =>
    trafficPlotPosition(timestamp, start, end, width, inset) * width;
  const y = (value: number) =>
    height - inset - (value / ceiling) * (height - inset * 2);
  const zeroY = y(0).toFixed(1);
  if (points.length === 0) {
    return `M ${x(start).toFixed(1)} ${zeroY} L ${x(end).toFixed(1)} ${zeroY}`;
  }

  const commands: string[] = [];
  const first = points[0];
  if (first.timestamp > start) {
    if (first.timestamp - start > trafficGapToleranceMilliseconds) {
      commands.push(
        `M ${x(start).toFixed(1)} ${zeroY}`,
        `L ${x(first.timestamp - 1).toFixed(1)} ${zeroY}`,
      );
    } else {
      commands.push(`M ${x(start).toFixed(1)} ${y(select(first)).toFixed(1)}`);
    }
  }
  commands.push(
    `${commands.length === 0 ? "M" : "L"} ${x(first.timestamp).toFixed(1)} ${y(select(first)).toFixed(1)}`,
  );

  for (let index = 1; index < points.length; index++) {
    const previous = points[index - 1];
    const point = points[index];
    if (
      point.timestamp - previous.timestamp >
      trafficGapToleranceMilliseconds
    ) {
      commands.push(
        `L ${x(previous.timestamp + 1).toFixed(1)} ${zeroY}`,
        `L ${x(point.timestamp - 1).toFixed(1)} ${zeroY}`,
      );
    }
    commands.push(
      `L ${x(point.timestamp).toFixed(1)} ${y(select(point)).toFixed(1)}`,
    );
  }

  const last = points.at(-1)!;
  if (end - last.timestamp > trafficGapToleranceMilliseconds) {
    commands.push(
      `L ${x(last.timestamp + 1).toFixed(1)} ${zeroY}`,
      `L ${x(end).toFixed(1)} ${zeroY}`,
    );
  } else if (last.timestamp < end) {
    commands.push(
      `L ${x(end).toFixed(1)} ${y(select(last)).toFixed(1)}`,
    );
  }
  return commands.join(" ");
}

export default function TrafficChart({
  points,
  nowMs,
  compact = false,
  showHorizontalAxis = !compact,
  windowMinutes = 30,
  currentRateAvailable = true,
}: Props) {
  const [hoveredPoint, setHoveredPoint] = useState<ParsedPoint | null>(null);
  const [tooltipPosition, setTooltipPosition] =
    useState<TooltipPosition | null>(null);
  const windowMilliseconds = windowMinutes * 60_000;
  const start = nowMs - windowMilliseconds;
  const parsed = points
    .map((point) => ({ ...point, timestamp: Date.parse(point.sampledAt) }))
    .filter(
      (point) =>
        Number.isFinite(point.timestamp) &&
        point.timestamp >= start &&
        point.timestamp <= nowMs + trafficSampleIntervalMilliseconds,
    );
  const displayPoints = prepareTrafficSeries(parsed, start, nowMs);
  const height = compact ? compactHeight : overviewHeight;
  const inset = compact ? 8 : 12;
  const axisTickCount = compact ? 3 : 4;
  const ceiling = Math.max(
    1,
    ...displayPoints.flatMap((point) => [
      point.receiveBytesPerSecond,
      point.sendBytesPerSecond,
    ]),
  );
  const receivePath = linePath(
    displayPoints,
    (point) => point.receiveBytesPerSecond,
    start,
    nowMs,
    ceiling,
    height,
    inset,
  );
  const sendPath = linePath(
    displayPoints,
    (point) => point.sendBytesPerSecond,
    start,
    nowMs,
    ceiling,
    height,
    inset,
  );
  const latest = trafficPointAtTimestamp(
    displayPoints,
    nowMs,
    trafficGapToleranceMilliseconds,
  );
  const receiveRate = currentRateAvailable
    ? formatRate(latest.receiveBytesPerSecond)
    : "—";
  const sendRate =
    currentRateAvailable ? formatRate(latest.sendBytesPerSecond) : "—";
  const hoveredPosition = hoveredPoint
    ? trafficPlotPosition(
        hoveredPoint.timestamp,
        start,
        nowMs,
        width,
        inset,
      ) * 100
    : 0;
  const axisTicks = Array.from({ length: axisTickCount }, (_, index) => {
    const progress = index / (axisTickCount - 1);
    const value = ceiling * (1 - progress);
    return {
      label: compact ? formatCompactAxisRate(value) : formatRate(value),
      top: ((inset + progress * (height - inset * 2)) / height) * 100,
    };
  });

  const handlePointerMove = (event: PointerEvent<HTMLDivElement>) => {
    const bounds = event.currentTarget.getBoundingClientRect();
    if (bounds.width <= 0) return;
    const position = Math.max(
      0,
      Math.min(1, (event.clientX - bounds.left) / bounds.width),
    );
    const targetTimestamp = trafficTimestampAtPosition(
      position,
      start,
      nowMs,
      width,
      inset,
    );
    setHoveredPoint(
      trafficPointAtTimestamp(
        displayPoints,
        targetTimestamp,
        trafficSampleIntervalMilliseconds / 2,
      ),
    );
    const chartBounds =
      event.currentTarget
        .closest(".peer-card, .modal.is-traffic, .traffic-chart")
        ?.getBoundingClientRect() ??
      bounds;
    setTooltipPosition(
      trafficTooltipPosition(
        chartBounds,
        event.clientY,
        window.innerWidth,
        window.innerHeight,
      ),
    );
  };

  return (
    <div className={`traffic-chart ${compact ? "is-compact" : ""}`.trim()}>
      <div className="traffic-chart-legend">
        <span className="is-receive">
          接收{compact ? "" : ` ${receiveRate}`}
        </span>
        <span className="is-send">
          发送{compact ? "" : ` ${sendRate}`}
        </span>
        <small>近 {windowMinutes} 分钟</small>
      </div>
      <div className="traffic-chart-plot">
        <div className="traffic-chart-y-axis" aria-hidden="true">
          {axisTicks.map((tick, index) => (
            <span key={index} style={{ top: `${tick.top}%` }}>
              {tick.label}
            </span>
          ))}
        </div>
        <div
          className="traffic-chart-canvas"
          onPointerMove={handlePointerMove}
          onPointerLeave={() => {
            setHoveredPoint(null);
            setTooltipPosition(null);
          }}
        >
          {parsed.length === 0 && !currentRateAvailable && (
            <span className="traffic-chart-empty">流量数据暂不可用</span>
          )}
          <svg
            viewBox={`0 0 ${width} ${height}`}
            role="img"
            aria-label={`近 ${windowMinutes} 分钟接收与发送速度折线图`}
            preserveAspectRatio="none"
          >
            {axisTicks.map((_, line) => {
              const y =
                inset +
                (line / (axisTickCount - 1)) * (height - inset * 2);
              return (
                <line
                  className="chart-grid"
                  key={line}
                  x1={inset}
                  x2={width - inset}
                  y1={y}
                  y2={y}
                />
              );
            })}
            <path className="chart-line is-receive" d={receivePath} />
            <path className="chart-line is-send" d={sendPath} />
          </svg>
          {hoveredPoint && (
            <span
              className="traffic-chart-crosshair"
              style={{ left: `${hoveredPosition}%` }}
              aria-hidden="true"
            />
          )}
        </div>
      </div>
      {showHorizontalAxis && (
        <div className="traffic-chart-axis">
          <span>{windowMinutes} 分钟前</span>
          <span>现在</span>
        </div>
      )}
      {hoveredPoint &&
        tooltipPosition &&
        createPortal(
          <div
            className="traffic-chart-tooltip is-detached"
            style={tooltipPosition}
          >
            <time dateTime={hoveredPoint.sampledAt}>
              {new Intl.DateTimeFormat("zh-CN", {
                hour: "2-digit",
                minute: "2-digit",
                second: "2-digit",
                hour12: false,
              }).format(hoveredPoint.timestamp)}
            </time>
            <span className="is-receive">
              接收 {formatRate(hoveredPoint.receiveBytesPerSecond)}
            </span>
            <span className="is-send">
              发送 {formatRate(hoveredPoint.sendBytesPerSecond)}
            </span>
          </div>,
          document.body,
        )}
    </div>
  );
}
