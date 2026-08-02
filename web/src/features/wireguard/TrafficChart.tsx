import { useState, type PointerEvent } from "react";
import type { TrafficPoint } from "./api";
import { nearestTrafficPoint } from "./trafficHover";

type Props = {
  points: TrafficPoint[];
  nowMs: number;
  compact?: boolean;
  windowMinutes?: number;
  currentRateAvailable?: boolean;
};

const width = 640;
const overviewHeight = 150;
const compactHeight = 72;
const sampleGapMilliseconds = 7_500;

type ParsedPoint = TrafficPoint & { timestamp: number };

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

function linePath(
  points: ParsedPoint[],
  select: (point: ParsedPoint) => number,
  start: number,
  end: number,
  ceiling: number,
  height: number,
  inset: number,
) {
  return points
    .map((point, index) => {
      const x =
        inset +
        ((point.timestamp - start) / Math.max(1, end - start)) *
          (width - inset * 2);
      const y =
        height -
        inset -
        (select(point) / ceiling) * (height - inset * 2);
      const previous = points[index - 1];
      const command =
        !previous || point.timestamp - previous.timestamp > sampleGapMilliseconds
          ? "M"
          : "L";
      return `${command} ${x.toFixed(1)} ${y.toFixed(1)}`;
    })
    .join(" ");
}

export default function TrafficChart({
  points,
  nowMs,
  compact = false,
  windowMinutes = 30,
  currentRateAvailable = true,
}: Props) {
  const [hoveredTimestamp, setHoveredTimestamp] = useState<number | null>(null);
  const windowMilliseconds = windowMinutes * 60_000;
  const start = nowMs - windowMilliseconds;
  const parsed = points
    .map((point) => ({ ...point, timestamp: Date.parse(point.sampledAt) }))
    .filter(
      (point) =>
        Number.isFinite(point.timestamp) &&
        point.timestamp >= start &&
        point.timestamp <= nowMs + sampleGapMilliseconds,
    );
  const height = compact ? compactHeight : overviewHeight;
  const inset = compact ? 5 : 12;
  const ceiling = Math.max(
    1,
    ...parsed.flatMap((point) => [
      point.receiveBytesPerSecond,
      point.sendBytesPerSecond,
    ]),
  );
  const receivePath = linePath(
    parsed,
    (point) => point.receiveBytesPerSecond,
    start,
    nowMs,
    ceiling,
    height,
    inset,
  );
  const sendPath = linePath(
    parsed,
    (point) => point.sendBytesPerSecond,
    start,
    nowMs,
    ceiling,
    height,
    inset,
  );
  const latest = parsed.at(-1);
  const receiveRate =
    latest && currentRateAvailable
      ? formatRate(latest.receiveBytesPerSecond)
      : "—";
  const sendRate =
    latest && currentRateAvailable ? formatRate(latest.sendBytesPerSecond) : "—";
  const hoveredPoint =
    hoveredTimestamp === null
      ? undefined
      : parsed.find((point) => point.timestamp === hoveredTimestamp);
  const hoveredPosition = hoveredPoint
    ? Math.max(
        0,
        Math.min(
          100,
          ((hoveredPoint.timestamp - start) / windowMilliseconds) * 100,
        ),
      )
    : 0;
  const tooltipAlignment =
    hoveredPosition < 24
      ? "is-start"
      : hoveredPosition > 76
        ? "is-end"
        : "is-center";

  const handlePointerMove = (event: PointerEvent<HTMLDivElement>) => {
    if (parsed.length === 0) return;
    const bounds = event.currentTarget.getBoundingClientRect();
    if (bounds.width <= 0) return;
    const position = Math.max(
      0,
      Math.min(1, (event.clientX - bounds.left) / bounds.width),
    );
    const nearest = nearestTrafficPoint(
      parsed,
      start + position * windowMilliseconds,
    );
    setHoveredTimestamp(nearest?.timestamp ?? null);
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
      <div
        className="traffic-chart-canvas"
        onPointerMove={handlePointerMove}
        onPointerLeave={() => setHoveredTimestamp(null)}
      >
        {parsed.length === 0 && (
          <span className="traffic-chart-empty">等待流量样本</span>
        )}
        <svg
          viewBox={`0 0 ${width} ${height}`}
          role="img"
          aria-label={`近 ${windowMinutes} 分钟接收与发送速度折线图`}
          preserveAspectRatio="none"
        >
          {!compact &&
            [0, 1, 2, 3].map((line) => {
              const y = inset + (line / 3) * (height - inset * 2);
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
          <>
            <span
              className="traffic-chart-crosshair"
              style={{ left: `${hoveredPosition}%` }}
              aria-hidden="true"
            />
            <div
              className={`traffic-chart-tooltip ${tooltipAlignment}`}
              style={{ left: `${hoveredPosition}%` }}
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
            </div>
          </>
        )}
      </div>
      {!compact && (
        <div className="traffic-chart-axis">
          <span>{windowMinutes} 分钟前</span>
          <span>现在</span>
        </div>
      )}
    </div>
  );
}
