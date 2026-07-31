import type { TrafficPoint } from "./api";

type TrafficChartProps = {
  points: TrafficPoint[];
};

const width = 720;
const height = 210;
const inset = 20;

function pathFor(
  points: TrafficPoint[],
  select: (point: TrafficPoint) => number,
  ceiling: number,
) {
  if (points.length === 0) return "";
  return points
    .map((point, index) => {
      const x =
        inset + (index / Math.max(1, points.length - 1)) * (width - inset * 2);
      const y =
        height - inset - (select(point) / ceiling) * (height - inset * 2);
      return `${index === 0 ? "M" : "L"} ${x.toFixed(1)} ${y.toFixed(1)}`;
    })
    .join(" ");
}

export default function TrafficChart({ points }: TrafficChartProps) {
  const ceiling = Math.max(
    1,
    ...points.flatMap((point) => [point.receivedBytes, point.sentBytes]),
  );
  const receivePath = pathFor(points, (point) => point.receivedBytes, ceiling);
  const sendPath = pathFor(points, (point) => point.sentBytes, ceiling);

  return (
    <div className="traffic-chart">
      <div className="traffic-chart-legend">
        <span className="is-receive">接收</span>
        <span className="is-send">发送</span>
        <small>每分钟流量 · 最近 1 小时</small>
      </div>
      <svg
        viewBox={`0 0 ${width} ${height}`}
        role="img"
        aria-label="最近一小时接收与发送流量图"
        preserveAspectRatio="none"
      >
        {[0, 1, 2, 3, 4].map((line) => {
          const y = inset + (line / 4) * (height - inset * 2);
          return <line className="chart-grid" key={line} x1={inset} x2={width - inset} y1={y} y2={y} />;
        })}
        <path className="chart-line is-receive" d={receivePath} />
        <path className="chart-line is-send" d={sendPath} />
      </svg>
      <div className="traffic-chart-axis">
        <span>60 分钟前</span>
        <span>现在</span>
      </div>
    </div>
  );
}
