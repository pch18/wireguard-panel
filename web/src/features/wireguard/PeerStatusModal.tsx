import Modal from "../../ui/Modal";
import TrafficChart from "./TrafficChart";
import type { PeerRuntimeStatus, WireGuardPeer } from "./api";

type Props = {
  peer: WireGuardPeer;
  status?: PeerRuntimeStatus;
  collectorAvailable: boolean;
  message?: string;
  onClose(): void;
};

export function formatBytes(value: number) {
  const units = ["B", "KiB", "MiB", "GiB", "TiB"];
  let result = value;
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

export function formatDuration(value: number) {
  if (value < 60) return `${Math.max(0, Math.floor(value))} 秒`;
  if (value < 3600) return `${Math.floor(value / 60)} 分`;
  if (value < 86400) {
    return `${Math.floor(value / 3600)} 小时 ${Math.floor((value % 3600) / 60)} 分`;
  }
  return `${Math.floor(value / 86400)} 天 ${Math.floor((value % 86400) / 3600)} 小时`;
}

function handshakeText(value?: string) {
  if (!value) return "尚无握手";
  return new Intl.DateTimeFormat("zh-CN", {
    dateStyle: "medium",
    timeStyle: "medium",
  }).format(new Date(value));
}

export default function PeerStatusModal({
  peer,
  status,
  collectorAvailable,
  message,
  onClose,
}: Props) {
  const available = collectorAvailable && status?.available;
  const active = available && status.active;
  return (
    <Modal
      title={`${peer.name} · 运行状态`}
      description="状态来自 wg show all dump；“活跃”表示最近 3 分钟内有握手，并非长连接状态。"
      variant="display"
      onClose={onClose}
      className="is-status"
    >
      <div className="status-modal-body">
        <div className={`runtime-banner ${active ? "is-active" : available ? "is-inactive" : "is-unavailable"}`}>
          <span className="status-dot" />
          <strong>{active ? "活跃" : available ? "不活跃" : "状态不可用"}</strong>
          <span>{message || (active ? `已持续 ${formatDuration(status?.activeDurationSeconds ?? 0)}` : available ? `已持续 ${formatDuration(status?.inactiveDurationSeconds ?? 0)}` : "配置仍可正常编辑")}</span>
        </div>

        <dl className="runtime-metrics">
          <div><dt>当前接收</dt><dd>{formatRate(status?.receiveBytesPerSecond ?? 0)}</dd></div>
          <div><dt>当前发送</dt><dd>{formatRate(status?.sendBytesPerSecond ?? 0)}</dd></div>
          <div><dt>累计接收</dt><dd>{formatBytes(status?.receivedBytes ?? 0)}</dd></div>
          <div><dt>累计发送</dt><dd>{formatBytes(status?.sentBytes ?? 0)}</dd></div>
          <div><dt>最近握手</dt><dd>{handshakeText(status?.lastHandshakeAt)}</dd></div>
          <div><dt>当前 Endpoint</dt><dd>{status?.currentEndpoint || "未观测到"}</dd></div>
        </dl>

        <TrafficChart points={status?.history ?? []} />
        <div className="status-identity">
          <span>稳定 Peer ID</span>
          <code>{peer.id}</code>
        </div>
      </div>
      <footer className="modal-actions">
        <button className="button is-primary" type="button" onClick={onClose}>关闭</button>
      </footer>
    </Modal>
  );
}
