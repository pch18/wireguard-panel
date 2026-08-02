function pad(value: number) {
  return String(value).padStart(2, "0");
}

export function formatPeerHandshakeElapsed(
  lastHandshakeAt: string | undefined,
  nowMs: number,
) {
  if (!lastHandshakeAt) return "未握手";
  const handshakeMs = Date.parse(lastHandshakeAt);
  if (!Number.isFinite(handshakeMs)) return "未握手";

  const elapsedSeconds = Math.max(0, Math.floor((nowMs - handshakeMs) / 1_000));
  const days = Math.floor(elapsedSeconds / 86_400);
  const hours = Math.floor((elapsedSeconds % 86_400) / 3_600);
  const minutes = Math.floor((elapsedSeconds % 3_600) / 60);
  const seconds = elapsedSeconds % 60;
  const dayPart = days > 0 ? `${days}d ` : "";
  const clockPart = hours > 0
    ? `${pad(hours)}:${pad(minutes)}:${pad(seconds)}`
    : `${pad(minutes)}:${pad(seconds)}`;
  return dayPart + clockPart;
}
