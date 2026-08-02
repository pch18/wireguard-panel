export function wireGuardConfigFilename(value: string) {
  const stem = value
    .trim()
    .replace(/\.conf$/i, "")
    .replace(/[<>:"/\\|?*\u0000-\u001f]/g, "-")
    .replace(/[.\s]+$/g, "")
    .slice(0, 120);
  return `${stem || "wireguard"}.conf`;
}

export function downloadWireGuardConfig(text: string, requestedName: string) {
  const blob = new Blob([text], { type: "text/plain;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = wireGuardConfigFilename(requestedName);
  anchor.hidden = true;
  document.body.append(anchor);
  try {
    anchor.click();
  } finally {
    anchor.remove();
    window.setTimeout(() => URL.revokeObjectURL(url), 0);
  }
}
