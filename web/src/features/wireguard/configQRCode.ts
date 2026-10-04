import QRCode from "qrcode";

// 只在用户点击时编码当前草稿；不规范化换行或裁剪空格，确保扫码内容与
// 复制、下载完全一致。四模块白边必须保留，避免扫描器把弹窗边框当作码点。
export function createConfigQRCode(text: string) {
  if (!text.trim()) throw new Error("请先填写配置内容");
  const { modules } = QRCode.create(
    [{ data: new TextEncoder().encode(text), mode: "byte" }],
    {
      errorCorrectionLevel: "M",
    },
  );
  const margin = 4;
  const paths: string[] = [];
  for (let row = 0; row < modules.size; row += 1) {
    for (let column = 0; column < modules.size; column += 1) {
      if (modules.get(row, column)) {
        paths.push(`M${column + margin} ${row + margin}h1v1h-1z`);
      }
    }
  }
  return { size: modules.size + margin * 2, path: paths.join("") };
}
