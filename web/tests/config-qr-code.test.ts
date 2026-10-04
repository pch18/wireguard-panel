import assert from "node:assert/strict";
import test from "node:test";
import jsQR from "jsqr";
import { createConfigQRCode } from "../src/features/wireguard/configQRCode.ts";

// 用独立解码器验收 SVG 路径实际承载的内容，而不是拿编码器自己的结果互相比较。
function decodeConfig(text: string) {
  const qr = createConfigQRCode(text);
  const scale = 4;
  const width = qr.size * scale;
  const pixels = new Uint8ClampedArray(width * width * 4).fill(255);
  for (const match of qr.path.matchAll(/M(\d+) (\d+)h1v1h-1z/g)) {
    const column = Number(match[1]);
    const row = Number(match[2]);
    // 四模块静区内不能有任何黑点，否则在边缘复杂的页面上容易无法扫码。
    assert.ok(column >= 4 && column < qr.size - 4);
    assert.ok(row >= 4 && row < qr.size - 4);
    for (let y = row * scale; y < (row + 1) * scale; y += 1) {
      for (let x = column * scale; x < (column + 1) * scale; x += 1) {
        const offset = (y * width + x) * 4;
        pixels[offset] = pixels[offset + 1] = pixels[offset + 2] = 0;
      }
    }
  }
  const decoded = jsQR(pixels, width, width);
  assert.ok(decoded, "生成的路径必须可被独立扫码器识别");
  return decoded.data;
}

test("二维码保留配置的中文、空格、空行和尾部换行", () => {
  const text =
    "\n[Interface]\n# 中文客户端 🚀\nAddress = 10.42.0.2/32\n\n[Peer]\nEndpoint = vpn.example.com:51820\n# 尾部空格  \n";
  assert.equal(decodeConfig(text), text);
});

test("每次生成使用最新草稿，不复用之前的二维码", () => {
  const original = "[Peer]\nEndpoint = original.example.com:51820\n";
  const edited = original.replace(
    "original.example.com:51820",
    "edited.example.com:60000",
  );
  assert.equal(decodeConfig(original), original);
  assert.equal(decodeConfig(edited), edited);
  assert.notEqual(
    createConfigQRCode(original).path,
    createConfigQRCode(edited).path,
  );
});

test("空内容和超过容量的配置不能生成残缺二维码", () => {
  for (const text of ["", "   \n\t", "x".repeat(5000)]) {
    assert.throws(() => createConfigQRCode(text));
  }
});
