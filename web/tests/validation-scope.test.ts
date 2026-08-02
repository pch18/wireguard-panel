import assert from "node:assert/strict";
import test from "node:test";
import { scopeValidationErrors } from "../src/features/wireguard/validationScope.ts";

test("advisory route-range messages are not treated as validation errors", () => {
  const scoped = scopeValidationErrors(
    [
      'WireGuard 配置冲突: Peer "123" 的 AllowedIPs 26.2.0.0/16 不属于 Interface 客户端路由范围',
      "PrivateKey 不能为空",
    ],
    [{ name: "123", allowedIPs: ["26.2.0.0/16"] }],
  );

  assert.deepEqual(scoped.interfaceErrors, ["PrivateKey 不能为空"]);
  assert.deepEqual(scoped.peerErrors, [[]]);
});

test("indexed Peer validation messages use their exact Peer card", () => {
  const scoped = scopeValidationErrors(
    ["Peer 2（second）：WireGuard 配置无效: PublicKey 不能为空"],
    [
      { name: "first", allowedIPs: [] },
      { name: "second", allowedIPs: [] },
    ],
  );

  assert.deepEqual(scoped.interfaceErrors, []);
  assert.deepEqual(scoped.peerErrors, [[], ["PublicKey 不能为空"]]);
});

test("every legacy route-range warning is ignored", () => {
  const scoped = scopeValidationErrors(
    [
      'WireGuard 配置冲突: Peer "first" 的 AllowedIPs 192.0.2.1/32 不属于 Interface 客户端路由范围',
      'WireGuard 配置冲突: Peer "second" 的 AllowedIPs 198.51.100.2/32 不属于 Interface 客户端路由范围',
    ],
    [
      { name: "first", allowedIPs: ["192.0.2.1/32"] },
      { name: "second", allowedIPs: ["198.51.100.2/32"] },
    ],
  );

  assert.deepEqual(scoped.interfaceErrors, []);
  assert.deepEqual(scoped.peerErrors, [[], []]);
});
