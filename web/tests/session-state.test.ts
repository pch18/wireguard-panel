import assert from "node:assert/strict";
import test from "node:test";
import {
  isAnonymousSessionError,
  sessionLoadErrorMessage,
} from "../src/features/auth/sessionState.ts";

test("only an explicit 401 is treated as an anonymous session", () => {
  assert.equal(
    isAnonymousSessionError(Object.assign(new Error("expired"), { status: 401 })),
    true,
  );
  assert.equal(
    isAnonymousSessionError(
      Object.assign(new Error("unavailable"), { status: 503 }),
    ),
    false,
  );
  assert.equal(isAnonymousSessionError(new TypeError("Failed to fetch")), false);
});

test("session loading keeps backend errors and normalizes network failures", () => {
  assert.equal(
    sessionLoadErrorMessage(
      Object.assign(new Error("登录服务暂时不可用"), { status: 503 }),
    ),
    "登录服务暂时不可用",
  );
  assert.equal(
    sessionLoadErrorMessage(new TypeError("Failed to fetch")),
    "暂时无法连接后端，请检查服务状态后重试",
  );
});
