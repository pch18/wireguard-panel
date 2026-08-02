import assert from "node:assert/strict";
import test from "node:test";
import {
  mergePeerTraffic,
  mergeTrafficPoints,
} from "../src/features/wireguard/trafficHistory.ts";

test("traffic history merges duplicate samples and retains the latest hour", () => {
  const start = Date.parse("2026-08-01T00:00:00Z");
  const point = (minutes: number, receive: number, send = receive) => ({
    sampledAt: new Date(start + minutes * 60_000).toISOString(),
    receiveBytesPerSecond: receive,
    sendBytesPerSecond: send,
  });
  const merged = mergeTrafficPoints(
    [point(0, 1), point(30, 2), point(60, 3)],
    [point(60, 30), point(61, 4)],
  );
  assert.deepEqual(merged, [point(30, 2), point(60, 30), point(61, 4)]);
});

test("traffic history ignores invalid samples and clamps negative rates", () => {
  const merged = mergeTrafficPoints([], [
    {
      sampledAt: "2026-08-01T00:00:00Z",
      receiveBytesPerSecond: -1,
      sendBytesPerSecond: -2,
    },
    {
      sampledAt: "invalid",
      receiveBytesPerSecond: 10,
      sendBytesPerSecond: 20,
    },
  ]);
  assert.equal(merged.length, 1);
  assert.equal(merged[0].receiveBytesPerSecond, 0);
  assert.equal(merged[0].sendBytesPerSecond, 0);
});

test("empty traffic history tolerates null values from older servers", () => {
  assert.deepEqual(mergeTrafficPoints(undefined, null), []);
  const merged = mergePeerTraffic(
    new Map(),
    { "new-peer": null },
    true,
  );
  assert.deepEqual(merged.get("new-peer"), []);
  assert.equal(mergePeerTraffic(merged, null).get("new-peer")?.length, 0);
});
