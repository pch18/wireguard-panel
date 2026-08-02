import assert from "node:assert/strict";
import test from "node:test";
import { updatePeerRateWindow } from "../src/features/wireguard/peerRateWindow.ts";

test("Peer rate window averages cumulative traffic over roughly ten seconds", () => {
  let samples = [];
  let result = updatePeerRateWindow(
    samples,
    { sampledAt: 0, receivedBytes: 0, sentBytes: 0 },
    { receiveBytesPerSecond: 0, sendBytesPerSecond: 0 },
  );
  samples = result.samples;
  for (let second = 2; second <= 10; second += 2) {
    result = updatePeerRateWindow(
      samples,
      {
        sampledAt: second * 1_000,
        receivedBytes: second * 1_000,
        sentBytes: second * 500,
      },
      { receiveBytesPerSecond: 0, sendBytesPerSecond: 0 },
    );
    samples = result.samples;
  }
  assert.equal(result.receiveBytesPerSecond, 1_000);
  assert.equal(result.sendBytesPerSecond, 500);
});

test("one zero interval does not immediately erase the recent rate", () => {
  let samples = [
    { sampledAt: 0, receivedBytes: 0, sentBytes: 0 },
    { sampledAt: 5_000, receivedBytes: 5_000, sentBytes: 2_500 },
  ];
  const result = updatePeerRateWindow(
    samples,
    { sampledAt: 10_000, receivedBytes: 5_000, sentBytes: 2_500 },
    { receiveBytesPerSecond: 0, sendBytesPerSecond: 0 },
  );
  assert.equal(result.receiveBytesPerSecond, 500);
  assert.equal(result.sendBytesPerSecond, 250);
});

test("counter reset starts a new rate window", () => {
  const result = updatePeerRateWindow(
    [{ sampledAt: 0, receivedBytes: 10_000, sentBytes: 5_000 }],
    { sampledAt: 10_000, receivedBytes: 100, sentBytes: 50 },
    { receiveBytesPerSecond: 12, sendBytesPerSecond: 6 },
  );
  assert.deepEqual(result.samples, [
    { sampledAt: 10_000, receivedBytes: 100, sentBytes: 50 },
  ]);
  assert.equal(result.receiveBytesPerSecond, 12);
  assert.equal(result.sendBytesPerSecond, 6);
});
