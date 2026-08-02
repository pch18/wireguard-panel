import assert from "node:assert/strict";
import test from "node:test";
import {
  resampleTrafficSeries,
  smoothTrafficSeries,
  trafficSampleIntervalMilliseconds,
} from "../src/features/wireguard/trafficSeries.ts";

const point = (timestamp: number, receive: number, send = receive) => ({
  timestamp,
  sampledAt: new Date(timestamp).toISOString(),
  receiveBytesPerSecond: receive,
  sendBytesPerSecond: send,
});

test("traffic samples use fixed five-second buckets", () => {
  const result = resampleTrafficSeries(
    [point(1_200, 10), point(6_300, 20)],
    0,
    5_000,
  );

  assert.equal(trafficSampleIntervalMilliseconds, 5_000);
  assert.deepEqual(
    result.map((item) => [item.timestamp, item.receiveBytesPerSecond]),
    [
      [0, 10],
      [5_000, 20],
    ],
  );
});

test("a short trailing delay holds the latest bucket without hiding an outage", () => {
  const result = resampleTrafficSeries([point(0, 10)], 0, 15_000);

  assert.deepEqual(
    result.map((item) => item.receiveBytesPerSecond),
    [10, 10, 10, 0],
  );
});

test("short sampling gaps are interpolated while long gaps remain zero", () => {
  const shortGap = resampleTrafficSeries(
    [point(0, 0), point(15_000, 30)],
    0,
    15_000,
  );
  assert.deepEqual(
    shortGap.map((item) => item.receiveBytesPerSecond),
    [0, 10, 20, 30],
  );

  const longGap = resampleTrafficSeries(
    [point(0, 10), point(20_000, 50)],
    0,
    20_000,
  );
  assert.deepEqual(
    longGap.map((item) => item.receiveBytesPerSecond),
    [10, 0, 0, 0, 50],
  );
});

test("three-bucket weighted smoothing reduces isolated sawtooth spikes", () => {
  const result = smoothTrafficSeries([
    point(0, 0),
    point(5_000, 0),
    point(10_000, 100),
    point(15_000, 0),
    point(20_000, 0),
  ]);

  assert.deepEqual(
    result.map((item) => item.receiveBytesPerSecond),
    [0, 25, 50, 25, 0],
  );
});
