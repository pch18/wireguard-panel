import assert from "node:assert/strict";
import test from "node:test";
import {
  nearestTrafficPoint,
  trafficPlotPosition,
  trafficPointAtTimestamp,
  trafficTimestampAtPosition,
  trafficTooltipPosition,
} from "../src/features/wireguard/trafficHover.ts";
import { trafficSampleIntervalMilliseconds } from "../src/features/wireguard/trafficSeries.ts";

const points = [
  { timestamp: 1_000, value: "first" },
  { timestamp: 4_000, value: "second" },
  { timestamp: 9_000, value: "third" },
];

test("traffic hover selects the nearest real sample", () => {
  assert.equal(nearestTrafficPoint(points, 3_100)?.value, "second");
  assert.equal(nearestTrafficPoint(points, 7_200)?.value, "third");
});

test("traffic hover clamps naturally to the first and last samples", () => {
  assert.equal(nearestTrafficPoint(points, -10_000)?.value, "first");
  assert.equal(nearestTrafficPoint(points, 20_000)?.value, "third");
  assert.equal(nearestTrafficPoint([], 5_000), undefined);
});

test("traffic hover uses the same inset coordinate system as the plotted line", () => {
  const start = 1_000;
  const end = 11_000;
  const width = 640;
  const inset = 12;
  const timestamp = 8_500;
  const position = trafficPlotPosition(timestamp, start, end, width, inset);

  assert.equal(position, (inset + 0.75 * (width - inset * 2)) / width);
  assert.equal(
    trafficTimestampAtPosition(position, start, end, width, inset),
    timestamp,
  );
  assert.equal(trafficTimestampAtPosition(0, start, end, width, inset), start);
  assert.equal(trafficTimestampAtPosition(1, start, end, width, inset), end);
});

test("traffic hover reports zero at the pointer time inside a sample gap", () => {
  const traffic = [
    {
      timestamp: 1_000,
      sampledAt: new Date(1_000).toISOString(),
      receiveBytesPerSecond: 20,
      sendBytesPerSecond: 10,
    },
    {
      timestamp: 20_000,
      sampledAt: new Date(20_000).toISOString(),
      receiveBytesPerSecond: 40,
      sendBytesPerSecond: 30,
    },
  ];

  const maximumDistance = trafficSampleIntervalMilliseconds / 2;
  assert.equal(
    trafficPointAtTimestamp(traffic, 2_000, maximumDistance),
    traffic[0],
  );
  assert.deepEqual(trafficPointAtTimestamp(traffic, 10_000, maximumDistance), {
    timestamp: 10_000,
    sampledAt: new Date(10_000).toISOString(),
    receiveBytesPerSecond: 0,
    sendBytesPerSecond: 0,
  });
});

test("traffic tooltip is placed outside the chart bounds", () => {
  const bounds = { top: 100, right: 400, bottom: 220, left: 100 };

  assert.deepEqual(trafficTooltipPosition(bounds, 160, 800, 600), {
    left: 408,
    top: 128,
  });
  assert.deepEqual(
    trafficTooltipPosition(
      { top: 100, right: 450, bottom: 220, left: 250 },
      160,
      500,
      600,
    ),
    {
      left: 66,
      top: 128,
    },
  );
  assert.deepEqual(
    trafficTooltipPosition(
      { top: 100, right: 290, bottom: 220, left: 10 },
      160,
      300,
      600,
    ),
    { left: 62, top: 28 },
  );
});
