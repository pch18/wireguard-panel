import assert from "node:assert/strict";
import test from "node:test";
import { nearestTrafficPoint } from "../src/features/wireguard/trafficHover.ts";

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
