import assert from "node:assert/strict";
import test from "node:test";
import { isRuntimeObservationFresh } from "../src/features/wireguard/runtimeFreshness.ts";

test("runtime observations expire instead of presenting stale state as current", () => {
  assert.equal(isRuntimeObservationFresh(10_000, 24_999), true);
  assert.equal(isRuntimeObservationFresh(10_000, 25_001), false);
  assert.equal(isRuntimeObservationFresh(0, 10_000), false);
  assert.equal(isRuntimeObservationFresh(11_000, 10_000), false);
});
