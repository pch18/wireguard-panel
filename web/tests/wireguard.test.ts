import assert from "node:assert/strict";
import test from "node:test";
import {
  linesToValues,
  valuesToLines,
} from "../src/features/wireguard/formUtils.ts";

test("WireGuard list fields accept comma and line separated values", () => {
  assert.deepEqual(
    linesToValues("10.0.0.1/24, fd00::1/64\n\n1.1.1.1"),
    ["10.0.0.1/24", "fd00::1/64", "1.1.1.1"],
  );
  assert.equal(valuesToLines(["one", "two"]), "one\ntwo");
});
