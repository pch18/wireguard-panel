import assert from "node:assert/strict";
import test from "node:test";
import { safeDestination } from "../src/app/navigation.ts";

test("safeDestination keeps an internal route", () => {
  assert.equal(
    safeDestination({
      from: {
        pathname: "/workspace",
        search: "?page=2",
        hash: "#list",
      },
    }),
    "/workspace?page=2#list",
  );
});

test("safeDestination rejects external and missing routes", () => {
  assert.equal(safeDestination({ from: { pathname: "//example.com" } }), "/");
  assert.equal(safeDestination({ from: { pathname: "https://example.com" } }), "/");
  assert.equal(safeDestination(null), "/");
});
