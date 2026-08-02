import assert from "node:assert/strict";
import test from "node:test";
import { validatePasswordChange } from "../src/features/auth/passwordValidation.ts";

test("password change accepts a matching strong password", () => {
  assert.equal(
    validatePasswordChange("admin5555", "NewPassword888", "NewPassword888"),
    "",
  );
});

test("password change rejects weak, unchanged, and mismatched passwords", () => {
  assert.match(validatePasswordChange("admin5555", "short", "short"), /8/);
  assert.match(
    validatePasswordChange("admin5555", "admin5555", "admin5555"),
    /相同/,
  );
  assert.match(
    validatePasswordChange("admin5555", "NewPassword888", "NewPassword889"),
    /不一致/,
  );
  const oversized = "密".repeat(25);
  assert.match(validatePasswordChange("admin5555", oversized, oversized), /72/);
});
