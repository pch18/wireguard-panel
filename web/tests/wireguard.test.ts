import assert from "node:assert/strict";
import test from "node:test";
import {
  digitsOnly,
  interfaceNameOnly,
  linesToValues,
  nextInterfaceName,
  valuesToInline,
  valuesToLines,
} from "../src/features/wireguard/formUtils.ts";
import {
  isWireGuardKey,
  wireGuardKeyOnly,
} from "../src/features/wireguard/keyUtils.ts";

test("WireGuard list fields accept comma and line separated values", () => {
  assert.deepEqual(
    linesToValues("10.0.0.1/24, fd00::1/64\n\n1.1.1.1"),
    ["10.0.0.1/24", "fd00::1/64", "1.1.1.1"],
  );
  assert.equal(valuesToLines(["one", "two"]), "one\ntwo");
  assert.equal(valuesToInline(["one", "two"]), "one, two");
});

test("numeric text fields discard typed and pasted non-digits", () => {
  assert.equal(digitsOnly("51a8-20"), "51820");
  assert.equal(digitsOnly(" port 65535 "), "65535");
  assert.equal(digitsOnly("粘贴45.321x"), "45321");
});

test("Interface names keep only native filename-safe characters", () => {
  assert.equal(interfaceNameOnly(" Tokyo VPN_01.conf "), "TokyoVPN_01conf");
  assert.equal(interfaceNameOnly("东京-wg_123456789012345"), "-wg_12345678901");
});

test("new Interface names use the first available wg index", () => {
  assert.equal(nextInterfaceName([]), "wg0");
  assert.equal(nextInterfaceName(["wg0"]), "wg1");
  assert.equal(nextInterfaceName(["wg0", "wg1", "wg3"]), "wg2");
  assert.equal(nextInterfaceName(["WG0", "wg00"]), "wg0");
});

test("WireGuard key validation accepts only canonical 32-byte Base64 keys", () => {
  assert.equal(
    isWireGuardKey("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="),
    true,
  );
  assert.equal(isWireGuardKey("short"), false);
  assert.equal(
    isWireGuardKey("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
    false,
  );
  assert.equal(
    isWireGuardKey("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB="),
    false,
  );
});

test("WireGuard key fields discard typed and pasted whitespace", () => {
  assert.equal(wireGuardKeyOnly("abc def"), "abcdef");
  assert.equal(wireGuardKeyOnly(" abc\tdef\n "), "abcdef");
});
