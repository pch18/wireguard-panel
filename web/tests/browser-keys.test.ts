import assert from "node:assert/strict";
import test from "node:test";
import {
  deriveWireGuardPublicKey,
  generateWireGuardKeyPair,
  generateWireGuardPresharedKey,
} from "../src/features/wireguard/browserKeys.ts";
import { isWireGuardKey } from "../src/features/wireguard/keyUtils.ts";

function hexToBase64(value: string) {
  return btoa(
    String.fromCharCode(
      ...value.match(/.{2}/g)!.map((byte) => Number.parseInt(byte, 16)),
    ),
  );
}

test("browser X25519 derivation matches the RFC 7748 vector", async () => {
  const privateKey = hexToBase64(
    "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
  );
  const expectedPublicKey = hexToBase64(
    "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
  );
  assert.equal(await deriveWireGuardPublicKey(privateKey), expectedPublicKey);
});

test("browser creates complete WireGuard key material without an API", async () => {
  const pair = await generateWireGuardKeyPair();
  assert.equal(isWireGuardKey(pair.privateKey), true);
  assert.equal(isWireGuardKey(pair.publicKey), true);
  assert.equal(await deriveWireGuardPublicKey(pair.privateKey), pair.publicKey);
  assert.equal(isWireGuardKey(generateWireGuardPresharedKey()), true);
});
