import assert from "node:assert/strict";
import test from "node:test";
import { peerPublicKeyPath } from "../src/features/wireguard/peerPath.ts";

test("Peer PublicKey becomes one URL-safe unpadded path segment", () => {
  assert.equal(
    peerPublicKeyPath("//////////////////////////////////////////8="),
    "__________________________________________8",
  );
  assert.equal(peerPublicKeyPath(" ab+c/de= "), "ab-c_de");
});
