import assert from "node:assert/strict";
import test from "node:test";
import { sortPeerEntriesByFirstAllowedIP } from "../src/features/wireguard/peerDisplayOrder.ts";

type Peer = { name: string; allowedIPs: string[] };

function names(peers: Peer[]) {
  return sortPeerEntriesByFirstAllowedIP(peers).map(({ peer }) => peer.name);
}

test("Peers without AllowedIPs appear before configured Peers", () => {
  assert.deepEqual(
    names([
      { name: "configured", allowedIPs: ["10.0.0.2/32"] },
      { name: "missing", allowedIPs: [] },
      { name: "blank", allowedIPs: ["  "] },
    ]),
    ["missing", "blank", "configured"],
  );
});

test("Peers are sorted numerically by their first Allowed IP", () => {
  assert.deepEqual(
    names([
      { name: "ten", allowedIPs: ["10.0.0.10/32", "1.1.1.1/32"] },
      { name: "two", allowedIPs: ["10.0.0.2/32"] },
      { name: "v6", allowedIPs: ["2001:db8::2/128"] },
      { name: "one", allowedIPs: ["10.0.0.1/32"] },
    ]),
    ["one", "two", "ten", "v6"],
  );
});

test("equal first Allowed IPs preserve their configuration order", () => {
  const peers = [
    { name: "first", allowedIPs: ["10.0.0.1/32"] },
    { name: "second", allowedIPs: ["10.0.0.1/32"] },
  ];
  assert.deepEqual(names(peers), ["first", "second"]);
  assert.deepEqual(
    sortPeerEntriesByFirstAllowedIP(peers).map(({ originalIndex }) => originalIndex),
    [0, 1],
  );
});
