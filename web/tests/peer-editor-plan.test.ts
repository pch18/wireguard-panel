import assert from "node:assert/strict";
import test from "node:test";
import type {
  IPPlan,
  WireGuardInterface,
} from "../src/features/wireguard/api.ts";
import { peerEditorPlan } from "../src/features/wireguard/peerEditorPlan.ts";

const config: WireGuardInterface = {
  id: "wg0",
  filename: "wg0.conf",
  revision: "current",
  privateKey: "private",
  address: ["10.20.30.1/24", "fd20::1/64"],
  dns: [],
  clientEndpoint: "",
  clientAllowedIPs: ["10.0.0.1/8", "fd00::1/8"],
  peers: [
    {
      name: "Peer 1",
      privateKey: "",
      publicKey: "public",
      presharedKey: "",
      allowedIPs: ["10.20.30.7/32"],
      endpoint: "",
    },
  ],
};

test("peer editor derives constraints from the current config while IP plan is unavailable", () => {
  assert.deepEqual(peerEditorPlan(config), {
    allowedRanges: ["10.0.0.0/8", "fd00::/8"],
    reservedAddresses: ["10.20.30.1/32", "fd20::1/128"],
    assignments: [
      {
        allowedIP: "10.20.30.7/32",
        peerPublicKey: "public",
        peerName: "Peer 1",
      },
    ],
  });
});

test("peer editor ignores an IP plan from a different config revision", () => {
  const stale = {
    revision: "stale",
    allowedRanges: ["192.0.2.0/24"],
    reservedAddresses: [],
    assignments: [],
  } as IPPlan;
  assert.deepEqual(peerEditorPlan(config, stale).allowedRanges, [
    "10.0.0.0/8",
    "fd00::/8",
  ]);
});
