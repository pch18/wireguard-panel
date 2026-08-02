import assert from "node:assert/strict";
import test from "node:test";
import {
  interfaceMatchesInput,
  peerMatchesInput,
} from "../src/features/wireguard/reconciliation.ts";
import type {
  InterfaceInput,
  PeerInput,
  WireGuardInterface,
  WireGuardPeer,
} from "../src/features/wireguard/api.ts";

const interfaceInput: InterfaceInput = {
  privateKey: "private-key",
  address: ["10.0.0.1/24"],
  listenPort: 51820,
  dns: ["1.1.1.1", "8.8.8.8"],
  mtu: 1420,
  clientEndpoint: "vpn.example.com:51820",
  clientAllowedIPs: ["10.0.0.0/8"],
};

const config: WireGuardInterface = {
  id: "wg0",
  filename: "wg0.conf",
  revision: "revision",
  peers: [],
  validationErrors: [],
  ...interfaceInput,
};

test("reconciliation recognizes a normalized Interface mutation", () => {
  assert.equal(
    interfaceMatchesInput(config, {
      ...interfaceInput,
      privateKey: " private-key ",
      dns: ["1.1.1.1, 8.8.8.8", "1.1.1.1"],
      clientEndpoint: " vpn.example.com:51820 ",
    }),
    true,
  );
  assert.equal(
    interfaceMatchesInput(config, { ...interfaceInput, mtu: 1380 }),
    false,
  );
});

const peerInput: PeerInput = {
  name: "Peer 1",
  privateKey: "private-key",
  publicKey: "public-key",
  presharedKey: "preshared-key",
  allowedIPs: ["10.0.0.2/32"],
  endpoint: "peer.example.com:51820",
  persistentKeepalive: 25,
};

const peer: WireGuardPeer = { ...peerInput };

test("reconciliation recognizes a normalized Peer mutation", () => {
  assert.equal(
    peerMatchesInput(peer, {
      ...peerInput,
      name: " Peer 1 ",
      allowedIPs: ["10.0.0.2/32, 10.0.0.2/32"],
      endpoint: " peer.example.com:51820 ",
    }),
    true,
  );
  assert.equal(
    peerMatchesInput(peer, { ...peerInput, allowedIPs: ["10.0.0.3/32"] }),
    false,
  );
});
