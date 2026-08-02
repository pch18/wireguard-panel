import assert from "node:assert/strict";
import test from "node:test";
import {
  mergeRuntimeState,
  mergeRuntimeTraffic,
} from "../src/features/wireguard/runtimeEvents.ts";

const current = {
  interfaceID: "wg0",
  interfaceName: "wg0",
  configurationRevision: "revision-1",
  runtimeControllable: true,
  runtimeStateAvailable: true,
  running: true,
  collectorAvailable: true,
  sampledAt: "2026-08-03T00:00:00Z",
  peers: [
    {
      publicKey: "peer-1",
      available: true,
      active: false,
      currentEndpoint: "",
      receivedBytes: 100,
      sentBytes: 200,
      receiveBytesPerSecond: 10,
      sendBytesPerSecond: 20,
      activeDurationSeconds: 0,
      inactiveDurationSeconds: 30,
    },
  ],
};

test("status events update state without erasing the latest traffic sample", () => {
  const merged = mergeRuntimeState(current, {
    interfaceID: "wg0",
    interfaceName: "wg0",
    configurationRevision: "revision-1",
    runtimeControllable: true,
    runtimeStateAvailable: true,
    running: true,
    collectorAvailable: true,
    sampledAt: "2026-08-03T00:00:01Z",
    peers: [
      {
        publicKey: "peer-1",
        available: true,
        active: true,
        currentEndpoint: "198.51.100.20:51820",
        lastHandshakeAt: "2026-08-03T00:00:01Z",
        activeDurationSeconds: 0,
        inactiveDurationSeconds: 0,
      },
    ],
  });

  assert.equal(merged.peers[0].active, true);
  assert.equal(merged.peers[0].currentEndpoint, "198.51.100.20:51820");
  assert.equal(merged.peers[0].receivedBytes, 100);
  assert.equal(merged.peers[0].receiveBytesPerSecond, 10);
});

test("traffic events update counters without erasing peer state", () => {
  const merged = mergeRuntimeTraffic(current, {
    kind: "update",
    interfaceID: "wg0",
    interfaceName: "wg0",
    configurationRevision: "revision-1",
    sampledAt: "2026-08-03T00:00:05Z",
    peers: [
      {
        publicKey: "peer-1",
        receivedBytes: 600,
        sentBytes: 1200,
        receiveBytesPerSecond: 100,
        sendBytesPerSecond: 200,
      },
    ],
    interfaceTraffic: [],
    peerTraffic: {},
  });

  assert.equal(merged.peers[0].active, false);
  assert.equal(merged.peers[0].inactiveDurationSeconds, 30);
  assert.equal(merged.peers[0].receivedBytes, 600);
  assert.equal(merged.peers[0].receiveBytesPerSecond, 100);
});
