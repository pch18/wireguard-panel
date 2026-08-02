import assert from "node:assert/strict";
import test from "node:test";
import {
  analyzeInterfaceChange,
  analyzePeerChange,
  interfaceInputAffectsRuntime,
  peerDeletionNeedsRestart,
  peerInputAffectsRuntime,
} from "../src/features/wireguard/runtimeDiff.ts";

const interfaceConfig = {
  id: "wg0",
  filename: "wg0.conf",
  revision: "revision",
  privateKey: "private",
  address: ["10.0.0.1/24"],
  listenPort: 51820,
  dns: ["1.1.1.1"],
  mtu: 1420,
  clientEndpoint: "old.example.com:51820",
  clientAllowedIPs: ["10.0.0.0/8"],
  peers: [],
};

test("client export settings do not affect the running Interface", () => {
  assert.equal(
    interfaceInputAffectsRuntime(interfaceConfig, {
      ...interfaceConfig,
      clientEndpoint: "new.example.com:51820",
      clientAllowedIPs: ["192.0.2.0/24"],
    }),
    false,
  );
  assert.equal(
    interfaceInputAffectsRuntime(interfaceConfig, {
      ...interfaceConfig,
      listenPort: 51821,
    }),
    true,
  );
});

test("Peer display metadata does not affect its running configuration", () => {
  const peer = {
    name: "before",
    privateKey: "private",
    publicKey: "public",
    presharedKey: "preshared",
    allowedIPs: ["10.0.0.2/32"],
    endpoint: "peer.example.com:51820",
    persistentKeepalive: 25,
  };
  assert.equal(
    peerInputAffectsRuntime(peer, {
      ...peer,
      name: "after",
      privateKey: "new-private",
    }),
    false,
  );
  assert.equal(
    peerInputAffectsRuntime(peer, {
      ...peer,
      allowedIPs: ["10.0.0.3/32"],
    }),
    true,
  );
});

test("Interface impact distinguishes hot updates from required restart", () => {
  const privateKey = analyzeInterfaceChange(interfaceConfig, {
    ...interfaceConfig,
    privateKey: "rotated",
  });
  assert.equal(privateKey.mode, "hot");
  assert.equal(privateKey.requiresConfirmation, false);
  assert.match(privateKey.changes[0] ?? "", /所有客户端/);

  const automaticPort = analyzeInterfaceChange(interfaceConfig, {
    ...interfaceConfig,
    listenPort: undefined,
  });
  assert.equal(automaticPort.mode, "hot");

  const explicitPort = analyzeInterfaceChange(
    { ...interfaceConfig, listenPort: undefined },
    { ...interfaceConfig, listenPort: 51820 },
  );
  assert.equal(explicitPort.mode, "hot");

  const dns = analyzeInterfaceChange(interfaceConfig, {
    ...interfaceConfig,
    dns: ["8.8.8.8"],
  });
  assert.equal(dns.mode, "restart");
  assert.equal(dns.requiresConfirmation, true);

  const fixedMTU = analyzeInterfaceChange(interfaceConfig, {
    ...interfaceConfig,
    mtu: 1380,
  });
  assert.equal(fixedMTU.mode, "hot");

  const automaticMTU = analyzeInterfaceChange(interfaceConfig, {
    ...interfaceConfig,
    mtu: undefined,
  });
  assert.equal(automaticMTU.mode, "restart");

  const fromAutomaticMTU = analyzeInterfaceChange(
    { ...interfaceConfig, mtu: undefined },
    { ...interfaceConfig, mtu: 1380 },
  );
  assert.equal(fromAutomaticMTU.mode, "hot");
});

test("default route changes require Interface restart", () => {
  const nextPeer = {
    name: "exit",
    privateKey: "",
    publicKey: "public",
    presharedKey: "",
    allowedIPs: ["0.0.0.0/0"],
    endpoint: "",
    persistentKeepalive: undefined,
  };
  const impact = analyzePeerChange(interfaceConfig, undefined, nextPeer);
  assert.equal(impact.mode, "restart");
  assert.equal(impact.requiresConfirmation, true);
  const withExit = { ...interfaceConfig, peers: [nextPeer] };
  assert.equal(peerDeletionNeedsRestart(withExit, nextPeer.publicKey), true);
});
