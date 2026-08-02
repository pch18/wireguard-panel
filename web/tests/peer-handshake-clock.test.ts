import assert from "node:assert/strict";
import test from "node:test";
import { formatPeerHandshakeElapsed } from "../src/features/wireguard/peerHandshakeClock.ts";

test("Peer handshake clock keeps non-zero day and hour fields", () => {
  const handshakeAt = "2026-08-01T00:00:00.000Z";
  const now = Date.parse("2026-08-02T02:03:04.900Z");
  assert.equal(formatPeerHandshakeElapsed(handshakeAt, now), "1d 02:03:04");
});

test("Peer handshake clock advances each second and never becomes negative", () => {
  const handshakeAt = "2026-08-01T00:00:10.000Z";
  assert.equal(
    formatPeerHandshakeElapsed(handshakeAt, Date.parse("2026-08-01T00:00:00.000Z")),
    "00:00",
  );
  assert.equal(
    formatPeerHandshakeElapsed(handshakeAt, Date.parse("2026-08-01T00:00:11.000Z")),
    "00:01",
  );
});

test("Peer handshake clock omits zero days and hours but always keeps minutes", () => {
  const handshakeAt = "2026-08-01T00:00:00.000Z";
  assert.equal(
    formatPeerHandshakeElapsed(
      handshakeAt,
      Date.parse("2026-08-01T02:00:04.000Z"),
    ),
    "02:00:04",
  );
  assert.equal(
    formatPeerHandshakeElapsed(
      handshakeAt,
      Date.parse("2026-08-02T00:03:04.000Z"),
    ),
    "1d 03:04",
  );
  assert.equal(
    formatPeerHandshakeElapsed(
      handshakeAt,
      Date.parse("2026-08-01T00:00:04.000Z"),
    ),
    "00:04",
  );
});

test("Peer handshake clock handles missing and invalid server timestamps", () => {
  assert.equal(formatPeerHandshakeElapsed(undefined, Date.now()), "未握手");
  assert.equal(formatPeerHandshakeElapsed("invalid", Date.now()), "未握手");
});
