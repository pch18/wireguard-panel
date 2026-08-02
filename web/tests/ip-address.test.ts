import assert from "node:assert/strict";
import test from "node:test";
import {
  addressRowFromCIDR,
  addressRowToCIDR,
  availablePrefixes,
  availableIPFamilies,
  blankAddressRow,
  cidrContainedByAny,
  cidrValueContainedByAny,
  cidrOverlaps,
  formatIPv6,
  interfaceAddressContainedByAny,
  normalizeAddressRow,
  parseCIDR,
  parseCIDRs,
  parseIPAddress,
  selectableSegmentOptions,
  segmentOptions,
  validateAddressCIDR,
} from "../src/features/wireguard/ipAddress.ts";

test("CIDR parser canonicalizes IPv4 and compressed IPv6", () => {
  assert.equal(parseCIDR("10.20.31.99/20")?.canonical, "10.20.16.0/20");
  assert.equal(parseCIDR("2001:0db8:0:0:0:ff00:42:8329/64")?.canonical, "2001:db8::/64");
  assert.equal(parseCIDR("::ffff:192.0.2.128/120")?.canonical, "::ffff:c000:200/120");
  assert.equal(formatIPv6(0n), "::");
  assert.equal(parseCIDR("2001:::1/64"), null);
  assert.equal(parseCIDR("10.0.0.1/33"), null);
});

test("IP parser preserves Interface host bits", () => {
  assert.equal(parseIPAddress("10.20.31.99")?.canonical, "10.20.31.99");
  assert.equal(
    parseIPAddress("2001:0db8:0:0:0:ff00:42:8329")?.canonical,
    "2001:db8::ff00:42:8329",
  );
  assert.equal(parseIPAddress("10.20.31.99", 6), null);
});

test("IPv4 selector requires the mask and defaults each segment to its first option", () => {
  const blank = blankAddressRow("row");
  assert.equal(segmentOptions(blank, 0, [], []).length, 0);
  const normalized = normalizeAddressRow({ ...blank, prefix: 24 }, [], []);
  assert.deepEqual(normalized.segments, [0, 0, 0, 0]);
  assert.equal(addressRowToCIDR(normalized), "0.0.0.0/24");
});

test("range constraints auto-select singleton octets and honor partial masks", () => {
  const allowed = parseCIDRs(["10.20.16.0/20"]);
  let row = normalizeAddressRow(
    { ...blankAddressRow("row"), prefix: 24 },
    allowed,
    [],
  );
  assert.deepEqual(row.segments, [10, 20, 16, 0]);
  const third = segmentOptions(row, 2, allowed, []);
  assert.deepEqual(
    third.filter((option) => !option.disabled).map((option) => option.value),
    Array.from({ length: 16 }, (_, index) => 16 + index),
  );

  row = normalizeAddressRow(
    { ...blankAddressRow("partial"), prefix: 21 },
    allowed,
    [],
  );
  assert.deepEqual(row.segments, [10, 20, 16, 0]);
  assert.deepEqual(
    segmentOptions(row, 2, allowed, []).map((option) => option.value),
    [0, 8, 16, 24, 32, 40, 48, 56, 64, 72, 80, 88, 96, 104, 112, 120, 128, 136, 144, 152, 160, 168, 176, 184, 192, 200, 208, 216, 224, 232, 240, 248],
  );
  assert.deepEqual(
    segmentOptions(row, 2, allowed, [])
      .filter((option) => !option.disabled)
      .map((option) => option.value),
    [16, 24],
  );
});

test("occupied prefixes do not remove in-range selector choices", () => {
  const allowed = parseCIDRs(["10.0.0.0/8"]);
  const occupied = parseCIDRs(["10.20.0.0/16"]);
  const row = normalizeAddressRow(
    { ...blankAddressRow("row"), prefix: 16 },
    allowed,
    occupied,
  );
  assert.equal(row.segments[0], 10);
  const options = segmentOptions(row, 1, allowed, occupied);
  assert.equal(options.find((option) => option.value === 20)?.disabled, false);
  assert.equal(options.find((option) => option.value === 21)?.disabled, false);
});

test("changed options retain a legal value and replace an illegal value with the first option", () => {
  const allowed = parseCIDRs(["10.20.7.0/24", "11.30.9.0/24"]);
  const original = normalizeAddressRow(
    {
      ...blankAddressRow("row"),
      prefix: 24,
      segments: [10, 20, 7, 0],
    },
    allowed,
    [],
  );
  assert.deepEqual(original.segments, [10, 20, 7, 0]);

  const changed = normalizeAddressRow(
    { ...original, segments: [11, 20, 7, 0] },
    allowed,
    [],
  );
  assert.deepEqual(changed.segments, [11, 30, 9, 0]);
});

test("an existing out-of-range segment is not offered as a selectable option", () => {
  const allowed = parseCIDRs(["10.20.0.0/24"]);
  const row = addressRowFromCIDR("legacy", "192.0.2.7/32");
  assert.ok(row);

  const visible = selectableSegmentOptions(
    segmentOptions(row!, 0, allowed, []),
  );
  assert.deepEqual(
    visible.map((option) => option.value),
    [10],
  );
});

test("IPv6 uses nibble segments while producing compressed canonical output", () => {
  const allowed = parseCIDRs(["fd12:3456:7800::/40"]);
  const row = normalizeAddressRow(
    { ...blankAddressRow("v6", 6), prefix: 64 },
    allowed,
    [],
  );
  assert.deepEqual(row.segments.slice(0, 10), [15, 13, 1, 2, 3, 4, 5, 6, 7, 8]);
  assert.equal(row.segments[10], 0);
  const parsed = addressRowFromCIDR("existing", "fd12:3456:789a::/64");
  assert.ok(parsed);
  assert.equal(addressRowToCIDR(parsed!), "fd12:3456:789a::/64");
});

test("containment and overlap compare entire prefixes", () => {
  const parent = parseCIDR("10.0.0.0/8")!;
  const child = parseCIDR("10.10.0.0/16")!;
  const outside = parseCIDR("11.0.0.0/8")!;
  assert.equal(cidrContainedByAny(child, [parent]), true);
  assert.equal(cidrContainedByAny(parent, [child]), false);
  assert.equal(cidrOverlaps(parent, child), true);
  assert.equal(cidrOverlaps(child, outside), false);
});

test("Interface addresses and Peer prefixes use their matching constraint semantics", () => {
  const ranges = parseCIDRs(["10.0.0.0/8"]);
  assert.equal(interfaceAddressContainedByAny("10.20.30.40/24", ranges), true);
  assert.equal(interfaceAddressContainedByAny("192.0.2.1/24", ranges), false);
  assert.equal(cidrValueContainedByAny("10.20.0.0/16", ranges), true);
  assert.equal(cidrValueContainedByAny("10.0.0.0/7", ranges), false);
});

test("a configured route range rejects an unconfigured address family", () => {
  const ipv4Only = parseCIDRs(["10.0.0.0/8"]);
  const row = normalizeAddressRow(
    { ...blankAddressRow("v6", 6), prefix: 128 },
    ipv4Only,
    [],
  );
  assert.equal(
    segmentOptions(row, 0, ipv4Only, []).some((option) => !option.disabled),
    false,
  );
  assert.equal(
    cidrContainedByAny(parseCIDR("fd00::1/128")!, ipv4Only),
    false,
  );
});

test("route ranges expose only their configured address families", () => {
  assert.deepEqual(availableIPFamilies(parseCIDRs(["10.0.0.0/8"])), [4]);
  assert.deepEqual(availableIPFamilies(parseCIDRs(["fd00::/8"])), [6]);
  assert.deepEqual(
    availableIPFamilies(parseCIDRs(["10.0.0.0/8", "fd00::/8"])),
    [4, 6],
  );
  assert.deepEqual(availableIPFamilies([]), [4, 6]);
});

test("prefix selectors expose only masks with a legal available subnet", () => {
  const allowed = parseCIDRs(["10.0.0.0/8"]);
  assert.deepEqual(
    availablePrefixes(4, allowed, []),
    Array.from({ length: 25 }, (_, index) => index + 8),
  );
  assert.deepEqual(
    availablePrefixes(4, allowed, parseCIDRs(["10.0.0.0/8"])),
    Array.from({ length: 25 }, (_, index) => index + 8),
  );
});

test("missing route ranges allow any valid address family", () => {
  assert.deepEqual(
    validateAddressCIDR("192.0.2.7", 32, 4, [], []),
    { cidr: "192.0.2.7/32", error: "" },
  );
  assert.deepEqual(
    validateAddressCIDR("fd00::7", 128, 6, [], []),
    { cidr: "fd00::7/128", error: "" },
  );
});

test("manually entered IPv6 addresses are canonicalized and validated", () => {
  const allowed = parseCIDRs(["fd12:3456::/48"]);
  const occupied = parseCIDRs(["fd12:3456:0:2::99/128"]);

  assert.deepEqual(
    validateAddressCIDR("fd12:3456:0:1::27", 128, 6, allowed, occupied),
    { cidr: "fd12:3456:0:1::27/128", error: "" },
  );
  assert.equal(
    validateAddressCIDR("fd12:::27", 128, 6, allowed, occupied).error,
    "IPv6 地址格式无效",
  );
  assert.equal(
    validateAddressCIDR("fd12:3456:0:2::99", 128, 6, allowed, occupied).error,
    "地址与 Interface 或其他 Peer 重复",
  );
  assert.equal(
    validateAddressCIDR("fd99::1", 128, 6, allowed, occupied).error,
    "地址超出路由范围约束",
  );
});

test("only exact occupied CIDRs are rejected", () => {
  const occupied = parseCIDRs(["10.20.0.0/16"]);
  assert.deepEqual(
    validateAddressCIDR("10.20.1.0", 24, 4, [], occupied),
    { cidr: "10.20.1.0/24", error: "" },
  );
  assert.equal(
    validateAddressCIDR("10.20.0.0", 16, 4, [], occupied).error,
    "地址与 Interface 或其他 Peer 重复",
  );
});
