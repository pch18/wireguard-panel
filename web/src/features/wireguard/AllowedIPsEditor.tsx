import {
  useEffect,
  useId,
  useLayoutEffect,
  useMemo,
  useRef,
  useState,
  type KeyboardEvent as ReactKeyboardEvent,
} from "react";
import { createPortal } from "react-dom";
import Icon from "../../ui/Icon";
import type { IPAssignment } from "./api";
import {
  addressRowToCIDR,
  availablePrefixes,
  availableIPFamilies,
  cidrValueContainedByAny,
  formatAddress,
  interfaceAddressContainedByAny,
  normalizeAddressRow,
  parseCIDR,
  parseCIDRs,
  parseIPAddress,
  selectableSegmentOptions,
  segmentBits,
  segmentOptions,
  validateAddressCIDR,
  type AddressRow,
  type IPFamily,
  type ParsedCIDR,
  type SegmentOption,
} from "./ipAddress";

type AllowedIPsEditorProps = {
  mode?: "peer" | "interface";
  initialValues: string[];
  showBlankRowWhenEmpty?: boolean;
  allowedRanges?: string[];
  reservedAddresses?: string[];
  assignments?: IPAssignment[];
  currentPeerPublicKey?: string;
  onChange(values: string[], complete: boolean): void;
};

type EditorRow = {
  id: string;
  family: IPFamily;
  prefix: number | null;
  ipv4Segments: Array<number | null>;
  ipv6Address: string;
};

type RowResult = {
  cidr: string | null;
  error: string;
};

type IPv4SegmentPickerProps = {
  value: number | null;
  options: SegmentOption[];
  disabled: boolean;
  label: string;
  invalid: boolean;
  onChange(value: number): void;
};

const EMPTY_VALUES: string[] = [];
const EMPTY_ASSIGNMENTS: IPAssignment[] = [];
const ALL_IPV4_OPTIONS: SegmentOption[] = Array.from(
  { length: 256 },
  (_, value) => ({ value, disabled: false }),
);

function valueIsOutsideConstraint(
  value: string,
  allowedRanges: ParsedCIDR[],
  isInterface: boolean,
) {
  return !(
    isInterface
      ? interfaceAddressContainedByAny(value, allowedRanges)
      : cidrValueContainedByAny(value, allowedRanges)
  );
}

function interfaceIPv4SegmentOptions(
  row: EditorRow,
  index: number,
  allowedRanges: ParsedCIDR[],
): SegmentOption[] {
  if (row.prefix === null) return [];
  if (allowedRanges.length === 0) return ALL_IPV4_OPTIONS;
  if (row.ipv4Segments.slice(0, index).some((value) => value === null)) {
    return [];
  }
  return ALL_IPV4_OPTIONS.map((option) => {
    let low = 0n;
    let high = 0n;
    for (let cursor = 0; cursor < 4; cursor += 1) {
      const fixed =
        cursor < index
          ? row.ipv4Segments[cursor]
          : cursor === index
            ? option.value
            : null;
      low = (low << 8n) | BigInt(fixed ?? 0);
      high = (high << 8n) | BigInt(fixed ?? 255);
    }
    const inRange = allowedRanges.some(
      (range) =>
        range.family === 4 && range.network <= high && range.end >= low,
    );
    return {
      value: option.value,
      disabled: !inRange,
      reason: inRange ? undefined : ("range" as const),
    };
  });
}

function IPv4SegmentPicker({
  value,
  options,
  disabled,
  label,
  invalid,
  onChange,
}: IPv4SegmentPickerProps) {
  const panelID = useId();
  const rootRef = useRef<HTMLSpanElement>(null);
  const triggerRef = useRef<HTMLButtonElement>(null);
  const panelRef = useRef<HTMLDivElement>(null);
  const [open, setOpen] = useState(false);
  const [panelPosition, setPanelPosition] = useState({
    top: 0,
    left: 0,
    width: 320,
  });
  const enabledOptions = options.filter((option) => !option.disabled);

  useLayoutEffect(() => {
    if (!open) return;

    const updatePosition = () => {
      const trigger = triggerRef.current;
      const panel = panelRef.current;
      if (!trigger || !panel) return;
      const padding = 12;
      const gap = 6;
      const triggerRect = trigger.getBoundingClientRect();
      const width = Math.min(320, window.innerWidth - padding * 2);
      const left = Math.min(
        Math.max(
          triggerRect.left + triggerRect.width / 2 - width / 2,
          padding,
        ),
        window.innerWidth - width - padding,
      );
      const panelHeight = panel.offsetHeight;
      const fitsBelow =
        triggerRect.bottom + gap + panelHeight <= window.innerHeight - padding;
      const top = fitsBelow
        ? triggerRect.bottom + gap
        : Math.max(padding, triggerRect.top - panelHeight - gap);
      setPanelPosition({ top, left, width });
    };

    updatePosition();
    const frame = window.requestAnimationFrame(updatePosition);
    window.addEventListener("resize", updatePosition);
    document.addEventListener("scroll", updatePosition, true);
    return () => {
      window.cancelAnimationFrame(frame);
      window.removeEventListener("resize", updatePosition);
      document.removeEventListener("scroll", updatePosition, true);
    };
  }, [open, options.length]);

  useEffect(() => {
    if (!open) return;

    const focusOption = () => {
      const selected = panelRef.current?.querySelector<HTMLButtonElement>(
        `[data-value="${value ?? ""}"]:not(:disabled)`,
      );
      const first = panelRef.current?.querySelector<HTMLButtonElement>(
        ".ipv4-segment-picker-option:not(:disabled)",
      );
      (selected ?? first)?.focus();
    };
    const frame = window.requestAnimationFrame(focusOption);

    const isInsidePicker = (target: EventTarget | null) =>
      target instanceof Node &&
      (rootRef.current?.contains(target) || panelRef.current?.contains(target));
    const closeOutside = (event: PointerEvent) => {
      if (!isInsidePicker(event.target)) setOpen(false);
    };
    const closeOnFocusOutside = (event: FocusEvent) => {
      if (!isInsidePicker(event.target)) setOpen(false);
    };
    const closeOnEscape = (event: KeyboardEvent) => {
      if (event.key !== "Escape") return;
      event.preventDefault();
      event.stopPropagation();
      setOpen(false);
      triggerRef.current?.focus();
    };

    document.addEventListener("pointerdown", closeOutside, true);
    document.addEventListener("focusin", closeOnFocusOutside);
    document.addEventListener("keydown", closeOnEscape, true);
    return () => {
      window.cancelAnimationFrame(frame);
      document.removeEventListener("pointerdown", closeOutside, true);
      document.removeEventListener("focusin", closeOnFocusOutside);
      document.removeEventListener("keydown", closeOnEscape, true);
    };
  }, [open, value]);

  const moveOptionFocus = (
    event: ReactKeyboardEvent<HTMLButtonElement>,
    optionValue: number,
  ) => {
    const currentIndex = enabledOptions.findIndex(
      (option) => option.value === optionValue,
    );
    if (currentIndex < 0) return;
    let nextIndex = currentIndex;
    if (event.key === "ArrowRight") nextIndex += 1;
    else if (event.key === "ArrowLeft") nextIndex -= 1;
    else if (event.key === "ArrowDown") nextIndex += 8;
    else if (event.key === "ArrowUp") nextIndex -= 8;
    else if (event.key === "Home") nextIndex = 0;
    else if (event.key === "End") nextIndex = enabledOptions.length - 1;
    else return;
    event.preventDefault();
    const next =
      enabledOptions[
        Math.min(Math.max(nextIndex, 0), enabledOptions.length - 1)
      ];
    panelRef.current
      ?.querySelector<HTMLButtonElement>(`[data-value="${next.value}"]`)
      ?.focus();
  };

  const panel = open
    ? createPortal(
        <div
          ref={panelRef}
          id={panelID}
          className="ipv4-segment-picker-panel"
          role="listbox"
          aria-label={`${label}可选值`}
          style={panelPosition}
        >
          <header className="ipv4-segment-picker-header">
            <strong>{label}</strong>
          </header>
          {options.length > 0 ? (
            <div className="ipv4-segment-picker-grid">
              {options.map((option) => (
                <button
                  className="ipv4-segment-picker-option"
                  type="button"
                  role="option"
                  key={option.value}
                  data-value={option.value}
                  aria-selected={option.value === value}
                  disabled={option.disabled}
                  title={
                    option.reason === "conflict" ? "该地址已被占用" : undefined
                  }
                  onKeyDown={(event) => moveOptionFocus(event, option.value)}
                  onClick={() => {
                    onChange(option.value);
                    setOpen(false);
                    triggerRef.current?.focus();
                  }}
                >
                  {option.value}
                </button>
              ))}
            </div>
          ) : (
            <p className="ipv4-segment-picker-empty">请先修正前一段地址</p>
          )}
        </div>,
        document.body,
      )
    : null;

  return (
    <span ref={rootRef} className="ipv4-segment-picker">
      <button
        ref={triggerRef}
        className={`ipv4-segment-picker-trigger ${
          invalid ? "is-out-of-range" : ""
        }`.trim()}
        type="button"
        disabled={disabled}
        aria-label={label}
        aria-haspopup="listbox"
        aria-expanded={open}
        aria-controls={open ? panelID : undefined}
        aria-invalid={invalid || undefined}
        onKeyDown={(event) => {
          if (event.key !== "ArrowDown") return;
          event.preventDefault();
          setOpen(true);
        }}
        onClick={() => setOpen((current) => !current)}
      >
        <span>{value ?? "—"}</span>
        <Icon name="chevron-down" />
      </button>
      {panel}
    </span>
  );
}

let nextRowID = 0;

function newRowID() {
  nextRowID += 1;
  return `allowed-ip-${nextRowID}`;
}

function blankEditorRow(family: IPFamily = 4): EditorRow {
  return {
    id: newRowID(),
    family,
    prefix: null,
    ipv4Segments: [0, 0, 0, 0],
    ipv6Address: "",
  };
}

function editorRowFromCIDR(
  value: string,
  preserveHostBits: boolean,
): EditorRow | null {
  const parsed = parseCIDR(value);
  if (!parsed) return null;
  const sourceAddress = preserveHostBits
    ? parseIPAddress(value.split("/", 1)[0], parsed.family)?.address
    : parsed.network;
  if (sourceAddress === undefined) return null;
  const address = formatAddress(sourceAddress, parsed.family);
  return {
    id: newRowID(),
    family: parsed.family,
    prefix: parsed.prefix,
    ipv4Segments:
      parsed.family === 4
        ? address.split(".").map(Number)
        : [null, null, null, null],
    ipv6Address: parsed.family === 6 ? address : "",
  };
}

function initialRows(
  values: string[],
  defaultFamily: IPFamily,
  preserveHostBits: boolean,
  showBlankRowWhenEmpty: boolean,
) {
  const rows = values.flatMap((value) => {
    const row = editorRowFromCIDR(value, preserveHostBits);
    return row ? [row] : [];
  });
  if (rows.length > 0) return rows;
  if (values.length > 0 || showBlankRowWhenEmpty) {
    return [blankEditorRow(defaultFamily)];
  }
  return [];
}

function toIPv4AddressRow(row: EditorRow): AddressRow {
  return {
    id: row.id,
    family: 4,
    prefix: row.prefix,
    segments: row.ipv4Segments,
  };
}

function normalizeIPv4EditorRow(
  row: EditorRow,
  allowedRanges: ParsedCIDR[],
  occupiedRanges: ParsedCIDR[],
): EditorRow {
  if (row.family !== 4) return row;
  const normalized = normalizeAddressRow(
    toIPv4AddressRow(row),
    allowedRanges,
    occupiedRanges,
  );
  return { ...row, ipv4Segments: normalized.segments };
}

function prefixLabel(prefix: number, family: IPFamily) {
  if (prefix === (family === 4 ? 32 : 128)) return `/${prefix} · 单地址`;
  return `/${prefix}`;
}

function validateRow(
  row: EditorRow,
  allowedRanges: ParsedCIDR[],
  occupiedRanges: ParsedCIDR[],
  preserveHostBits: boolean,
): RowResult {
  if (row.prefix === null) {
    return { cidr: null, error: "请选择子网掩码，或删除该地址行" };
  }
  if (row.family === 6) {
    if (preserveHostBits) {
      const parsed = parseIPAddress(row.ipv6Address, 6);
      if (!parsed) return { cidr: null, error: "IPv6 地址格式无效" };
      return { cidr: `${parsed.canonical}/${row.prefix}`, error: "" };
    }
    return validateAddressCIDR(
      row.ipv6Address,
      row.prefix,
      row.family,
      allowedRanges,
      occupiedRanges,
    );
  }
  const cidr = addressRowToCIDR(toIPv4AddressRow(row));
  if (!cidr) return { cidr: null, error: "请按顺序填写完整 IPv4 地址" };
  if (preserveHostBits) return { cidr, error: "" };
  const parsed = parseCIDR(cidr);
  if (!parsed) return { cidr: null, error: "IPv4 地址格式无效" };
  return validateAddressCIDR(
    formatAddress(parsed.network, 4),
    parsed.prefix,
    4,
    allowedRanges,
    occupiedRanges,
  );
}

function validateRows(
  rows: EditorRow[],
  allowedRanges: ParsedCIDR[],
  occupiedRanges: ParsedCIDR[],
  preserveHostBits: boolean,
) {
  const candidates = rows.map((row) =>
    validateRow(row, allowedRanges, [], preserveHostBits),
  );
  const counts = new Map<string, number>();
  for (const candidate of candidates) {
    if (candidate.cidr) {
      counts.set(candidate.cidr, (counts.get(candidate.cidr) ?? 0) + 1);
    }
  }
  return rows.map((row, index) => {
    const candidate = candidates[index];
    if (candidate.cidr && (counts.get(candidate.cidr) ?? 0) > 1) {
      return {
        cidr: null,
        error: preserveHostBits
          ? "Address 与另一条地址重复"
          : "AllowedIPs 与另一条地址重复",
      };
    }
    return validateRow(
      row,
      allowedRanges,
      occupiedRanges,
      preserveHostBits,
    );
  });
}

export default function AllowedIPsEditor({
  mode = "peer",
  initialValues,
  showBlankRowWhenEmpty = true,
  allowedRanges = EMPTY_VALUES,
  reservedAddresses = EMPTY_VALUES,
  assignments = EMPTY_ASSIGNMENTS,
  currentPeerPublicKey,
  onChange,
}: AllowedIPsEditorProps) {
  const isInterface = mode === "interface";
  const headingID = useId();
  const parsedAllowedRanges = useMemo(
    () => parseCIDRs(allowedRanges),
    [allowedRanges],
  );
  const [constraintsEnabled, setConstraintsEnabled] = useState(() =>
    !initialValues.some((value) =>
      valueIsOutsideConstraint(value, parsedAllowedRanges, isInterface),
    ),
  );
  const effectiveAllowedRanges = useMemo(
    () => (constraintsEnabled ? parsedAllowedRanges : []),
    [constraintsEnabled, parsedAllowedRanges],
  );
  const occupiedRanges = useMemo(
    () =>
      parseCIDRs([
        ...reservedAddresses,
        ...assignments
          .filter(
            (assignment) =>
              !currentPeerPublicKey ||
              assignment.peerPublicKey !== currentPeerPublicKey,
          )
          .map((assignment) => assignment.allowedIP),
      ]),
    [assignments, currentPeerPublicKey, reservedAddresses],
  );
  const allowedFamilies = useMemo(
    () => availableIPFamilies(effectiveAllowedRanges),
    [effectiveAllowedRanges],
  );
  const defaultFamily = allowedFamilies[0] ?? 4;
  const [rows, setRows] = useState<EditorRow[]>(() =>
    initialRows(
      initialValues,
      defaultFamily,
      isInterface,
      showBlankRowWhenEmpty,
    ),
  );
  const onChangeRef = useRef(onChange);
  onChangeRef.current = onChange;
  const ipv4Allowed = allowedFamilies.includes(4);
  const ipv6Allowed = allowedFamilies.includes(6);

  const results = validateRows(
    rows,
    [],
    occupiedRanges,
    isInterface,
  );
  const isConstraintViolation = (
    result: RowResult,
    enforceConstraints = constraintsEnabled,
  ) =>
    enforceConstraints &&
    result.cidr !== null &&
    valueIsOutsideConstraint(
      result.cidr,
      parsedAllowedRanges,
      isInterface,
    );
  const firstVisibleErrorIndex = results.findIndex(
    (result) => result.error !== "",
  );
  const firstConstraintErrorIndex = results.findIndex((result) =>
    isConstraintViolation(result),
  );
  const hasVisibleError =
    firstVisibleErrorIndex >= 0 || firstConstraintErrorIndex >= 0;
  const rangeHint =
    firstVisibleErrorIndex >= 0
      ? `地址 ${firstVisibleErrorIndex + 1}：${results[firstVisibleErrorIndex].error}`
      : firstConstraintErrorIndex >= 0
        ? `地址 ${firstConstraintErrorIndex + 1}：当前值不符合已启用的路由范围约束，请修改`
      : allowedRanges.length > 0
          ? constraintsEnabled
            ? `范围：${allowedRanges.join("、")}`
            : `参考范围：${allowedRanges.join("、")}`
          : isInterface
            ? ""
            : "未设置路由范围约束，可使用任意 IP";

  const emitRows = (
    nextRows: EditorRow[],
    enforceConstraints = constraintsEnabled,
  ) => {
    const nextResults = validateRows(
      nextRows,
      [],
      occupiedRanges,
      isInterface,
    );
    onChangeRef.current(
      nextResults.flatMap((result) => (result.cidr ? [result.cidr] : [])),
      nextResults.every(
        (result) =>
          result.error === "" &&
          !isConstraintViolation(result, enforceConstraints),
      ),
    );
  };

  const updateRows = (nextRows: EditorRow[]) => {
    setRows(nextRows);
    emitRows(nextRows);
  };

  useEffect(() => {
    emitRows(rows);
    // Normal row edits already pass through updateRows. Constraint changes
    // also change whether an existing value is valid and the form can save.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [constraintsEnabled, occupiedRanges, parsedAllowedRanges]);

  const replaceRow = (
    rowID: string,
    updater: (row: EditorRow) => EditorRow,
  ) => {
    updateRows(
      rows.map((row) =>
        row.id === rowID
          ? isInterface
            ? updater(row)
            : normalizeIPv4EditorRow(
                updater(row),
                effectiveAllowedRanges,
                [],
              )
          : row,
      ),
    );
  };

  const setFamily = (rowID: string, family: IPFamily) => {
    if (!allowedFamilies.includes(family)) return;
    replaceRow(rowID, (row) => ({ ...blankEditorRow(family), id: row.id }));
  };

  const setPrefix = (rowID: string, value: string) => {
    replaceRow(rowID, (row) => ({
      ...row,
      prefix: value === "" ? null : Number(value),
    }));
  };

  const setIPv4Segment = (rowID: string, index: number, value: number) => {
    replaceRow(rowID, (row) => {
      const ipv4Segments = row.ipv4Segments.slice();
      ipv4Segments[index] = value;
      return { ...row, ipv4Segments };
    });
  };

  return (
    <section
      className={`allowed-ips-editor ${isInterface ? "interface-address-editor " : ""}is-full`}
      aria-labelledby={headingID}
    >
      <header className="allowed-ips-heading">
        <div className="allowed-ips-heading-copy">
          <strong id={headingID}>{isInterface ? "Address" : "AllowedIPs"}</strong>
          {rangeHint && (
            <small
              className={hasVisibleError ? "field-error" : ""}
              aria-live="polite"
            >
              {rangeHint}
            </small>
          )}
        </div>
        {parsedAllowedRanges.length > 0 && (
          <label className="toggle allowed-constraint-toggle">
            <input
              type="checkbox"
              checked={constraintsEnabled}
              onChange={(event) => {
                const enabled = event.target.checked;
                setConstraintsEnabled(enabled);
                emitRows(rows, enabled);
              }}
            />
            <span aria-hidden="true" />
            <span>启用约束</span>
          </label>
        )}
      </header>

      {rows.length > 0 && (
        <div className="allowed-ip-rows">
          {rows.map((row, rowIndex) => {
          const result = results[rowIndex];
          const rowInvalid = result.error !== "";
          const rowOutOfRange = isConstraintViolation(result);
          const ipv4AddressRow = toIPv4AddressRow(row);
          return (
            <div
              className={`allowed-ip-row ${rowInvalid ? "is-invalid" : ""} ${
                rowOutOfRange ? "is-out-of-range" : ""
              }`.trim()}
              key={row.id}
              title={
                rowInvalid
                  ? result.error
                  : rowOutOfRange
                    ? "当前值不符合已启用的路由范围约束，请修改"
                    : undefined
              }
            >
              <select
                className="allowed-ip-family"
                value={row.family}
                aria-label={`${isInterface ? "Interface " : ""}地址 ${
                  rowIndex + 1
                } 类型`}
                onChange={(event) =>
                  setFamily(row.id, Number(event.target.value) as IPFamily)
                }
              >
                <option value={4} disabled={!ipv4Allowed}>
                  IPv4{ipv4Allowed ? "" : " · 路由范围未启用"}
                </option>
                <option value={6} disabled={!ipv6Allowed}>
                  IPv6{ipv6Allowed ? "" : " · 路由范围未启用"}
                </option>
              </select>

              {row.family === 4 ? (
                <div
                  className="allowed-ipv4-input"
                  aria-label={`地址 ${rowIndex + 1} IPv4`}
                >
                  {row.ipv4Segments.map((segment, index) => {
                    const previousComplete = row.ipv4Segments
                      .slice(0, index)
                      .every((item) => item !== null);
                    const hostOnly =
                      !isInterface &&
                      row.prefix !== null &&
                      index * segmentBits(4) >= row.prefix;
                    const options: SegmentOption[] = isInterface
                      ? interfaceIPv4SegmentOptions(
                          row,
                          index,
                          effectiveAllowedRanges,
                        )
                      : segmentOptions(
                          ipv4AddressRow,
                          index,
                          effectiveAllowedRanges,
                          [],
                        );
                    return (
                      <span key={index}>
                        {index > 0 && <i aria-hidden="true">.</i>}
                        {hostOnly ? (
                          <span
                            className="allowed-ipv4-fixed"
                            aria-label={`IPv4 第 ${index + 1} 段固定为 0`}
                          >
                            0
                          </span>
                        ) : (
                          <IPv4SegmentPicker
                            value={segment}
                            options={selectableSegmentOptions(options)}
                            disabled={row.prefix === null || !previousComplete}
                            label={`${isInterface ? "Interface " : ""}IPv4 第 ${index + 1} 段`}
                            invalid={false}
                            onChange={(value) =>
                              setIPv4Segment(row.id, index, value)
                            }
                          />
                        )}
                      </span>
                    );
                  })}
                </div>
              ) : (
                <input
                  className="allowed-ipv6-input"
                  value={row.ipv6Address}
                  disabled={row.prefix === null}
                  inputMode="text"
                  autoComplete="off"
                  spellCheck={false}
                  aria-label={`${isInterface ? "Interface " : ""}地址 ${
                    rowIndex + 1
                  } IPv6`}
                  aria-invalid={rowInvalid || undefined}
                  placeholder={
                    row.prefix === null
                      ? "请先选择掩码"
                      : isInterface
                        ? "例如 fd20::1"
                        : "例如 fd20::2"
                  }
                  onChange={(event) =>
                    replaceRow(row.id, (current) => ({
                      ...current,
                      ipv6Address: event.target.value,
                    }))
                  }
                />
              )}

              <select
                className="allowed-ip-prefix"
                value={row.prefix ?? ""}
                aria-label={`${isInterface ? "Interface " : ""}地址 ${
                  rowIndex + 1
                } 子网掩码`}
                onChange={(event) => setPrefix(row.id, event.target.value)}
              >
                <option value="">选择掩码</option>
                {(isInterface
                  ? Array.from(
                      { length: (row.family === 4 ? 32 : 128) + 1 },
                      (_, prefix) => prefix,
                    )
                  : availablePrefixes(row.family, effectiveAllowedRanges, [])
                ).map((prefix) => (
                  <option key={prefix} value={prefix}>
                    {prefixLabel(prefix, row.family)}
                  </option>
                ))}
              </select>

              <button
                className="icon-button allowed-ip-remove"
                type="button"
                aria-label={`删除${isInterface ? " Interface" : ""} 地址 ${
                  rowIndex + 1
                }`}
                title="删除此地址"
                onClick={() =>
                  updateRows(rows.filter((item) => item.id !== row.id))
                }
              >
                <Icon name="trash" />
              </button>
            </div>
          );
          })}
        </div>
      )}

      <button
        className="button allowed-ip-add"
        type="button"
        onClick={() => updateRows([...rows, blankEditorRow(defaultFamily)])}
      >
        <Icon name="plus" />
        {isInterface ? "添加 Address" : "添加 Allowed IP"}
      </button>
    </section>
  );
}
