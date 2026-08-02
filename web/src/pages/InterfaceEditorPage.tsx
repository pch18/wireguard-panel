import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { ApiError } from "../app/apiClient";
import ConfigTextModal from "../features/wireguard/ConfigTextModal";
import InterfaceModal from "../features/wireguard/InterfaceModal";
import InterfaceRenameModal from "../features/wireguard/InterfaceRenameModal";
import MiddleEllipsisKey from "../features/wireguard/MiddleEllipsisKey";
import PeerModal from "../features/wireguard/PeerModal";
import TrafficChart, {
  formatBytes,
  formatRate,
} from "../features/wireguard/TrafficChart";
import { deriveWireGuardPublicKey } from "../features/wireguard/browserKeys";
import {
  cidrValueContainedByAny,
  interfaceAddressContainedByAny,
  parseCIDRs,
  type ParsedCIDR,
} from "../features/wireguard/ipAddress";
import { peerDeletionNeedsRestart } from "../features/wireguard/runtimeDiff";
import { isRuntimeObservationFresh } from "../features/wireguard/runtimeFreshness";
import {
  updatePeerRateWindow,
  type PeerTrafficSample,
  type PeerWindowedRate,
} from "../features/wireguard/peerRateWindow";
import { formatPeerHandshakeElapsed } from "../features/wireguard/peerHandshakeClock";
import { sortPeerEntriesByFirstAllowedIP } from "../features/wireguard/peerDisplayOrder";
import {
  interfaceMatchesInput,
  peerMatchesInput,
} from "../features/wireguard/reconciliation";
import { scopeValidationErrors } from "../features/wireguard/validationScope";
import {
  mergePeerTraffic,
  mergeTrafficPoints,
} from "../features/wireguard/trafficHistory";
import {
  createPeer,
  deletePeer,
  getClientConfigPreview,
  getInterface,
  getInterfaceConfig,
  getIPPlan,
  getRawInterfaceConfig,
  getRuntimeStatus,
  importPeerConfig,
  peerToInput,
  replaceInterfaceConfig,
  renameInterface,
  restartInterface,
  runtimeEventsURL,
  startInterface,
  stopInterface,
  updateInterface,
  updatePeer,
  type InterfaceInput,
  type InterfaceRuntimeStatus,
  type InterfaceTrafficEvent,
  type IPPlan,
  type PeerInput,
  type TrafficPoint,
  type WireGuardInterface,
  type WireGuardPeer,
} from "../features/wireguard/api";
import Icon from "../ui/Icon";
import Modal from "../ui/Modal";
import { useToast } from "../ui/Toast";

type ConfigPreview = {
  title: string;
  description: string;
  text: string;
};

type ImportTarget = "interface" | "peer";
type RuntimeAction = "start" | "stop" | "restart";
type RestartRetry =
  | { target: "interface"; text: string }
  | { target: "peer"; text: string }
  | { target: "interface-form"; input: InterfaceInput }
  | { target: "peer-form"; input: PeerInput };

function mutationStateMayBeUncertain(error: unknown) {
  return !(error instanceof ApiError) || error.status >= 500;
}

function displayList(values: string[]) {
  return values.length ? values.join(", ") : "未配置";
}

function ConstraintAwareIPList({
  values,
  constraints,
  interfaceAddresses = false,
}: {
  values: string[];
  constraints: ParsedCIDR[];
  interfaceAddresses?: boolean;
}) {
  if (values.length === 0) return <>未配置</>;
  return values.map((value, index) => {
    const inRange =
      constraints.length === 0 ||
      (interfaceAddresses
        ? interfaceAddressContainedByAny(value, constraints)
        : cidrValueContainedByAny(value, constraints));
    return (
      <span key={`${index}:${value}`}>
        {index > 0 && ", "}
        <span
          className={inRange ? undefined : "is-out-of-range"}
          title={inRange ? undefined : "超出路由范围约束"}
        >
          {value}
        </span>
      </span>
    );
  });
}

function handshakeTitle(value?: string) {
  if (!value) return undefined;
  const timestamp = new Date(value);
  if (Number.isNaN(timestamp.getTime())) return undefined;
  return new Intl.DateTimeFormat("zh-CN", {
    dateStyle: "medium",
    timeStyle: "medium",
  }).format(timestamp);
}

export default function InterfaceEditorPage() {
  const { id: idParam } = useParams();
  const navigate = useNavigate();
  const { showToast, updateToast, dismissToast } = useToast();
  const interfaceID = idParam;
  const invalidID = !/^[A-Za-z0-9_-]{1,15}$/.test(interfaceID ?? "");

  const [config, setConfig] = useState<WireGuardInterface | null>(null);
  const [ipPlan, setIPPlan] = useState<IPPlan>();
  const [runtime, setRuntime] = useState<InterfaceRuntimeStatus>();
  const [runtimeObservedAt, setRuntimeObservedAt] = useState(0);
  const [interfacePublicKey, setInterfacePublicKey] = useState("");
  const [publicKeyPending, setPublicKeyPending] = useState(false);
  const [loading, setLoading] = useState(!invalidID);
  const [loadError, setLoadError] = useState(
    invalidID ? "Interface ID 无效" : "",
  );
  const [savePending, setSavePending] = useState(false);
  const [runtimePendingAction, setRuntimePendingAction] =
    useState<RuntimeAction | null>(null);
  const [runtimeConfirmation, setRuntimeConfirmation] =
    useState<RuntimeAction | null>(null);
  const [rawConfigText, setRawConfigText] = useState("");
  const [peerImportText, setPeerImportText] = useState("");
  const [interfaceModalOpen, setInterfaceModalOpen] = useState(false);
  const [renameModalOpen, setRenameModalOpen] = useState(false);
  const [renamePending, setRenamePending] = useState(false);
  const [editingPeer, setEditingPeer] = useState<
    WireGuardPeer | "new" | null
  >(null);
  const [peerPending, setPeerPending] = useState(false);
  const [deletingPeer, setDeletingPeer] = useState<WireGuardPeer | null>(null);
  const [peerDeletePending, setPeerDeletePending] = useState(false);
  const [trafficPeer, setTrafficPeer] = useState<WireGuardPeer | null>(null);
  const [configPreview, setConfigPreview] = useState<ConfigPreview | null>(null);
  const [importTarget, setImportTarget] = useState<ImportTarget | null>(null);
  const [importPending, setImportPending] = useState(false);
  const [restartRetry, setRestartRetry] = useState<RestartRetry | null>(null);
  const [actionMenu, setActionMenu] = useState<string | null>(null);
  const [windowedRates, setWindowedRates] = useState<
    Map<string, PeerWindowedRate>
  >(new Map());
  const [interfaceTraffic, setInterfaceTraffic] = useState<TrafficPoint[]>([]);
  const [peerTraffic, setPeerTraffic] = useState(
    () => new Map<string, TrafficPoint[]>(),
  );
  const [clockNow, setClockNow] = useState(() => Date.now());
  const loadRequestRef = useRef(0);
  const runtimeRequestRef = useRef(0);
  const externalRevisionRef = useRef<string>();
  const inputModalOpenRef = useRef(false);
  const peerTrafficHistoryRef = useRef(
    new Map<string, PeerTrafficSample[]>(),
  );
  const configIDRef = useRef<string>();
  const configRevisionRef = useRef<string>();
  configIDRef.current = config?.id;
  configRevisionRef.current = config?.revision;
  inputModalOpenRef.current =
    interfaceModalOpen ||
    renameModalOpen ||
    editingPeer !== null ||
    importTarget !== null ||
    restartRetry !== null;
  const scopedValidationErrors = useMemo(
    () =>
      scopeValidationErrors(
        config?.validationErrors ?? [],
        config?.peers ?? [],
      ),
    [config],
  );
  const routeConstraints = useMemo(
    () => parseCIDRs(config?.clientAllowedIPs ?? []),
    [config?.clientAllowedIPs],
  );
  const displayedPeerEntries = useMemo(
    () => sortPeerEntriesByFirstAllowedIP(config?.peers ?? []),
    [config?.peers],
  );

  const load = useCallback(
    async () => {
      if (interfaceID === undefined || invalidID) return;
      const requestID = ++loadRequestRef.current;
      const hasVisibleConfig = configIDRef.current === interfaceID;
      if (!hasVisibleConfig) setLoading(true);
      setLoadError("");
      try {
        const [configResult, planResult] = await Promise.allSettled([
          getInterface(interfaceID),
          getIPPlan(interfaceID),
        ]);
        if (configResult.status === "rejected") {
          throw configResult.reason;
        }
        if (requestID !== loadRequestRef.current) return;
        const loaded = configResult.value;
        configRevisionRef.current = loaded.revision;
        setConfig(loaded);
        setIPPlan(
          planResult.status === "fulfilled" &&
            planResult.value.revision === loaded.revision
            ? planResult.value
            : undefined,
        );
        return loaded;
      } catch (error) {
        if (requestID !== loadRequestRef.current) return;
        const message =
          error instanceof Error ? error.message : "Interface 加载失败";
        if (!hasVisibleConfig) setLoadError(message);
        showToast(message, "error");
        return undefined;
      } finally {
        if (requestID === loadRequestRef.current) setLoading(false);
      }
    },
    [interfaceID, invalidID, showToast],
  );

  const reloadExternalRevision = useCallback(
    async (revision: string) => {
      // Keep the revision used to open an active input modal. If the backing
      // config changed, its next mutation must receive 412 instead of silently
      // overwriting the newer version with stale form values.
      if (inputModalOpenRef.current) return;
      if (externalRevisionRef.current === revision) return;
      const latest = await load();
      if (latest) externalRevisionRef.current = revision;
    },
    [load],
  );

  useEffect(() => {
    if (invalidID) {
      loadRequestRef.current++;
      runtimeRequestRef.current++;
      setLoading(false);
      setLoadError("Interface ID 无效");
      setConfig(null);
      setIPPlan(undefined);
      setRuntime(undefined);
      setRuntimeObservedAt(0);
      return;
    }
    void load();
  }, [invalidID, load]);

  useEffect(() => {
    if (!actionMenu) return;

    const closeOutside = (event: PointerEvent) => {
      if (
        event.target instanceof Element &&
        !event.target.closest("[data-action-menu]")
      ) {
        setActionMenu(null);
      }
    };
    const closeOnEscape = (event: KeyboardEvent) => {
      if (event.key === "Escape") setActionMenu(null);
    };

    document.addEventListener("pointerdown", closeOutside);
    document.addEventListener("keydown", closeOnEscape);
    return () => {
      document.removeEventListener("pointerdown", closeOutside);
      document.removeEventListener("keydown", closeOnEscape);
    };
  }, [actionMenu]);

  useEffect(() => {
    const privateKey = config?.privateKey.trim();
    if (!privateKey) {
      setInterfacePublicKey("");
      setPublicKeyPending(false);
      return;
    }
    let active = true;
    setPublicKeyPending(true);
    void deriveWireGuardPublicKey(privateKey)
      .then((publicKey) => {
        if (active) setInterfacePublicKey(publicKey);
      })
      .catch(() => {
        if (active) setInterfacePublicKey("");
      })
      .finally(() => {
        if (active) setPublicKeyPending(false);
      });
    return () => {
      active = false;
    };
  }, [config?.privateKey]);

  const refreshRuntime = useCallback(async (expectedRevision?: string) => {
    if (interfaceID === undefined || invalidID) return undefined;
    const revision = expectedRevision ?? configRevisionRef.current;
    const requestID = ++runtimeRequestRef.current;
    try {
      const next = await getRuntimeStatus(interfaceID);
      if (requestID !== runtimeRequestRef.current) return undefined;
      if (revision && next.configurationRevision !== revision) {
        void reloadExternalRevision(next.configurationRevision);
        return undefined;
      }
      setRuntime(next);
      const observedAt = Date.now();
      setRuntimeObservedAt(observedAt);
      setClockNow(observedAt);
      return next;
    } catch (error) {
      if (
        error instanceof ApiError &&
        (error.status === 404 || error.status === 422)
      ) {
        void load();
      }
      if (requestID === runtimeRequestRef.current) {
        setRuntime({
          interfaceID,
          interfaceName: interfaceID,
          configurationRevision: revision ?? "",
          running: undefined,
          collectorAvailable: false,
          message: "运行状态暂时无法读取",
          peers: [],
        });
        setRuntimeObservedAt(Date.now());
      }
      return undefined;
    }
  }, [interfaceID, invalidID, load, reloadExternalRevision]);

  useEffect(() => {
    setInterfaceTraffic([]);
    setPeerTraffic(new Map());
    if (interfaceID === undefined || invalidID) return;

    const source = new EventSource(runtimeEventsURL(interfaceID));
    const receiveTraffic = (message: Event) => {
      try {
        const event = JSON.parse(
          (message as MessageEvent<string>).data,
        ) as InterfaceTrafficEvent;
        const revision = configRevisionRef.current;
        if (
          revision &&
          event.status.configurationRevision &&
          event.status.configurationRevision !== revision
        ) {
          void reloadExternalRevision(event.status.configurationRevision);
          return;
        }
        runtimeRequestRef.current++;
        setRuntime(event.status);
        const observedAt = Date.now();
        setRuntimeObservedAt(observedAt);
        setClockNow(observedAt);
        const replace = event.kind === "history";
        setInterfaceTraffic((current) =>
          mergeTrafficPoints(replace ? [] : current, event.interfaceTraffic),
        );
        setPeerTraffic((current) =>
          mergePeerTraffic(current, event.peerTraffic, replace),
        );
      } catch {
        // EventSource reconnects automatically; retain the last valid sample.
      }
    };
    source.addEventListener("traffic", receiveTraffic);
    return () => {
      runtimeRequestRef.current++;
      source.removeEventListener("traffic", receiveTraffic);
      source.close();
    };
  }, [interfaceID, invalidID, reloadExternalRevision]);

  useEffect(() => {
    setClockNow(Date.now());
    const timer = window.setInterval(() => setClockNow(Date.now()), 1_000);
    return () => window.clearInterval(timer);
  }, [interfaceID]);

  const currentRuntime =
    runtime &&
    runtime.interfaceID === interfaceID &&
    (!config?.revision || runtime.configurationRevision === config.revision)
      ? runtime
      : undefined;
  const runtimeObservationFresh = isRuntimeObservationFresh(
    runtimeObservedAt,
    clockNow,
  );
  const runtimeMetricsAvailable = Boolean(
    currentRuntime?.collectorAvailable && runtimeObservationFresh,
  );
  // Runtime controllability is a backend deployment capability, not a sampled
  // property of one configuration revision. Retain it while a successful
  // mutation advances the revision and the fresh status request is in flight.
  const fileOnlyRuntime =
    currentRuntime?.runtimeControllable === false ||
    (runtime?.runtimeControllable === false &&
      runtime.interfaceID === interfaceID);
  const runtimeRunning =
    !fileOnlyRuntime &&
    runtimeObservationFresh &&
    currentRuntime?.runtimeStateAvailable
      ? Boolean(currentRuntime.running)
      : undefined;
  const runtimePending = runtimePendingAction !== null;
  const restartRetryPending = restartRetry
    ? restartRetry.target === "interface-form"
      ? savePending
      : restartRetry.target === "peer-form"
        ? peerPending
        : importPending
    : false;

  const runtimeByPeer = useMemo(
    () =>
      new Map(
        currentRuntime?.peers.map((peer) => [peer.publicKey, peer]) ?? [],
      ),
    [currentRuntime],
  );

  const interfaceRuntimeSummary = useMemo(() => {
    const totalPeers = config?.peers.length ?? 0;
    if (!runtimeMetricsAvailable || !currentRuntime) {
      return {
        available: false,
        activePeers: 0,
        totalPeers,
        receivedBytes: 0,
        sentBytes: 0,
        receiveBytesPerSecond: 0,
        sendBytesPerSecond: 0,
      };
    }

    return currentRuntime.peers.reduce(
      (summary, peer) => {
        const rate = windowedRates.get(peer.publicKey);
        summary.activePeers += peer.available && peer.active ? 1 : 0;
        summary.receivedBytes += peer.receivedBytes;
        summary.sentBytes += peer.sentBytes;
        summary.receiveBytesPerSecond +=
          rate?.receiveBytesPerSecond ?? peer.receiveBytesPerSecond;
        summary.sendBytesPerSecond +=
          rate?.sendBytesPerSecond ?? peer.sendBytesPerSecond;
        return summary;
      },
      {
        available: true,
        activePeers: 0,
        totalPeers,
        receivedBytes: 0,
        sentBytes: 0,
        receiveBytesPerSecond: 0,
        sendBytesPerSecond: 0,
      },
    );
  }, [
    config?.peers.length,
    currentRuntime,
    runtimeMetricsAvailable,
    windowedRates,
  ]);
  const onlinePeerCount = interfaceRuntimeSummary.available
    ? interfaceRuntimeSummary.activePeers
    : undefined;
  const offlinePeerCount =
    onlinePeerCount === undefined
      ? undefined
      : Math.max(0, interfaceRuntimeSummary.totalPeers - onlinePeerCount);

  useEffect(() => {
    peerTrafficHistoryRef.current.clear();
    setWindowedRates(new Map());
  }, [interfaceID]);

  useEffect(() => {
    const sampledAt = Date.parse(currentRuntime?.sampledAt ?? "");
    if (!currentRuntime?.collectorAvailable || !Number.isFinite(sampledAt)) {
      setWindowedRates(new Map());
      return;
    }

    const activeKeys = new Set<string>();
    const nextRates = new Map<string, PeerWindowedRate>();
    for (const status of currentRuntime.peers) {
      activeKeys.add(status.publicKey);
      const fallback = {
        receiveBytesPerSecond: status.receiveBytesPerSecond,
        sendBytesPerSecond: status.sendBytesPerSecond,
      };
      if (!status.available) {
        nextRates.set(status.publicKey, fallback);
        continue;
      }
      const result = updatePeerRateWindow(
        peerTrafficHistoryRef.current.get(status.publicKey) ?? [],
        {
          sampledAt,
          receivedBytes: status.receivedBytes,
          sentBytes: status.sentBytes,
        },
        fallback,
      );
      peerTrafficHistoryRef.current.set(status.publicKey, result.samples);
      nextRates.set(status.publicKey, {
        receiveBytesPerSecond: result.receiveBytesPerSecond,
        sendBytesPerSecond: result.sendBytesPerSecond,
      });
    }
    for (const publicKey of peerTrafficHistoryRef.current.keys()) {
      if (!activeKeys.has(publicKey)) {
        peerTrafficHistoryRef.current.delete(publicKey);
      }
    }
    setWindowedRates(nextRates);
  }, [currentRuntime]);

  const handleRevisionConflict = async (
    error: unknown,
    toastID: number,
  ) => {
    if (!(error instanceof ApiError) || error.status !== 412) return false;
    const previousRevision = configRevisionRef.current;
    const hadUnsavedInput = inputModalOpenRef.current;
    const latest = await load();
    const refreshed =
      latest !== undefined || configRevisionRef.current !== previousRevision;
    updateToast(
      toastID,
      refreshed
        ? hadUnsavedInput
          ? "配置已更新；表单内容已保留，请检查后重试。"
          : "配置已更新，请重试。"
        : hadUnsavedInput
          ? "配置已更新但读取失败；表单内容已保留。"
          : "配置已更新但读取失败，请稍后重试。",
      "warning",
      8_000,
    );
    if (refreshed) await refreshRuntime();
    return true;
  };

  const refreshIPPlan = async () => {
    if (interfaceID === undefined) return;
    try {
      const plan = await getIPPlan(interfaceID);
      setIPPlan(
        !configRevisionRef.current ||
          plan.revision === configRevisionRef.current
          ? plan
          : undefined,
      );
    } catch {
      setIPPlan(undefined);
    }
  };

  const reconcileAfterMutationFailure = async () => {
    const latest = await load();
    await refreshRuntime(latest?.revision);
    return latest;
  };

  const save = async (
    interfaceInput: InterfaceInput,
    restartConfirmed = false,
  ) => {
    if (interfaceID === undefined || !config) return;
    setSavePending(true);
    const toastID = showToast("正在保存…", "loading", 0);
    try {
      const saved = await updateInterface(
        interfaceID,
        config.revision,
        interfaceInput,
        restartConfirmed,
      );
      configRevisionRef.current = saved.revision;
      setConfig(saved);
      setInterfaceModalOpen(false);
      setRestartRetry(null);
      await Promise.all([
        refreshIPPlan(),
        refreshRuntime(saved.revision),
      ]);
      dismissToast(toastID);
    } catch (error) {
      if (
        !restartConfirmed &&
        error instanceof ApiError &&
        error.code === "restart_required"
      ) {
        dismissToast(toastID);
        setRestartRetry({ target: "interface-form", input: interfaceInput });
        return;
      }
      if (!(await handleRevisionConflict(error, toastID))) {
        const uncertain = mutationStateMayBeUncertain(error);
        const latest = uncertain
          ? await reconcileAfterMutationFailure()
          : undefined;
        if (
          !(error instanceof ApiError) &&
          latest &&
          interfaceMatchesInput(latest, interfaceInput)
        ) {
          setInterfaceModalOpen(false);
          setRestartRetry(null);
          await refreshIPPlan();
          updateToast(
            toastID,
            "响应中断，但已确认后端保存成功并同步当前状态。",
            "warning",
            8_000,
          );
          return;
        }
        updateToast(
          toastID,
          `${error instanceof Error ? error.message : "Interface 保存失败"}${
            latest ? "；已重新同步后端当前状态" : ""
          }`,
          "error",
        );
      }
    } finally {
      setSavePending(false);
    }
  };

  const changeRuntime = async (action: RuntimeAction) => {
    if (!interfaceID || !config || runtimeRunning === undefined) return;
    setRuntimeConfirmation(null);
    setRuntimePendingAction(action);
    const actionLabel =
      action === "start" ? "启动" : action === "stop" ? "停止" : "重启";
    const toastID = showToast(`正在${actionLabel}…`, "loading", 0);
    try {
      const current =
        action === "start"
          ? await startInterface(interfaceID, config.revision)
          : action === "stop"
            ? await stopInterface(interfaceID, config.revision)
            : await restartInterface(interfaceID, config.revision);
      configRevisionRef.current = current.revision;
      setConfig(current);
      await refreshRuntime(current.revision);
      dismissToast(toastID);
    } catch (error) {
      if (!(await handleRevisionConflict(error, toastID))) {
        const latest = mutationStateMayBeUncertain(error)
          ? await reconcileAfterMutationFailure()
          : undefined;
        updateToast(
          toastID,
          `${error instanceof Error
            ? error.message
            : `Interface ${actionLabel}失败`}${
            latest ? "；已重新同步后端当前状态" : ""
          }`,
          "error",
          8_000,
        );
      }
    } finally {
      setRuntimePendingAction(null);
    }
  };

  const openRawConfigEditor = async () => {
    if (!interfaceID) return;
    const toastID = showToast("正在读取原始配置…", "loading", 0);
    try {
      setRawConfigText(await getRawInterfaceConfig(interfaceID));
      setImportTarget("interface");
      dismissToast(toastID);
    } catch (error) {
      updateToast(
        toastID,
        error instanceof Error ? error.message : "原始配置读取失败",
        "error",
      );
    }
  };

  const rename = async (name: string) => {
    if (!interfaceID || !config) return;
    setRenamePending(true);
    const toastID = showToast("正在重命名…", "loading", 0);
    try {
      const renamed = await renameInterface(interfaceID, config.revision, name);
      configRevisionRef.current = renamed.revision;
      setConfig(renamed);
      setRuntime(undefined);
      setRuntimeObservedAt(0);
      setRenameModalOpen(false);
      dismissToast(toastID);
      navigate(`/interfaces/${encodeURIComponent(renamed.id)}`, {
        replace: true,
      });
    } catch (error) {
      if (await handleRevisionConflict(error, toastID)) return;
      if (!(error instanceof ApiError)) {
        try {
          const renamed = await getInterface(name);
          configRevisionRef.current = renamed.revision;
          setConfig(renamed);
          setRuntime(undefined);
          setRuntimeObservedAt(0);
          setRenameModalOpen(false);
          navigate(`/interfaces/${encodeURIComponent(renamed.id)}`, {
            replace: true,
          });
          updateToast(
            toastID,
            "响应中断，但已确认后端重命名成功。",
            "warning",
            8_000,
          );
        } catch {
          const latest = await reconcileAfterMutationFailure();
          updateToast(
            toastID,
            latest
              ? "重命名未生效；已重新同步后端当前状态。"
              : `重命名结果暂时无法确认，请检查 ${name}.conf 或 ${interfaceID}.conf。`,
            latest ? "error" : "warning",
            10_000,
          );
        }
        return;
      }
      updateToast(toastID, error.message, "error", 8_000);
      if (mutationStateMayBeUncertain(error)) {
        await reconcileAfterMutationFailure();
      }
    } finally {
      setRenamePending(false);
    }
  };

  const submitPeer = async (
    peerInput: PeerInput,
    restartConfirmed = false,
  ) => {
    if (interfaceID === undefined || !config) return;
    setPeerPending(true);
    const originalPublicKey =
      editingPeer && editingPeer !== "new"
        ? editingPeer.publicKey
        : undefined;
    const toastID = showToast(
      originalPublicKey
        ? "正在保存 Peer…"
        : "正在添加 Peer…",
      "loading",
      0,
    );
    try {
      const saved = originalPublicKey
        ? await updatePeer(
            interfaceID,
            originalPublicKey,
            config.revision,
            peerInput,
            restartConfirmed,
          )
        : await createPeer(
            interfaceID,
            config.revision,
            peerInput,
            restartConfirmed,
          );
      configRevisionRef.current = saved.revision;
      setConfig(saved);
      await Promise.all([
        refreshIPPlan(),
        refreshRuntime(saved.revision),
      ]);
      dismissToast(toastID);
      setEditingPeer(null);
      setRestartRetry(null);
    } catch (error) {
      if (
        !restartConfirmed &&
        error instanceof ApiError &&
        error.code === "restart_required"
      ) {
        dismissToast(toastID);
        setRestartRetry({ target: "peer-form", input: peerInput });
        return;
      }
      if (!(await handleRevisionConflict(error, toastID))) {
        const uncertain = mutationStateMayBeUncertain(error);
        const latest = uncertain
          ? await reconcileAfterMutationFailure()
          : undefined;
        const savedPeer = latest?.peers.find(
          (peer) => peer.publicKey === peerInput.publicKey.trim(),
        );
        if (
          !(error instanceof ApiError) &&
          savedPeer &&
          peerMatchesInput(savedPeer, peerInput)
        ) {
          setEditingPeer(null);
          setRestartRetry(null);
          await refreshIPPlan();
          updateToast(
            toastID,
            "响应中断，但已确认后端已保存 Peer。",
            "warning",
            8_000,
          );
          return;
        }
        updateToast(
          toastID,
          `${error instanceof Error ? error.message : "Peer 保存失败"}${
            latest ? "；已重新同步后端当前状态" : ""
          }`,
          "error",
        );
      }
    } finally {
      setPeerPending(false);
    }
  };

  const confirmPeerDelete = async () => {
    if (interfaceID === undefined || !deletingPeer || !config) return;
    setPeerDeletePending(true);
    const toastID = showToast("正在删除 Peer…", "loading", 0);
    try {
      const saved = await deletePeer(
        interfaceID,
        deletingPeer.publicKey,
        config.revision,
        true,
      );
      configRevisionRef.current = saved.revision;
      setConfig(saved);
      await Promise.all([
        refreshIPPlan(),
        refreshRuntime(saved.revision),
      ]);
      dismissToast(toastID);
      setDeletingPeer(null);
    } catch (error) {
      if (!(await handleRevisionConflict(error, toastID))) {
        const deletedPublicKey = deletingPeer.publicKey;
        const uncertain = mutationStateMayBeUncertain(error);
        const latest = uncertain
          ? await reconcileAfterMutationFailure()
          : undefined;
        if (
          !(error instanceof ApiError) &&
          latest &&
          !latest.peers.some((peer) => peer.publicKey === deletedPublicKey)
        ) {
          setDeletingPeer(null);
          await refreshIPPlan();
          updateToast(
            toastID,
            "响应中断，但已确认后端已删除 Peer。",
            "warning",
            8_000,
          );
          return;
        }
        updateToast(
          toastID,
          `${error instanceof Error ? error.message : "Peer 删除失败"}${
            latest ? "；已重新同步后端当前状态" : ""
          }`,
          "error",
        );
      }
    } finally {
      setPeerDeletePending(false);
    }
  };

  const openInterfacePreview = async () => {
    if (interfaceID === undefined) return;
    const toastID = showToast("正在读取配置…", "loading", 0);
    try {
      const text = await getInterfaceConfig(interfaceID);
      setConfigPreview({
        title: `导出 ${config?.filename ?? `${interfaceID}.conf`}`,
        description: "",
        text,
      });
      dismissToast(toastID);
    } catch (error) {
      updateToast(
        toastID,
        error instanceof Error ? error.message : "Interface 配置读取失败",
        "error",
        6_000,
      );
    }
  };

  const openClientPreview = async (peer: WireGuardPeer) => {
    if (interfaceID === undefined) return;
    const toastID = showToast("正在生成客户端配置…", "loading", 0);
    try {
      const text = await getClientConfigPreview(interfaceID, peer.publicKey);
      setConfigPreview({
        title: `客户端配置：${peer.name}`,
        description: "必填字段即使缺值也会保留；空的可选字段不会输出。",
        text,
      });
      dismissToast(toastID);
    } catch (error) {
      updateToast(
        toastID,
        error instanceof Error ? error.message : "客户端配置生成失败",
        "error",
        6_000,
      );
    }
  };

  const submitInterfaceImport = async (
    text: string,
    restartConfirmed = false,
  ) => {
    if (interfaceID === undefined || !config) return;
    setImportPending(true);
    const toastID = showToast("正在保存配置…", "loading", 0);
    try {
      const saved = await replaceInterfaceConfig(
        interfaceID,
        config.revision,
        text,
        restartConfirmed,
      );
      configRevisionRef.current = saved.revision;
      setConfig(saved);
      setInterfaceModalOpen(false);
      setImportTarget(null);
      setRestartRetry(null);
      await Promise.all([
        refreshIPPlan(),
        refreshRuntime(saved.revision),
      ]);
      if ((saved.validationErrors?.length ?? 0) > 0) {
        updateToast(
          toastID,
          "配置已保存但存在错误；修正前请勿重启",
          "warning",
        );
      } else {
        dismissToast(toastID);
      }
    } catch (error) {
      if (
        !restartConfirmed &&
        error instanceof ApiError &&
        error.code === "restart_required"
      ) {
        dismissToast(toastID);
        setRawConfigText(text);
        setRestartRetry({ target: "interface", text });
        return;
      }
      if (!(await handleRevisionConflict(error, toastID))) {
        const latest = mutationStateMayBeUncertain(error)
          ? await reconcileAfterMutationFailure()
          : undefined;
        updateToast(
          toastID,
          `${error instanceof Error ? error.message : "Interface 导入失败"}${
            latest ? "；已重新同步后端当前状态" : ""
          }`,
          "error",
          6_000,
        );
      }
    } finally {
      setImportPending(false);
    }
  };

  const submitPeerImport = async (
    text: string,
    restartConfirmed = false,
  ) => {
    if (interfaceID === undefined || !config) return;
    setImportPending(true);
    const toastID = showToast("正在校验并导入 Peer…", "loading", 0);
    try {
      const saved = await importPeerConfig(
        interfaceID,
        config.revision,
        text,
        restartConfirmed,
      );
      configRevisionRef.current = saved.revision;
      setConfig(saved);
      setImportTarget(null);
      setPeerImportText("");
      setRestartRetry(null);
      await Promise.all([
        refreshIPPlan(),
        refreshRuntime(saved.revision),
      ]);
      dismissToast(toastID);
    } catch (error) {
      if (
        !restartConfirmed &&
        error instanceof ApiError &&
        error.code === "restart_required"
      ) {
        dismissToast(toastID);
        setPeerImportText(text);
        setRestartRetry({ target: "peer", text });
        return;
      }
      if (!(await handleRevisionConflict(error, toastID))) {
        const latest = mutationStateMayBeUncertain(error)
          ? await reconcileAfterMutationFailure()
          : undefined;
        updateToast(
          toastID,
          `${error instanceof Error ? error.message : "Peer 导入失败"}${
            latest ? "；已重新同步后端当前状态" : ""
          }`,
          "error",
          6_000,
        );
      }
    } finally {
      setImportPending(false);
    }
  };

  if (loading || (!loadError && config?.id !== interfaceID)) {
    return (
      <div className="page">
        <section className="content-state">
          <span className="spinner" />
          <h2>正在读取 Interface</h2>
        </section>
      </div>
    );
  }

  if (loadError) {
    return (
      <div className="page">
        <section className="content-state is-error">
          <Icon name="alert" />
          <h2>无法打开 Interface</h2>
          <p>{loadError}</p>
          <div className="state-actions">
            <Link className="button" to="/">
              <Icon name="arrow-left" />
              返回列表
            </Link>
            {!invalidID && (
              <button className="button" type="button" onClick={() => void load()}>
                <Icon name="refresh" />
                重试
              </button>
            )}
          </div>
        </section>
      </div>
    );
  }

  return (
    <div className="page editor-page">
      <section className="interface-overview-card">
        <header className="interface-overview-header">
          <div className="interface-overview-title">
            <span className="section-icon">
              <Icon name="network" />
            </span>
            <div>
              <div className="interface-title-line">
                <h1>{config?.filename}</h1>
                <span
                  className={`interface-runtime-badge ${
                    fileOnlyRuntime
                      ? "is-file-only"
                      : runtimeRunning === undefined
                        ? "is-unknown"
                        : runtimeRunning
                          ? "is-running"
                          : "is-stopped"
                  }`}
                >
                  {fileOnlyRuntime
                    ? "仅文件模式"
                    : runtimeRunning === undefined
                      ? "状态未知"
                      : runtimeRunning
                        ? "运行中"
                        : "已停用"}
                </span>
              </div>
            </div>
          </div>

          <div className="interface-overview-actions">
            <div
              className="runtime-action-group"
              role="group"
              aria-label="Interface 运行操作"
            >
              <button
                className="runtime-action-button is-start"
                type="button"
                disabled={
                  runtimePending ||
                  runtimeRunning === undefined ||
                  runtimeRunning
                }
                onClick={() => setRuntimeConfirmation("start")}
              >
                {runtimePendingAction === "start" ? (
                  <span className="spinner is-small" />
                ) : (
                  <Icon name="power" />
                )}
                启动
              </button>
              <button
                className="runtime-action-button is-stop"
                type="button"
                disabled={
                  runtimePending ||
                  runtimeRunning === undefined ||
                  !runtimeRunning
                }
                onClick={() => setRuntimeConfirmation("stop")}
              >
                {runtimePendingAction === "stop" ? (
                  <span className="spinner is-small" />
                ) : (
                  <Icon name="stop" />
                )}
                停止
              </button>
              <button
                className="runtime-action-button is-restart"
                type="button"
                disabled={
                  runtimePending ||
                  runtimeRunning === undefined ||
                  !runtimeRunning
                }
                onClick={() => setRuntimeConfirmation("restart")}
              >
                {runtimePendingAction === "restart" ? (
                  <span className="spinner is-small" />
                ) : (
                  <Icon name="refresh" />
                )}
                重启
              </button>
            </div>
            <button
              className="button is-primary is-compact"
              type="button"
              onClick={() => setInterfaceModalOpen(true)}
            >
              <Icon name="edit" />
              编辑
            </button>
            <div className="action-menu-anchor" data-action-menu>
              <button
                className="icon-button action-menu-trigger"
                type="button"
                aria-label="更多 Interface 操作"
                aria-haspopup="menu"
                aria-expanded={actionMenu === "interface"}
                onClick={() =>
                  setActionMenu((current) =>
                    current === "interface" ? null : "interface",
                  )
                }
              >
                <Icon name="more-horizontal" />
              </button>
              {actionMenu === "interface" && (
                <div className="action-menu" role="menu">
                  <button
                    type="button"
                    role="menuitem"
                    onClick={() => {
                      setActionMenu(null);
                      setRenameModalOpen(true);
                    }}
                  >
                    <Icon name="edit" />
                    重命名
                  </button>
                  <button
                    type="button"
                    role="menuitem"
                    onClick={() => {
                      setActionMenu(null);
                      void openRawConfigEditor();
                    }}
                  >
                    <Icon name="edit" />
                    编辑原始配置
                  </button>
                  <button
                    type="button"
                    role="menuitem"
                    onClick={() => {
                      setActionMenu(null);
                      void openInterfacePreview();
                    }}
                  >
                    <Icon name="download" />
                    导出配置
                  </button>
                </div>
              )}
            </div>
          </div>
        </header>

        <dl className="interface-fact-grid" aria-live="polite">
          <div className="is-public-key">
            <dt>公钥</dt>
            <dd>
              <code title={interfacePublicKey}>
                {publicKeyPending
                  ? "正在计算…"
                  : interfacePublicKey || "暂时无法计算"}
              </code>
            </dd>
          </div>
          <div className="is-address">
            <dt>地址</dt>
            <dd>
              <ConstraintAwareIPList
                values={config?.address ?? []}
                constraints={routeConstraints}
                interfaceAddresses
              />
            </dd>
          </div>
          <div className="is-port">
            <dt>监听端口</dt>
            <dd>{config?.listenPort ?? "自动"}</dd>
          </div>
          <div className="is-mtu">
            <dt>MTU</dt>
            <dd>{config?.mtu ?? "自动"}</dd>
          </div>
          <div className="is-dns">
            <dt>DNS</dt>
            <dd>{displayList(config?.dns ?? [])}</dd>
          </div>
          <div className="is-endpoint">
            <dt>客户端 Endpoint</dt>
            <dd>{config?.clientEndpoint || "未配置"}</dd>
          </div>
          <div className="is-routes">
            <dt>路由范围约束</dt>
            <dd>{displayList(config?.clientAllowedIPs ?? [])}</dd>
          </div>
        </dl>
        <dl
          className="interface-runtime-summary"
          aria-label="Interface 流量状态"
        >
          <div>
            <dt>累计接收</dt>
            <dd>
              <strong>
                {interfaceRuntimeSummary.available
                  ? formatBytes(interfaceRuntimeSummary.receivedBytes)
                  : "暂不可用"}
              </strong>
              <small>
                当前 {interfaceRuntimeSummary.available
                  ? formatRate(interfaceRuntimeSummary.receiveBytesPerSecond)
                  : "—"}
              </small>
            </dd>
          </div>
          <div>
            <dt>累计发送</dt>
            <dd>
              <strong>
                {interfaceRuntimeSummary.available
                  ? formatBytes(interfaceRuntimeSummary.sentBytes)
                  : "暂不可用"}
              </strong>
              <small>
                当前 {interfaceRuntimeSummary.available
                  ? formatRate(interfaceRuntimeSummary.sendBytesPerSecond)
                  : "—"}
              </small>
            </dd>
          </div>
        </dl>
        <div className="interface-traffic-chart">
          <TrafficChart
            points={interfaceTraffic}
            nowMs={clockNow}
            currentRateAvailable={runtimeMetricsAvailable}
          />
        </div>
      </section>

      {scopedValidationErrors.interfaceErrors.length > 0 && (
        <section className="interface-validation-warning" aria-live="polite">
          <Icon name="alert" />
          <div>
            <strong>
              配置有误，Interface
              {runtimeRunning === undefined
                ? " 运行状态未知"
                : runtimeRunning
                  ? " 当前仍在运行"
                  : " 保持停用"}
            </strong>
            <ul>
              {scopedValidationErrors.interfaceErrors.map((message, index) => (
                <li key={`${index}:${message}`}>{message}</li>
              ))}
            </ul>
          </div>
          <button
            className="button is-quiet is-compact"
            type="button"
            onClick={() => void openRawConfigEditor()}
          >
            <Icon name="edit" />
            编辑原始配置
          </button>
        </section>
      )}

      <section className="peers-section">
        <header className="peers-section-header">
          <div className="peers-title-summary">
            <h2>Peers</h2>
            <span className="peer-count is-total">
              总数 <strong>{interfaceRuntimeSummary.totalPeers}</strong>
            </span>
            <span
              className={`peer-count is-online ${
                onlinePeerCount === undefined ? "is-unknown" : ""
              }`.trim()}
              title={
                onlinePeerCount === undefined
                  ? "运行状态暂不可用"
                  : "最近 3 分钟有握手"
              }
            >
              在线 <strong>{onlinePeerCount ?? "—"}</strong>
            </span>
            <span
              className={`peer-count is-offline ${
                offlinePeerCount === undefined ? "is-unknown" : ""
              }`.trim()}
              title={
                offlinePeerCount === undefined ? "运行状态暂不可用" : undefined
              }
            >
              离线 <strong>{offlinePeerCount ?? "—"}</strong>
            </span>
          </div>
          <div className="peers-heading-actions">
            <button
              className="button is-primary is-compact"
              type="button"
              onClick={() => setEditingPeer("new")}
            >
              <Icon name="plus" />
              添加 Peer
            </button>
            <div className="action-menu-anchor" data-action-menu>
              <button
                className="icon-button action-menu-trigger"
                type="button"
                aria-label="更多 Peer 操作"
                aria-haspopup="menu"
                aria-expanded={actionMenu === "peers"}
                onClick={() =>
                  setActionMenu((current) =>
                    current === "peers" ? null : "peers",
                  )
                }
              >
                <Icon name="more-horizontal" />
              </button>
              {actionMenu === "peers" && (
                <div className="action-menu" role="menu">
                  <button
                    type="button"
                    role="menuitem"
                    onClick={() => {
                      setActionMenu(null);
                      setImportTarget("peer");
                    }}
                  >
                    <Icon name="upload" />
                    导入 Peer
                  </button>
                </div>
              )}
            </div>
          </div>
        </header>

        {config?.peers.length ? (
            <div className="peer-card-grid">
              {displayedPeerEntries.map(({ peer, originalIndex: peerIndex }) => {
                const status = runtimeByPeer.get(peer.publicKey);
                const peerValidationErrors =
                  scopedValidationErrors.peerErrors[peerIndex] ?? [];
                const available = runtimeMetricsAvailable && status?.available;
                const rate = windowedRates.get(peer.publicKey) ?? {
                  receiveBytesPerSecond:
                    status?.receiveBytesPerSecond ?? 0,
                  sendBytesPerSecond: status?.sendBytesPerSecond ?? 0,
                };
                return (
                  <article
                    className={`peer-card ${
                      peerValidationErrors.length ? "has-validation" : ""
                    }`.trim()}
                    key={`${peerIndex}:${peer.publicKey}`}
                  >
                    <div className="peer-card-body">
                      <button
                        className="peer-card-edit-target"
                        type="button"
                        aria-label={`编辑 ${peer.name}`}
                        onClick={() => setEditingPeer(peer)}
                      />
                      <div className="peer-card-content">
                        <div className="peer-card-heading">
                          <div className="peer-card-name">
                            <span
                              className={`peer-runtime-dot ${
                                !available
                                  ? ""
                                  : status?.active
                                    ? "is-active"
                                    : "is-offline"
                              }`}
                            />
                            <h3 title={peer.name}>{peer.name}</h3>
                          </div>
                          <div className="peer-card-heading-actions">
                            <span
                              className="peer-card-handshake"
                              title={handshakeTitle(status?.lastHandshakeAt)}
                            >
                              <Icon name="clock" />
                              <span className="peer-card-handshake-time">
                                {available
                                  ? formatPeerHandshakeElapsed(
                                      status?.lastHandshakeAt,
                                      clockNow,
                                    )
                                  : "—"}
                              </span>
                            </span>
                          </div>
                        </div>

                        <div
                          className="peer-card-public-key"
                          title={peer.publicKey}
                        >
                          <span>公钥</span>
                          <MiddleEllipsisKey value={peer.publicKey} />
                          {!peer.privateKey.trim() && (
                            <small
                              className="peer-card-private-key-note"
                              title="未保存该 Peer 的私钥"
                            >
                              无私钥
                            </small>
                          )}
                        </div>

                        <div
                          className={`peer-card-allowed-ips ${
                            peerValidationErrors.length ? "has-validation" : ""
                          }`.trim()}
                          title={
                            peerValidationErrors.length
                              ? peerValidationErrors.join("\n")
                              : displayList(peer.allowedIPs)
                          }
                        >
                          <span>IPs</span>
                          <strong>
                            <ConstraintAwareIPList
                              values={peer.allowedIPs}
                              constraints={routeConstraints}
                            />
                          </strong>
                          {peerValidationErrors.length > 0 && (
                            <button
                              className="peer-ip-repair"
                              type="button"
                              aria-label={`修改 ${peer.name} IPs`}
                              onClick={() => {
                                void openRawConfigEditor();
                              }}
                            >
                              修改
                            </button>
                          )}
                        </div>

                        <div className="peer-card-runtime-grid">
                          <button
                            className="peer-traffic-preview"
                            type="button"
                            aria-label={`查看 ${peer.name} 流量大图`}
                            onClick={() => setTrafficPeer(peer)}
                          >
                            <TrafficChart
                              compact
                              points={peerTraffic.get(peer.publicKey) ?? []}
                              nowMs={clockNow}
                              currentRateAvailable={runtimeMetricsAvailable}
                            />
                          </button>
                          <div className="peer-card-runtime-details">
                            <span className="is-receive">
                              <strong>
                                ↓ {available
                                  ? formatBytes(status?.receivedBytes ?? 0)
                                  : "—"}
                              </strong>
                              <small>
                                {available
                                  ? formatRate(rate.receiveBytesPerSecond)
                                  : "—"}
                              </small>
                            </span>
                            <span className="is-send">
                              <strong>
                                ↑ {available
                                  ? formatBytes(status?.sentBytes ?? 0)
                                  : "—"}
                              </strong>
                              <small>
                                {available
                                  ? formatRate(rate.sendBytesPerSecond)
                                  : "—"}
                              </small>
                            </span>
                            <div
                              className={`peer-card-endpoint ${
                                status?.currentEndpoint ? "" : "is-unavailable"
                              }`.trim()}
                              title={status?.currentEndpoint || undefined}
                            >
                              <span aria-hidden="true">↪</span>
                              <strong>
                                {available
                                  ? status?.currentEndpoint || "未观测到"
                                  : "暂不可用"}
                              </strong>
                            </div>
                            <button
                              className="peer-card-client-action"
                              type="button"
                              title="客户端配置"
                              aria-label={`查看 ${peer.name} 客户端配置`}
                              onClick={() => void openClientPreview(peer)}
                            >
                              <Icon name="terminal" />
                              <span>客户端</span>
                            </button>
                          </div>
                        </div>
                      </div>
                    </div>
                  </article>
                );
              })}
            </div>
          ) : (
            <div className="peer-empty">
              <Icon name="users" />
              <p>暂无 Peer</p>
            </div>
          )}
      </section>

      {runtimeConfirmation && config && (
        <Modal
          title={`确认${
            runtimeConfirmation === "start"
              ? "启动"
              : runtimeConfirmation === "stop"
                ? "停止"
                : "重启"
          } ${config.filename}`}
          variant="display"
          onClose={() => setRuntimeConfirmation(null)}
          className="is-compact runtime-confirmation-dialog"
        >
          <div
            className={`runtime-confirmation-note is-${runtimeConfirmation}`}
          >
            <Icon
              name={
                runtimeConfirmation === "restart"
                  ? "refresh"
                  : runtimeConfirmation === "stop"
                    ? "stop"
                    : "power"
              }
            />
            <div>
              <strong>
                {runtimeConfirmation === "start"
                  ? "使用当前配置启动 Interface"
                  : runtimeConfirmation === "stop"
                    ? "所有 Peer 连接将中断，配置文件会保留"
                    : "所有 Peer 连接将短暂中断"}
              </strong>
            </div>
          </div>
          <footer className="modal-actions">
            <button
              className="button"
              type="button"
              onClick={() => setRuntimeConfirmation(null)}
            >
              取消
            </button>
            <button
              className={`button ${
                runtimeConfirmation === "stop" ? "is-danger" : "is-primary"
              }`}
              type="button"
              autoFocus
              onClick={() => void changeRuntime(runtimeConfirmation)}
            >
              {runtimeConfirmation === "start"
                ? "确认启动"
                : runtimeConfirmation === "stop"
                  ? "确认停止"
                  : "确认重启"}
            </button>
          </footer>
        </Modal>
      )}

      {interfaceModalOpen && config && (
        <InterfaceModal
          initial={config}
          pending={savePending}
          running={runtimeRunning === true}
          onClose={() => setInterfaceModalOpen(false)}
          onSubmit={(interfaceInput, _name, restartConfirmed) =>
            void save(interfaceInput, restartConfirmed)
          }
        />
      )}

      {renameModalOpen && config && (
        <InterfaceRenameModal
          currentName={config.id}
          pending={renamePending}
          running={runtimeRunning === true}
          onClose={() => setRenameModalOpen(false)}
          onSubmit={(name) => void rename(name)}
        />
      )}

      {editingPeer && (
        <PeerModal
          initial={editingPeer === "new" ? undefined : peerToInput(editingPeer)}
          pending={peerPending}
          ipPlan={ipPlan}
          currentInterface={config!}
          running={runtimeRunning === true}
          onClose={() => setEditingPeer(null)}
          onDelete={
            editingPeer === "new"
              ? undefined
              : () => {
                  setEditingPeer(null);
                  setDeletingPeer(editingPeer);
                }
          }
          onSubmit={(peerInput, restartConfirmed) =>
            void submitPeer(peerInput, restartConfirmed)
          }
        />
      )}

      {trafficPeer && (
        <Modal
          title={`${trafficPeer.name} · 流量`}
          variant="display"
          onClose={() => setTrafficPeer(null)}
          className="is-traffic"
        >
          <div className="peer-traffic-modal-body">
            <TrafficChart
              points={peerTraffic.get(trafficPeer.publicKey) ?? []}
              nowMs={clockNow}
              currentRateAvailable={runtimeMetricsAvailable}
            />
          </div>
          <footer className="modal-actions">
            <button
              className="button is-primary"
              type="button"
              onClick={() => setTrafficPeer(null)}
            >
              关闭
            </button>
          </footer>
        </Modal>
      )}

      {configPreview && (
        <ConfigTextModal
          title={configPreview.title}
          description={configPreview.description}
          mode="preview"
          value={configPreview.text}
          onClose={() => setConfigPreview(null)}
        />
      )}

      {importTarget === "interface" && !restartRetry && (
        <ConfigTextModal
          title={`编辑 ${config?.filename} 原始配置`}
          description="需要重建运行状态的修改，会在确认后自动完成停止、保存和启动。"
          mode="import"
          value={rawConfigText}
          pending={importPending}
          submitLabel="保存配置文件"
          onClose={() => setImportTarget(null)}
          onSubmit={(text) => void submitInterfaceImport(text)}
        />
      )}

      {importTarget === "peer" && !restartRetry && (
        <ConfigTextModal
          title="导入 Peer"
          description="支持一次粘贴多个 [Peer] 段；全部校验通过后才会统一导入。"
          mode="import"
          value={peerImportText}
          pending={importPending}
          submitLabel="校验并导入全部"
          placeholder={
            "[Peer]\n# Name = Peer 1\nPublicKey = …\nAllowedIPs = 10.20.0.2/32\n\n[Peer]\n# Name = Peer 2\nPublicKey = …\nAllowedIPs = 10.20.0.3/32"
          }
          onClose={() => {
            setImportTarget(null);
            setPeerImportText("");
          }}
          onSubmit={(text) => void submitPeerImport(text)}
        />
      )}

      {restartRetry && (
        <Modal
          title="保存并重启 Interface？"
          variant="input"
          closeDisabled={restartRetryPending}
          onClose={() => setRestartRetry(null)}
          className="is-compact runtime-confirmation-dialog"
        >
          <div className="runtime-confirmation-note is-restart">
            <Icon name="alert" />
            <div>
              <strong>这份配置需要重建 Interface</strong>
              <p>保存时会短暂停止 Interface，写入新配置后立即重新启动。</p>
            </div>
          </div>
          <footer className="modal-actions">
            <button
              className="button"
              type="button"
              disabled={restartRetryPending}
              onClick={() => setRestartRetry(null)}
            >
              返回修改
            </button>
            <button
              className="button is-primary"
              type="button"
              disabled={restartRetryPending}
              autoFocus
              onClick={() => {
                if (restartRetry.target === "interface") {
                  void submitInterfaceImport(restartRetry.text, true);
                } else if (restartRetry.target === "peer") {
                  void submitPeerImport(restartRetry.text, true);
                } else if (restartRetry.target === "interface-form") {
                  void save(restartRetry.input, true);
                } else {
                  void submitPeer(restartRetry.input, true);
                }
              }}
            >
              {restartRetryPending && <span className="spinner is-small" />}
              {restartRetryPending ? "保存并重启中" : "保存并重启"}
            </button>
          </footer>
        </Modal>
      )}

      {deletingPeer && (
        <Modal
          title={`删除 ${deletingPeer.name}？`}
          description="将从当前 Interface 移除此 Peer。"
          variant="display"
          closeDisabled={peerDeletePending}
          onClose={() => setDeletingPeer(null)}
          className="is-compact"
        >
          {runtimeRunning === true &&
            config &&
            peerDeletionNeedsRestart(config, deletingPeer.publicKey) && (
              <div className="danger-note">
                <Icon name="alert" />
                <p>
                  该 Peer 是唯一默认路由；删除时会短暂停止并重新启动 Interface。
                </p>
              </div>
            )}
          <footer className="modal-actions">
            <button
              className="button"
              type="button"
              disabled={peerDeletePending}
              onClick={() => setDeletingPeer(null)}
            >
              取消
            </button>
            <button
              className="button is-danger"
              type="button"
              disabled={peerDeletePending}
              onClick={() => void confirmPeerDelete()}
            >
              {peerDeletePending && <span className="spinner is-small" />}
              {peerDeletePending ? "删除中" : "确认删除"}
            </button>
          </footer>
        </Modal>
      )}
    </div>
  );
}
