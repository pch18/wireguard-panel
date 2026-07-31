import {
  useCallback,
  useEffect,
  useMemo,
  useState,
  type FormEvent,
} from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { ApiError } from "../app/apiClient";
import PeerModal from "../features/wireguard/PeerModal";
import PeerStatusModal, {
  formatRate,
} from "../features/wireguard/PeerStatusModal";
import {
  blankInterface,
  createInterface,
  createPeer,
  deletePeer,
  downloadClientConfig,
  getInterface,
  getIPPlan,
  getRuntimeStatus,
  interfaceToInput,
  linesToValues,
  peerToInput,
  updateInterface,
  updatePeer,
  valuesToLines,
  type InterfaceInput,
  type InterfaceRuntimeStatus,
  type IPPlan,
  type PeerInput,
  type WireGuardInterface,
  type WireGuardPeer,
} from "../features/wireguard/api";
import Icon from "../ui/Icon";
import Modal from "../ui/Modal";
import { useToast } from "../ui/Toast";

type TextLists = {
  address: string;
  dns: string;
  clientDNS: string;
  clientAllowedIPs: string;
  preUp: string;
  postUp: string;
  preDown: string;
  postDown: string;
};

const blankLists = (): TextLists => ({
  address: "",
  dns: "",
  clientDNS: "",
  clientAllowedIPs: "",
  preUp: "",
  postUp: "",
  preDown: "",
  postDown: "",
});

const listsFromInterface = (config: WireGuardInterface): TextLists => ({
  address: valuesToLines(config.address),
  dns: valuesToLines(config.dns),
  clientDNS: valuesToLines(config.clientDNS),
  clientAllowedIPs: valuesToLines(config.clientAllowedIPs),
  preUp: valuesToLines(config.preUp),
  postUp: valuesToLines(config.postUp),
  preDown: valuesToLines(config.preDown),
  postDown: valuesToLines(config.postDown),
});

function optionalNumber(value: string) {
  if (value.trim() === "") return undefined;
  return Number(value);
}

function shortKey(value: string) {
  if (value.length <= 24) return value;
  return `${value.slice(0, 13)}…${value.slice(-8)}`;
}

export default function InterfaceEditorPage() {
  const { id: idParam } = useParams();
  const navigate = useNavigate();
  const { showToast, updateToast } = useToast();
  const creating = idParam === "new";
  const interfaceID = creating ? undefined : Number(idParam);
  const invalidID =
    !creating && (!Number.isInteger(interfaceID) || interfaceID! < 0);

  const [config, setConfig] = useState<WireGuardInterface | null>(null);
  const [input, setInput] = useState<InterfaceInput>(blankInterface());
  const [lists, setLists] = useState<TextLists>(blankLists());
  const [ipPlan, setIPPlan] = useState<IPPlan>();
  const [runtime, setRuntime] = useState<InterfaceRuntimeStatus>();
  const [loading, setLoading] = useState(!creating && !invalidID);
  const [loadError, setLoadError] = useState(
    invalidID ? "Interface ID 无效" : "",
  );
  const [savePending, setSavePending] = useState(false);
  const [showPrivateKey, setShowPrivateKey] = useState(false);
  const [editingPeer, setEditingPeer] = useState<
    WireGuardPeer | "new" | null
  >(null);
  const [peerPending, setPeerPending] = useState(false);
  const [deletingPeer, setDeletingPeer] = useState<WireGuardPeer | null>(null);
  const [peerDeletePending, setPeerDeletePending] = useState(false);
  const [statusPeer, setStatusPeer] = useState<WireGuardPeer | null>(null);

  const load = useCallback(
    async (syncForm = true) => {
      if (interfaceID === undefined || invalidID) return;
      setLoading(true);
      setLoadError("");
      try {
        const [loaded, plan] = await Promise.all([
          getInterface(interfaceID),
          getIPPlan(interfaceID),
        ]);
        setConfig(loaded);
        setIPPlan(plan);
        if (syncForm) {
          setInput(interfaceToInput(loaded));
          setLists(listsFromInterface(loaded));
        }
      } catch (error) {
        const message =
          error instanceof Error ? error.message : "Interface 加载失败";
        setLoadError(message);
        showToast(message, "error");
      } finally {
        setLoading(false);
      }
    },
    [interfaceID, invalidID, showToast],
  );

  useEffect(() => {
    if (creating) {
      setConfig(null);
      setInput(blankInterface());
      setLists(blankLists());
      setIPPlan(undefined);
      setRuntime(undefined);
      setLoading(false);
      setLoadError("");
      return;
    }
    void load();
  }, [creating, load]);

  useEffect(() => {
    if (interfaceID === undefined || invalidID) return;
    let stopped = false;
    let polling = false;
    const poll = async () => {
      if (polling) return;
      polling = true;
      try {
        const next = await getRuntimeStatus(interfaceID);
        if (!stopped) setRuntime(next);
      } catch {
        if (!stopped) {
          setRuntime({
            interfaceID,
            interfaceName: `wg${interfaceID}`,
            collectorAvailable: false,
            message: "运行状态暂时无法读取",
            peers: [],
          });
        }
      } finally {
        polling = false;
      }
    };
    void poll();
    const timer = window.setInterval(() => void poll(), 2_500);
    return () => {
      stopped = true;
      window.clearInterval(timer);
    };
  }, [interfaceID, invalidID]);

  const runtimeByPeer = useMemo(
    () => new Map(runtime?.peers.map((peer) => [peer.peerID, peer]) ?? []),
    [runtime],
  );

  const prepareInput = (): InterfaceInput => ({
    ...input,
    address: linesToValues(lists.address),
    dns: linesToValues(lists.dns),
    clientDNS: linesToValues(lists.clientDNS),
    clientAllowedIPs: linesToValues(lists.clientAllowedIPs),
    preUp: linesToValues(lists.preUp),
    postUp: linesToValues(lists.postUp),
    preDown: linesToValues(lists.preDown),
    postDown: linesToValues(lists.postDown),
  });

  const handleRevisionConflict = async (
    error: unknown,
    toastID: number,
  ) => {
    if (!(error instanceof ApiError) || error.status !== 412) return false;
    updateToast(
      toastID,
      "配置已被另一个客户端修改，已载入最新版本；请检查后重试。",
      "warning",
      6_000,
    );
    await load(false);
    return true;
  };

  const refreshIPPlan = async () => {
    if (interfaceID === undefined) return;
    try {
      setIPPlan(await getIPPlan(interfaceID));
    } catch {
      // 主操作已经成功，不用第二条 Toast 干扰用户。
    }
  };

  const save = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setSavePending(true);
    const toastID = showToast(
      creating ? "正在创建 Interface…" : "正在保存配置…",
      "loading",
      0,
    );
    try {
      const saved =
        interfaceID === undefined
          ? await createInterface(prepareInput())
          : await updateInterface(interfaceID, config!.revision, prepareInput());
      setConfig(saved);
      setInput(interfaceToInput(saved));
      setLists(listsFromInterface(saved));
      updateToast(
        toastID,
        interfaceID === undefined
          ? `${saved.filename} 已创建`
          : `${saved.filename} 已保存`,
        "success",
      );
      if (interfaceID === undefined) {
        navigate(`/interfaces/${saved.id}`, { replace: true });
      } else {
        await refreshIPPlan();
      }
    } catch (error) {
      if (!(await handleRevisionConflict(error, toastID))) {
        updateToast(
          toastID,
          error instanceof Error ? error.message : "Interface 保存失败",
          "error",
        );
      }
    } finally {
      setSavePending(false);
    }
  };

  const submitPeer = async (peerInput: PeerInput) => {
    if (interfaceID === undefined || !config) return;
    setPeerPending(true);
    const existingPeerID =
      editingPeer && editingPeer !== "new" ? editingPeer.id : undefined;
    const toastID = showToast(
      existingPeerID ? "正在保存 Peer…" : "正在添加 Peer…",
      "loading",
      0,
    );
    try {
      const saved = existingPeerID
        ? await updatePeer(
            interfaceID,
            existingPeerID,
            config.revision,
            peerInput,
          )
        : await createPeer(interfaceID, config.revision, peerInput);
      setConfig(saved);
      setInput(interfaceToInput(saved));
      setLists(listsFromInterface(saved));
      updateToast(
        toastID,
        existingPeerID ? "Peer 已保存" : "Peer 已添加",
        "success",
      );
      setEditingPeer(null);
      await refreshIPPlan();
    } catch (error) {
      if (!(await handleRevisionConflict(error, toastID))) {
        updateToast(
          toastID,
          error instanceof Error ? error.message : "Peer 保存失败",
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
        deletingPeer.id,
        config.revision,
      );
      setConfig(saved);
      setInput(interfaceToInput(saved));
      setLists(listsFromInterface(saved));
      updateToast(toastID, "Peer 已删除", "success");
      setDeletingPeer(null);
      await refreshIPPlan();
    } catch (error) {
      if (!(await handleRevisionConflict(error, toastID))) {
        updateToast(
          toastID,
          error instanceof Error ? error.message : "Peer 删除失败",
          "error",
        );
      }
    } finally {
      setPeerDeletePending(false);
    }
  };

  const downloadPeerConfig = async (peer: WireGuardPeer) => {
    if (interfaceID === undefined) return;
    const toastID = showToast("正在生成客户端配置…", "loading", 0);
    try {
      const filename = await downloadClientConfig(interfaceID, peer.id);
      updateToast(toastID, `${filename} 已下载`, "success");
    } catch (error) {
      updateToast(
        toastID,
        error instanceof Error ? error.message : "客户端配置生成失败",
        "error",
        6_000,
      );
    }
  };

  if (loading) {
    return (
      <div className="page">
        <section className="content-state">
          <span className="spinner" />
          <h2>正在读取 Interface</h2>
          <p>解析原生 WireGuard 配置文件…</p>
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
      <header className="editor-heading">
        <div className="editor-heading-main">
          <Link className="icon-button" to="/" aria-label="返回 Interface 列表">
            <Icon name="arrow-left" />
          </Link>
          <div>
            <p className="eyebrow">
              {creating ? "NEW INTERFACE" : config?.filename}
            </p>
            <h1>{creating ? "新建 Interface" : config?.name}</h1>
            <p>
              {creating
                ? "保存后系统将自动分配下一个 wg<ID>.conf。"
                : `ID ${config?.id} · ${config?.peers.length ?? 0} 个 Peer`}
            </p>
          </div>
        </div>
        {!creating && <span className="native-badge">原生配置</span>}
      </header>

      <form className="interface-form" onSubmit={save}>
        <section className="form-card">
          <header className="form-card-header">
            <span className="section-icon"><Icon name="network" /></span>
            <div>
              <h2>基础配置</h2>
              <p>Interface 的身份、地址与监听设置。</p>
            </div>
          </header>
          <div className="form-grid">
            <div className="field">
              <label htmlFor="interface-name">
                名称 <span aria-hidden="true">*</span>
              </label>
              <input
                id="interface-name"
                value={input.name}
                required
                maxLength={128}
                placeholder="例如 Tokyo Gateway"
                onChange={(event) =>
                  setInput((current) => ({
                    ...current,
                    name: event.target.value,
                  }))
                }
              />
              <small>写入 # Name = … 注释。</small>
            </div>
            <div className="field">
              <label htmlFor="interface-listen-port">ListenPort</label>
              <input
                id="interface-listen-port"
                type="number"
                min="0"
                max="65535"
                value={input.listenPort ?? ""}
                placeholder="留空则自动选择"
                onChange={(event) =>
                  setInput((current) => ({
                    ...current,
                    listenPort: optionalNumber(event.target.value),
                  }))
                }
              />
            </div>
            <div className="field is-full">
              <label htmlFor="interface-private-key">
                PrivateKey <span aria-hidden="true">*</span>
              </label>
              <div className="secret-input">
                <input
                  id="interface-private-key"
                  type={showPrivateKey ? "text" : "password"}
                  value={input.privateKey}
                  required
                  autoComplete="off"
                  placeholder="Interface 的 32 字节 Base64 私钥"
                  onChange={(event) =>
                    setInput((current) => ({
                      ...current,
                      privateKey: event.target.value,
                    }))
                  }
                />
                <button
                  className="icon-button"
                  type="button"
                  aria-label={showPrivateKey ? "隐藏私钥" : "显示私钥"}
                  onClick={() => setShowPrivateKey((shown) => !shown)}
                >
                  <Icon name={showPrivateKey ? "eye-off" : "eye"} />
                </button>
              </div>
            </div>
            <div className="field">
              <label htmlFor="interface-address">Address</label>
              <textarea
                id="interface-address"
                value={lists.address}
                rows={4}
                placeholder={"10.20.0.1/24\nfd20::1/64"}
                onChange={(event) =>
                  setLists((current) => ({
                    ...current,
                    address: event.target.value,
                  }))
                }
              />
              <small>它同时是 Peer 地址规划的子网来源。</small>
            </div>
            <div className="field">
              <label htmlFor="interface-dns">DNS</label>
              <textarea
                id="interface-dns"
                value={lists.dns}
                rows={4}
                placeholder={"1.1.1.1\nresolver.example.com"}
                onChange={(event) =>
                  setLists((current) => ({
                    ...current,
                    dns: event.target.value,
                  }))
                }
              />
              <small>wg-quick 在服务端应用的 DNS 字段。</small>
            </div>
          </div>
        </section>

        <section className="form-card">
          <header className="form-card-header">
            <span className="section-icon"><Icon name="download" /></span>
            <div>
              <h2>客户端配置模板</h2>
              <p>用于直接生成每个 Peer 可运行的 .conf，不创建额外文件。</p>
            </div>
          </header>
          <div className="form-grid">
            <div className="field is-full">
              <label htmlFor="client-endpoint">服务器公开 Endpoint</label>
              <input
                id="client-endpoint"
                value={input.clientEndpoint}
                placeholder="vpn.example.com:51820"
                onChange={(event) =>
                  setInput((current) => ({
                    ...current,
                    clientEndpoint: event.target.value,
                  }))
                }
              />
              <small>客户端连接此服务器时使用的公网域名或 IP 与端口。</small>
            </div>
            <div className="field">
              <label htmlFor="client-dns">客户端 DNS</label>
              <textarea
                id="client-dns"
                value={lists.clientDNS}
                rows={3}
                placeholder={"1.1.1.1\n8.8.8.8"}
                onChange={(event) =>
                  setLists((current) => ({
                    ...current,
                    clientDNS: event.target.value,
                  }))
                }
              />
            </div>
            <div className="field">
              <label htmlFor="client-allowed-ips">客户端 AllowedIPs</label>
              <textarea
                id="client-allowed-ips"
                value={lists.clientAllowedIPs}
                rows={3}
                placeholder={"0.0.0.0/0\n::/0"}
                onChange={(event) =>
                  setLists((current) => ({
                    ...current,
                    clientAllowedIPs: event.target.value,
                  }))
                }
              />
              <small>留空时默认使用 Interface 的网段。</small>
            </div>
            <div className="field">
              <label htmlFor="client-keepalive">
                客户端 PersistentKeepalive
              </label>
              <input
                id="client-keepalive"
                type="number"
                min="0"
                max="65535"
                value={input.clientPersistentKeepalive ?? ""}
                placeholder="25"
                onChange={(event) =>
                  setInput((current) => ({
                    ...current,
                    clientPersistentKeepalive: optionalNumber(event.target.value),
                  }))
                }
              />
            </div>
          </div>
        </section>

        <details className="form-card advanced-card">
          <summary>
            <span className="section-icon"><Icon name="settings" /></span>
            <span>
              <strong>高级路由设置</strong>
              <small>MTU、路由表、FwMark 与 SaveConfig</small>
            </span>
            <Icon name="chevron-down" />
          </summary>
          <div className="form-grid advanced-body">
            <div className="field">
              <label htmlFor="interface-mtu">MTU</label>
              <input
                id="interface-mtu"
                type="number"
                min="1"
                max="65535"
                value={input.mtu ?? ""}
                placeholder="自动推导"
                onChange={(event) =>
                  setInput((current) => ({
                    ...current,
                    mtu: optionalNumber(event.target.value),
                  }))
                }
              />
            </div>
            <div className="field">
              <label htmlFor="interface-table">Table</label>
              <input
                id="interface-table"
                value={input.table}
                placeholder="auto、off、路由表 ID 或名称"
                onChange={(event) =>
                  setInput((current) => ({
                    ...current,
                    table: event.target.value,
                  }))
                }
              />
            </div>
            <div className="field">
              <label htmlFor="interface-fwmark">FwMark</label>
              <input
                id="interface-fwmark"
                value={input.fwMark}
                placeholder="十进制、0x 十六进制或 off"
                onChange={(event) =>
                  setInput((current) => ({
                    ...current,
                    fwMark: event.target.value,
                  }))
                }
              />
            </div>
            <div className="field toggle-field">
              <span className="field-label">SaveConfig</span>
              <label className="toggle">
                <input
                  type="checkbox"
                  checked={input.saveConfig}
                  onChange={(event) =>
                    setInput((current) => ({
                      ...current,
                      saveConfig: event.target.checked,
                    }))
                  }
                />
                <span aria-hidden="true" />
                <span>开启时 wg-quick 停止会重写文件</span>
              </label>
              <small className="save-config-warning">
                可能清除 Peer ID、名称和私钥注释，面板环境强烈建议关闭。
              </small>
            </div>
          </div>
        </details>

        <details className="form-card advanced-card">
          <summary>
            <span className="section-icon"><Icon name="terminal" /></span>
            <span>
              <strong>生命周期命令</strong>
              <small>PreUp、PostUp、PreDown 与 PostDown</small>
            </span>
            <Icon name="chevron-down" />
          </summary>
          <div className="form-grid advanced-body">
            {(
              [
                ["preUp", "PreUp"],
                ["postUp", "PostUp"],
                ["preDown", "PreDown"],
                ["postDown", "PostDown"],
              ] as const
            ).map(([key, label]) => (
              <div className="field" key={key}>
                <label htmlFor={`interface-${key}`}>{label}</label>
                <textarea
                  id={`interface-${key}`}
                  value={lists[key]}
                  rows={4}
                  placeholder={`${label} 命令，每行一条`}
                  onChange={(event) =>
                    setLists((current) => ({
                      ...current,
                      [key]: event.target.value,
                    }))
                  }
                />
              </div>
            ))}
          </div>
        </details>

        <div className="form-actions">
          <span>
            {creating
              ? "保存后才能添加 Peer。"
              : `revision ${config?.revision.slice(0, 10)}… · 原子写入 ${config?.filename}`}
          </span>
          <div>
            <Link className="button" to="/">取消</Link>
            <button
              className="button is-primary"
              type="submit"
              disabled={savePending}
            >
              {savePending && <span className="spinner is-small" />}
              {savePending
                ? "保存中"
                : creating
                  ? "创建 Interface"
                  : "保存配置"}
            </button>
          </div>
        </div>
      </form>

      <section className={`form-card peers-card ${creating ? "is-locked" : ""}`}>
        <header className="form-card-header peers-heading">
          <span className="section-icon"><Icon name="users" /></span>
          <div>
            <h2>Peers</h2>
            <p>
              {creating
                ? "先创建 Interface，再管理它的 Peer。"
                : `${config?.peers.length ?? 0} 个 Peer · 2.5 秒刷新运行状态`}
            </p>
          </div>
          {!creating && (
            <button
              className="button is-primary"
              type="button"
              onClick={() => setEditingPeer("new")}
            >
              <Icon name="plus" />
              添加 Peer
            </button>
          )}
        </header>

        {!creating &&
          (config?.peers.length ? (
            <div className="peer-list">
              {config.peers.map((peer) => {
                const status = runtimeByPeer.get(peer.id);
                const available =
                  runtime?.collectorAvailable && status?.available;
                return (
                  <article className="peer-row" key={peer.id}>
                    <span
                      className={`peer-runtime-dot ${
                        available
                          ? status?.active
                            ? "is-active"
                            : "is-inactive"
                          : "is-unavailable"
                      }`}
                      title={
                        available
                          ? status?.active
                            ? "活跃"
                            : "不活跃"
                          : runtime?.message || "状态不可用"
                      }
                    />
                    <div className="peer-primary">
                      <span>{peer.name}</span>
                      <code title={peer.publicKey}>{shortKey(peer.publicKey)}</code>
                      <small>
                        {peer.systemGenerated
                          ? "系统密钥 · 私钥已保存"
                          : peer.privateKey
                            ? "手动密钥 · 私钥已保存"
                            : "仅公钥"}
                      </small>
                    </div>
                    <div className="peer-detail">
                      <span>客户端地址</span>
                      <strong>
                        {peer.clientAddress.length
                          ? peer.clientAddress.join(", ")
                          : "未配置"}
                      </strong>
                    </div>
                    <div className="peer-detail peer-throughput">
                      <span>实时速率</span>
                      <strong>
                        ↓ {formatRate(status?.receiveBytesPerSecond ?? 0)}
                        <br />
                        ↑ {formatRate(status?.sendBytesPerSecond ?? 0)}
                      </strong>
                    </div>
                    <div className="peer-actions">
                      <button
                        className="icon-button"
                        type="button"
                        aria-label={`查看 ${peer.name} 运行状态`}
                        title="运行状态"
                        onClick={() => setStatusPeer(peer)}
                      >
                        <Icon name="activity" />
                      </button>
                      <button
                        className="icon-button"
                        type="button"
                        aria-label={`下载 ${peer.name} 客户端配置`}
                        title="下载客户端配置"
                        onClick={() => void downloadPeerConfig(peer)}
                      >
                        <Icon name="download" />
                      </button>
                      <button
                        className="icon-button"
                        type="button"
                        aria-label={`编辑 ${peer.name}`}
                        title="编辑"
                        onClick={() => setEditingPeer(peer)}
                      >
                        <Icon name="edit" />
                      </button>
                      <button
                        className="icon-button is-danger"
                        type="button"
                        aria-label={`删除 ${peer.name}`}
                        title="删除"
                        onClick={() => setDeletingPeer(peer)}
                      >
                        <Icon name="trash" />
                      </button>
                    </div>
                  </article>
                );
              })}
            </div>
          ) : (
            <div className="peer-empty">
              <Icon name="users" />
              <p>还没有 Peer</p>
              <span>系统可生成密钥、规划地址并直接提供客户端配置。</span>
            </div>
          ))}
      </section>

      {editingPeer && (
        <PeerModal
          initial={editingPeer === "new" ? undefined : peerToInput(editingPeer)}
          pending={peerPending}
          ipPlan={ipPlan}
          onClose={() => setEditingPeer(null)}
          onSubmit={(peerInput) => void submitPeer(peerInput)}
        />
      )}

      {statusPeer && (
        <PeerStatusModal
          peer={statusPeer}
          status={runtimeByPeer.get(statusPeer.id)}
          collectorAvailable={runtime?.collectorAvailable ?? false}
          message={runtime?.message}
          onClose={() => setStatusPeer(null)}
        />
      )}

      {deletingPeer && (
        <Modal
          title={`删除 ${deletingPeer.name}`}
          description="Peer 将按稳定 ID 从当前原生配置文件中移除。"
          variant="display"
          onClose={() => setDeletingPeer(null)}
          className="is-compact"
        >
          <div className="danger-note">
            <Icon name="alert" />
            <p>
              ID：<code>{deletingPeer.id}</code>
              <br />
              PublicKey：<code>{shortKey(deletingPeer.publicKey)}</code>
            </p>
          </div>
          <footer className="modal-actions">
            <button
              className="button"
              type="button"
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
