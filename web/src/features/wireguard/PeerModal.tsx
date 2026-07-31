import { useEffect, useState, type FormEvent } from "react";
import Icon from "../../ui/Icon";
import Modal from "../../ui/Modal";
import {
  blankPeer,
  linesToValues,
  valuesToLines,
  type IPNetworkPlan,
  type IPPlan,
  type PeerInput,
} from "./api";

type PeerModalProps = {
  initial?: PeerInput;
  pending: boolean;
  ipPlan?: IPPlan;
  onClose(): void;
  onSubmit(input: PeerInput): void;
};

function optionalNumber(value: string) {
  if (value.trim() === "") return undefined;
  return Number(value);
}

export default function PeerModal({
  initial,
  pending,
  ipPlan,
  onClose,
  onSubmit,
}: PeerModalProps) {
  const [input, setInput] = useState<PeerInput>(initial ?? blankPeer());
  const [allowedIPs, setAllowedIPs] = useState(
    valuesToLines(initial?.allowedIPs ?? []),
  );
  const [clientAddress, setClientAddress] = useState(
    valuesToLines(initial?.clientAddress ?? []),
  );
  const [showPrivateKey, setShowPrivateKey] = useState(false);
  const [showPresharedKey, setShowPresharedKey] = useState(false);

  useEffect(() => {
    const next = initial ?? blankPeer();
    setInput(next);
    setAllowedIPs(valuesToLines(next.allowedIPs));
    setClientAddress(valuesToLines(next.clientAddress));
  }, [initial]);

  const applySuggestion = (network: IPNetworkPlan) => {
    setClientAddress(network.suggestedAddress);
    setAllowedIPs(network.suggestedAllowedIP);
  };

  const submit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    onSubmit({
      ...input,
      privateKey: input.generateKeyPair ? "" : input.privateKey,
      publicKey: input.generateKeyPair ? "" : input.publicKey,
      presharedKey: input.generatePresharedKey ? "" : input.presharedKey,
      allowedIPs: linesToValues(allowedIPs),
      clientAddress: linesToValues(clientAddress),
    });
  };

  return (
    <Modal
      title={initial ? "编辑 Peer" : "添加 Peer"}
      description={
        initial
          ? "Peer 由配置块中的稳定 ID 定位；修改公钥不会改变它的身份。"
          : "系统会为 Peer 分配稳定 ID，并可生成密钥和无冲突的客户端地址。"
      }
      variant="input"
      onClose={onClose}
      className="is-wide"
    >
      <form className="modal-form peer-form" onSubmit={submit}>
        <div className="field is-full">
          <label htmlFor="peer-name">
            名称 <span aria-hidden="true">*</span>
          </label>
          <input
            id="peer-name"
            value={input.name}
            required
            maxLength={128}
            autoFocus
            placeholder="例如 Alice MacBook"
            onChange={(event) =>
              setInput((current) => ({ ...current, name: event.target.value }))
            }
          />
          <small>以 # Name = … 写在该 Peer 的配置块中。</small>
        </div>

        <section className="peer-form-section is-full" aria-labelledby="ip-plan-title">
          <div className="peer-form-section-heading">
            <div>
              <strong id="ip-plan-title">客户端地址规划</strong>
              <small>建议地址会同时填写 ClientAddress 和服务端 AllowedIPs。</small>
            </div>
            <span className="safe-badge">冲突检查</span>
          </div>
          {ipPlan?.networks.length ? (
            <div className="ip-plan-grid">
              {ipPlan.networks.map((network) => (
                <article className="ip-plan-item" key={network.network}>
                  <div>
                    <span>子网</span>
                    <code>{network.network}</code>
                  </div>
                  <div>
                    <span>已占用</span>
                    <strong>{network.allocatedAddresses.length} 个地址</strong>
                  </div>
                  {network.availableForPlanning ? (
                    <button
                      className="button is-quiet"
                      type="button"
                      onClick={() => applySuggestion(network)}
                    >
                      <Icon name="plus" />
                      使用 {network.suggestedAddress}
                    </button>
                  ) : (
                    <span className="ip-plan-full">没有可建议的地址</span>
                  )}
                </article>
              ))}
            </div>
          ) : (
            <div className="planning-empty">
              请先为 Interface 配置 Address（例如 10.20.0.1/24），保存后即可自动规划。
            </div>
          )}
        </section>

        <div className="field">
          <label htmlFor="peer-client-address">
            ClientAddress <span aria-hidden="true">*</span>
          </label>
          <textarea
            id="peer-client-address"
            value={clientAddress}
            required
            rows={3}
            placeholder={"10.20.0.2/24\nfd20::2/64"}
            onChange={(event) => setClientAddress(event.target.value)}
          />
          <small>写入给客户端的 [Interface] Address。</small>
        </div>

        <div className="field">
          <label htmlFor="peer-allowed-ips">
            服务端 AllowedIPs <span aria-hidden="true">*</span>
          </label>
          <textarea
            id="peer-allowed-ips"
            value={allowedIPs}
            required
            rows={3}
            placeholder={"10.20.0.2/32\nfd20::2/128"}
            onChange={(event) => setAllowedIPs(event.target.value)}
          />
          <small>同一 Interface 的不同 Peer 不允许地址段重叠。</small>
        </div>

        <section className="peer-form-section is-full" aria-labelledby="key-source-title">
          <div className="peer-form-section-heading">
            <div>
              <strong id="key-source-title">Peer 密钥对</strong>
              <small>系统生成时，私钥以注释保存在当前 wg 配置文件中。</small>
            </div>
          </div>
          {!initial && (
            <div className="choice-row">
              <button
                className={`choice-button ${input.generateKeyPair ? "is-selected" : ""}`}
                type="button"
                onClick={() =>
                  setInput((current) => ({
                    ...current,
                    generateKeyPair: true,
                    privateKey: "",
                    publicKey: "",
                  }))
                }
              >
                <Icon name="key" />
                <span><strong>系统生成</strong><small>推荐，可直接下载客户端配置</small></span>
              </button>
              <button
                className={`choice-button ${!input.generateKeyPair ? "is-selected" : ""}`}
                type="button"
                onClick={() =>
                  setInput((current) => ({
                    ...current,
                    generateKeyPair: false,
                  }))
                }
              >
                <Icon name="edit" />
                <span><strong>手动输入</strong><small>适合已有客户端密钥</small></span>
              </button>
            </div>
          )}
        </section>

        {(!input.generateKeyPair || initial) && (
          <>
            <div className="field is-full">
              <label htmlFor="peer-public-key">
                PublicKey <span aria-hidden="true">*</span>
              </label>
              <input
                id="peer-public-key"
                value={input.publicKey}
                autoComplete="off"
                required
                placeholder="Peer 的 32 字节 Base64 公钥"
                onChange={(event) =>
                  setInput((current) => ({
                    ...current,
                    publicKey: event.target.value,
                  }))
                }
              />
              <small>稳定 ID 与公钥独立，换钥后仍能准确定位同一个 Peer。</small>
            </div>

            <div className="field is-full">
              <label htmlFor="peer-private-key">PrivateKey</label>
              <div className="secret-input">
                <input
                  id="peer-private-key"
                  type={showPrivateKey ? "text" : "password"}
                  value={input.privateKey}
                  autoComplete="new-password"
                  placeholder="可选；填写后才能生成可运行的客户端配置"
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
          </>
        )}

        <div className="field is-full">
          <div className="field-label-row">
            <label htmlFor="peer-preshared-key">PresharedKey</label>
            <label className="compact-check">
              <input
                type="checkbox"
                checked={input.generatePresharedKey}
                onChange={(event) =>
                  setInput((current) => ({
                    ...current,
                    generatePresharedKey: event.target.checked,
                  }))
                }
              />
              系统生成新 PSK
            </label>
          </div>
          <div className="secret-input">
            <input
              id="peer-preshared-key"
              type={showPresharedKey ? "text" : "password"}
              value={input.generatePresharedKey ? "" : input.presharedKey}
              disabled={input.generatePresharedKey}
              autoComplete="new-password"
              placeholder={
                input.generatePresharedKey
                  ? "保存时生成"
                  : "可选的 32 字节 Base64 预共享密钥"
              }
              onChange={(event) =>
                setInput((current) => ({
                  ...current,
                  presharedKey: event.target.value,
                }))
              }
            />
            <button
              className="icon-button"
              type="button"
              disabled={input.generatePresharedKey}
              aria-label={showPresharedKey ? "隐藏预共享密钥" : "显示预共享密钥"}
              onClick={() => setShowPresharedKey((shown) => !shown)}
            >
              <Icon name={showPresharedKey ? "eye-off" : "eye"} />
            </button>
          </div>
        </div>

        <details className="peer-advanced is-full">
          <summary>
            <span>高级 Peer 字段</span>
            <small>Endpoint 与双向 PersistentKeepalive</small>
            <Icon name="chevron-down" />
          </summary>
          <div className="peer-advanced-grid">
            <div className="field">
              <label htmlFor="peer-endpoint">服务端 Endpoint</label>
              <input
                id="peer-endpoint"
                value={input.endpoint}
                placeholder="仅固定远端地址时填写"
                onChange={(event) =>
                  setInput((current) => ({
                    ...current,
                    endpoint: event.target.value,
                  }))
                }
              />
            </div>
            <div className="field">
              <label htmlFor="peer-keepalive">服务端 PersistentKeepalive</label>
              <input
                id="peer-keepalive"
                type="number"
                min="0"
                max="65535"
                value={input.persistentKeepalive ?? ""}
                placeholder="通常留空"
                onChange={(event) =>
                  setInput((current) => ({
                    ...current,
                    persistentKeepalive: optionalNumber(event.target.value),
                  }))
                }
              />
            </div>
            <div className="field">
              <label htmlFor="peer-client-keepalive">客户端 PersistentKeepalive</label>
              <input
                id="peer-client-keepalive"
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
              <small>客户端位于 NAT 后时通常建议 25 秒。</small>
            </div>
          </div>
        </details>

        <footer className="modal-actions">
          <button className="button" type="button" onClick={onClose}>
            取消
          </button>
          <button className="button is-primary" type="submit" disabled={pending}>
            {pending && <span className="spinner is-small" />}
            {pending ? "保存中" : initial ? "保存 Peer" : "添加 Peer"}
          </button>
        </footer>
      </form>
    </Modal>
  );
}
