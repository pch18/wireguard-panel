import { useEffect, useMemo, useRef, useState, type FormEvent } from "react";
import Icon from "../../ui/Icon";
import Modal from "../../ui/Modal";
import { useToast } from "../../ui/Toast";
import { generateWireGuardKeyPair } from "./browserKeys";
import InterfaceAddressEditor from "./InterfaceAddressEditor";
import { parseCIDR } from "./ipAddress";
import { analyzeInterfaceChange } from "./runtimeDiff";
import WireGuardKeyEditor from "./WireGuardKeyEditor";
import {
  blankInterface,
  digitsOnly,
  interfaceNameOnly,
  interfaceToInput,
  linesToValues,
  probeWireGuardMTU,
  valuesToInline,
  type InterfaceInput,
  type WireGuardInterface,
} from "./api";

type InterfaceModalProps = {
  initial?: WireGuardInterface;
  defaultName?: string;
  pending: boolean;
  running?: boolean;
  onClose(): void;
  onSubmit(input: InterfaceInput, name?: string, restartConfirmed?: boolean): void;
};

function optionalNumber(value: string) {
  return value === "" ? undefined : Number(value);
}

export default function InterfaceModal({
  initial,
  defaultName = "wg0",
  pending,
  running = false,
  onClose,
  onSubmit,
}: InterfaceModalProps) {
  const { showToast } = useToast();
  const [input, setInput] = useState<InterfaceInput>(() =>
    initial ? interfaceToInput(initial) : blankInterface(),
  );
  const [publicKey, setPublicKey] = useState("");
  const [name, setName] = useState(() => (initial ? "" : defaultName));
  const nameManuallyEdited = useRef(false);
  const formRef = useRef<HTMLFormElement>(null);
  const [address, setAddress] = useState(() => initial?.address ?? []);
  const [addressComplete, setAddressComplete] = useState(false);
  const [dns, setDNS] = useState(() => valuesToInline(initial?.dns ?? []));
  const [clientAllowedIPs, setClientAllowedIPs] = useState(() =>
    valuesToInline(initial?.clientAllowedIPs ?? []),
  );
  const routeConstraintValues = useMemo(
    () => linesToValues(clientAllowedIPs),
    [clientAllowedIPs],
  );
  const invalidRouteConstraint = routeConstraintValues.find(
    (value) => parseCIDR(value) === null,
  );
  const [listenPort, setListenPort] = useState(() =>
    initial?.listenPort === undefined ? "" : String(initial.listenPort),
  );
  const [mtu, setMTU] = useState(() =>
    initial?.mtu === undefined ? "" : String(initial.mtu),
  );
  const [mtuProbePending, setMTUProbePending] = useState(false);
  const [keyRegenerationConfirmation, setKeyRegenerationConfirmation] =
    useState(false);
  const [keyRegenerationPending, setKeyRegenerationPending] = useState(false);
  const [confirmation, setConfirmation] = useState<{
    input: InterfaceInput;
    name?: string;
    changes: string[];
  }>();

  useEffect(() => {
    if (!initial && !nameManuallyEdited.current) {
      setName(defaultName);
    }
  }, [defaultName, initial]);

  useEffect(() => {
    if (pending) formRef.current?.setAttribute("inert", "");
    else formRef.current?.removeAttribute("inert");
  }, [pending]);

  const probeMTU = async () => {
    setMTUProbePending(true);
    try {
      const result = await probeWireGuardMTU();
      setMTU(String(result.wireGuardMTU));
    } catch (error) {
      showToast(
        error instanceof Error ? error.message : "MTU 探测失败",
        "error",
        6_000,
      );
    } finally {
      setMTUProbePending(false);
    }
  };

  const regenerateKeyPair = async () => {
    setKeyRegenerationPending(true);
    try {
      const pair = await generateWireGuardKeyPair();
      setInput((current) => ({ ...current, privateKey: pair.privateKey }));
      setPublicKey(pair.publicKey);
      setKeyRegenerationConfirmation(false);
    } catch (error) {
      showToast(
        error instanceof Error ? error.message : "WireGuard 密钥生成失败",
        "error",
      );
    } finally {
      setKeyRegenerationPending(false);
    }
  };

  const submit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const nextListenPort = optionalNumber(listenPort);
    const nextMTU = optionalNumber(mtu);
    if (nextListenPort !== undefined && nextListenPort > 65_535) {
      showToast("Listen Port 必须在 0 到 65535 之间", "error");
      return;
    }
    if (nextMTU !== undefined && (nextMTU < 1 || nextMTU > 65_535)) {
      showToast("MTU 必须在 1 到 65535 之间", "error");
      return;
    }
    if (invalidRouteConstraint) {
      showToast(
        `路由范围约束 ${invalidRouteConstraint} 不是有效的 CIDR`,
        "error",
      );
      return;
    }
    if (!addressComplete) {
      showToast("请为每条 Interface Address 选择掩码，或删除地址行", "error");
      return;
    }
    const nextInput = {
      ...input,
      privateKey: input.privateKey.trim(),
      address,
      listenPort: nextListenPort,
      dns: linesToValues(dns),
      mtu: nextMTU,
      clientEndpoint: input.clientEndpoint.trim(),
      clientAllowedIPs: linesToValues(clientAllowedIPs),
    };
    if (initial && running) {
      const impact = analyzeInterfaceChange(initial, nextInput);
      if (impact.requiresConfirmation && impact.mode === "restart") {
        setConfirmation({
          input: nextInput,
          changes: impact.changes,
        });
        return;
      }
    }
    onSubmit(nextInput, initial ? undefined : name);
  };

  if (keyRegenerationConfirmation) {
    return (
      <Modal
        title="重新生成 Interface 密钥对？"
        variant="input"
        closeDisabled={keyRegenerationPending}
        onClose={() => setKeyRegenerationConfirmation(false)}
        className="is-compact runtime-confirmation-dialog"
      >
        <div className="runtime-confirmation-note is-stop">
          <Icon name="alert" />
          <div>
            <strong>现有客户端可能失去连接</strong>
            <p>
              新公钥保存并应用后，所有客户端都必须更新服务端 PublicKey，
              否则连接将中断。确认后只会先替换当前表单中的密钥，保存配置后才会生效。
            </p>
          </div>
        </div>
        <footer className="modal-actions">
          <button
            className="button"
            type="button"
            disabled={keyRegenerationPending}
            onClick={() => setKeyRegenerationConfirmation(false)}
          >
            取消
          </button>
          <button
            className="button is-danger"
            type="button"
            disabled={keyRegenerationPending}
            autoFocus
            onClick={() => void regenerateKeyPair()}
          >
            {keyRegenerationPending && <span className="spinner is-small" />}
            {keyRegenerationPending ? "生成中" : "确认重新生成"}
          </button>
        </footer>
      </Modal>
    );
  }

  if (confirmation) {
    return (
      <Modal
        title="保存并重启 Interface？"
        variant="input"
        closeDisabled={pending}
        onClose={onClose}
        className="is-compact runtime-confirmation-dialog"
      >
        <div className="runtime-confirmation-note is-stop">
          <Icon name="alert" />
          <div>
            <strong>Interface 将短暂中断</strong>
            <ul className="runtime-change-list">
              {confirmation.changes.map((change) => (
                <li key={change}>{change}</li>
              ))}
            </ul>
          </div>
        </div>
        <footer className="modal-actions">
          <button
            className="button"
            type="button"
            disabled={pending}
            onClick={() => setConfirmation(undefined)}
          >
            返回修改
          </button>
          <button
            className="button is-primary"
            type="button"
            disabled={pending}
            autoFocus
            onClick={() => onSubmit(confirmation.input, confirmation.name, true)}
          >
            {pending && <span className="spinner is-small" />}
            {pending ? "保存并重启中" : "保存并重启"}
          </button>
        </footer>
      </Modal>
    );
  }

  return (
    <Modal
      title={initial ? `编辑 ${initial.filename}` : "新建 Interface"}
      variant="input"
      closeDisabled={pending}
      onClose={onClose}
      className="is-interface-editor"
    >
      <form
        ref={formRef}
        className="modal-form interface-modal-form"
        aria-busy={pending}
        onSubmit={submit}
      >
        <div className="field">
          <label htmlFor="interface-name">
            名称
            {!initial && <span aria-hidden="true">*</span>}
          </label>
          <input
            id="interface-name"
            value={initial?.id ?? name}
            required={!initial}
            disabled={Boolean(initial)}
            maxLength={15}
            pattern={"[A-Za-z0-9_\\-]{1,15}"}
            autoFocus={!initial}
            placeholder="例如 wg0 或 tokyo-vpn"
            onChange={(event) => {
              nameManuallyEdited.current = true;
              setName(interfaceNameOnly(event.target.value));
            }}
          />
          {initial && <small>请使用“重命名”修改名称。</small>}
        </div>

        <div className="field listen-port-field">
          <label htmlFor="interface-listen-port">Listen Port</label>
          <input
            id="interface-listen-port"
            type="text"
            inputMode="numeric"
            pattern="[0-9]*"
            value={listenPort}
            placeholder="自动"
            onChange={(event) => setListenPort(digitsOnly(event.target.value))}
          />
        </div>

        <WireGuardKeyEditor
          key={
            initial
              ? `interface-keys-${initial.revision}`
              : "new-interface-keys"
          }
          idPrefix="interface"
          privateKey={input.privateKey}
          publicKey={publicKey}
          privateRequired
          publicEditable={false}
          autoGenerate={!initial}
          allowRegenerate
          regenerateLabel="重新生成密钥对"
          regenerateInPrivateHeader
          privatePlaintext
          className="is-interface"
          onRegenerateRequest={
            initial
              ? () => setKeyRegenerationConfirmation(true)
              : undefined
          }
          onChange={(privateKey, nextPublicKey) => {
            setInput((current) => ({ ...current, privateKey }));
            setPublicKey(nextPublicKey);
          }}
        />

        <InterfaceAddressEditor
          key={
            initial
              ? `interface-addresses-${initial.revision}`
              : "new-interface-addresses"
          }
          initialValues={address}
          allowedRanges={routeConstraintValues}
          showBlankRowWhenEmpty={!initial}
          onChange={(values, complete) => {
            setAddress(values);
            setAddressComplete(complete);
          }}
        />

        <div className="field">
          <label htmlFor="interface-dns">DNS</label>
          <input
            id="interface-dns"
            value={dns}
            placeholder="1.1.1.1, 8.8.8.8"
            onChange={(event) => setDNS(event.target.value)}
          />
        </div>

        <div className="field">
          <div className="field-label-row">
            <label htmlFor="interface-mtu">MTU</label>
            <button
              className="button is-quiet mtu-probe-button"
              type="button"
              disabled={mtuProbePending}
              onClick={() => void probeMTU()}
            >
              {mtuProbePending ? (
                <span className="spinner is-small" />
              ) : (
                <Icon name="refresh" />
              )}
              {mtuProbePending ? "探测中" : "探测"}
            </button>
          </div>
          <input
            id="interface-mtu"
            type="text"
            inputMode="numeric"
            pattern="[0-9]*"
            value={mtu}
            placeholder="自动"
            onChange={(event) => setMTU(digitsOnly(event.target.value))}
          />
        </div>

        <section className="peer-defaults-section is-full">
          <header>
            <strong>额外参数</strong>
          </header>
          <div className="peer-defaults-grid">
            <div className="field">
              <label htmlFor="client-endpoint">客户端 Endpoint</label>
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
            </div>
            <div className="field">
              <label htmlFor="client-allowed-ips">
                路由范围约束
              </label>
              <input
                id="client-allowed-ips"
                value={clientAllowedIPs}
                aria-invalid={Boolean(invalidRouteConstraint) || undefined}
                placeholder="10.0.0.0/8, fd00::/8"
                onChange={(event) => setClientAllowedIPs(event.target.value)}
              />
              {invalidRouteConstraint && (
                <small className="field-error">
                  {invalidRouteConstraint} 不是有效的 CIDR
                </small>
              )}
            </div>
          </div>
        </section>

        <footer className="modal-actions">
          <button className="button" type="button" disabled={pending} onClick={onClose}>
            取消
          </button>
          <button
            className="button is-primary"
            type="submit"
            disabled={
              pending ||
              input.privateKey.trim() === "" ||
              !addressComplete ||
              Boolean(invalidRouteConstraint)
            }
          >
            {pending && <span className="spinner is-small" />}
            {pending ? "保存中" : initial ? "保存配置" : "创建 Interface"}
          </button>
        </footer>
      </form>
    </Modal>
  );
}
