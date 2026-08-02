import { useEffect, useRef, useState, type FormEvent } from "react";
import Icon from "../../ui/Icon";
import Modal from "../../ui/Modal";
import { useToast } from "../../ui/Toast";
import AllowedIPsEditor from "./AllowedIPsEditor";
import {
  generateWireGuardKeyPair,
  generateWireGuardPresharedKey,
} from "./browserKeys";
import WireGuardKeyEditor from "./WireGuardKeyEditor";
import { analyzePeerChange } from "./runtimeDiff";
import {
  blankPeer,
  type IPPlan,
  type PeerInput,
  type WireGuardInterface,
} from "./api";

type PeerModalProps = {
  initial?: PeerInput;
  pending: boolean;
  ipPlan?: IPPlan;
  currentInterface: WireGuardInterface;
  running?: boolean;
  onClose(): void;
  onDelete?(): void;
  onSubmit(input: PeerInput, restartConfirmed?: boolean): void;
};

export default function PeerModal({
  initial,
  pending,
  ipPlan,
  currentInterface,
  running = false,
  onClose,
  onDelete,
  onSubmit,
}: PeerModalProps) {
  const { showToast } = useToast();
  const formRef = useRef<HTMLFormElement>(null);
  const [input, setInput] = useState<PeerInput>(initial ?? blankPeer());
  const [allowedIPsComplete, setAllowedIPsComplete] = useState(false);
  const [keyRegenerationConfirmation, setKeyRegenerationConfirmation] =
    useState(false);
  const [keyRegenerationPending, setKeyRegenerationPending] = useState(false);
  const [confirmation, setConfirmation] = useState<{
    input: PeerInput;
    changes: string[];
  }>();

  useEffect(() => {
    if (pending) formRef.current?.setAttribute("inert", "");
    else formRef.current?.removeAttribute("inert");
  }, [pending]);

  const submit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!allowedIPsComplete) {
      showToast(
        "请检查 AllowedIPs：地址必须完整，启用约束时还必须位于范围内",
        "error",
      );
      return;
    }
    const nextInput = {
      ...input,
      privateKey: input.privateKey.trim(),
      publicKey: input.publicKey.trim(),
      presharedKey: input.presharedKey.trim(),
    };
    if (running) {
      const original = initial
        ? currentInterface.peers.find(
            (peer) => peer.publicKey === initial.publicKey,
          )
        : undefined;
      const impact = analyzePeerChange(currentInterface, original, nextInput);
      if (impact.requiresConfirmation && impact.mode === "restart") {
        setConfirmation({
          input: nextInput,
          changes: impact.changes,
        });
        return;
      }
    }
    onSubmit(nextInput);
  };

  const generatePresharedKey = () => {
    try {
      const presharedKey = generateWireGuardPresharedKey();
      setInput((current) => ({
        ...current,
        presharedKey,
      }));
    } catch (error) {
      showToast(
        error instanceof Error ? error.message : "PresharedKey 生成失败",
        "error",
      );
    }
  };

  const regenerateKeyPair = async () => {
    setKeyRegenerationPending(true);
    try {
      const pair = await generateWireGuardKeyPair();
      setInput((current) => ({
        ...current,
        privateKey: pair.privateKey,
        publicKey: pair.publicKey,
      }));
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

  if (keyRegenerationConfirmation) {
    return (
      <Modal
        title="重新生成 Peer 密钥对？"
        variant="input"
        closeDisabled={keyRegenerationPending}
        onClose={() => setKeyRegenerationConfirmation(false)}
        className="is-compact runtime-confirmation-dialog"
      >
        <div className="runtime-confirmation-note is-stop">
          <Icon name="alert" />
          <div>
            <strong>原密钥对应的客户端可能失去连接</strong>
            <p>
              新密钥保存并应用后，使用旧私钥的客户端将无法继续连接。
              确认后只会先替换当前表单中的密钥，保存 Peer 后才会生效。
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
            onClick={() => onSubmit(confirmation.input, true)}
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
      title={initial ? "编辑 Peer" : "添加 Peer"}
      variant="input"
      closeDisabled={pending}
      onClose={onClose}
      className="is-interface-editor is-peer-editor"
    >
      <form
        ref={formRef}
        className="modal-form interface-modal-form peer-form"
        aria-busy={pending}
        onSubmit={submit}
      >
        <div className="field is-full">
          <label htmlFor="peer-name">名称</label>
          <input
            id="peer-name"
            value={input.name}
            maxLength={128}
            autoFocus
            placeholder="例如 Alice MacBook"
            onChange={(event) =>
              setInput((current) => ({ ...current, name: event.target.value }))
            }
          />
        </div>

        <WireGuardKeyEditor
          key={`peer-keys-${initial?.publicKey ?? "new"}`}
          idPrefix="peer"
          privateKey={input.privateKey}
          publicKey={input.publicKey}
          privateRequired={false}
          publicEditable
          autoGenerate={!initial}
          allowRegenerate
          regenerateLabel="重新生成密钥对"
          regenerateInPrivateHeader
          privatePlaintext
          className="is-peer"
          onRegenerateRequest={
            initial
              ? () => setKeyRegenerationConfirmation(true)
              : undefined
          }
          onChange={(privateKey, publicKey) =>
            setInput((current) => ({
              ...current,
              privateKey,
              publicKey,
            }))
          }
        />

        <AllowedIPsEditor
          key={`peer-addresses-${initial?.publicKey ?? "new"}`}
          initialValues={initial?.allowedIPs ?? []}
          showBlankRowWhenEmpty={!initial}
          allowedRanges={ipPlan?.allowedRanges}
          reservedAddresses={ipPlan?.reservedAddresses}
          assignments={ipPlan?.assignments}
          currentPeerPublicKey={initial?.publicKey}
          onChange={(allowedIPs, complete) => {
            setAllowedIPsComplete(complete);
            setInput((current) => ({ ...current, allowedIPs }));
          }}
        />

        <div className="field is-full">
          <div className="field-label-row">
            <label htmlFor="peer-preshared-key">PresharedKey</label>
            <button
              className="button is-quiet key-rotate-button"
              type="button"
              onClick={generatePresharedKey}
            >
              <Icon name="refresh" />
              {input.presharedKey ? "重新生成" : "生成"}
            </button>
          </div>
          <input
            id="peer-preshared-key"
            type="text"
            value={input.presharedKey}
            autoComplete="off"
            placeholder="可选"
            onChange={(event) =>
              setInput((current) => ({
                ...current,
                presharedKey: event.target.value,
              }))
            }
          />
        </div>

        <footer className="modal-actions">
          {initial && onDelete && (
            <button
              className="button is-danger-quiet peer-delete-action"
              type="button"
              disabled={pending}
              onClick={onDelete}
            >
              <Icon name="trash" />
              删除 Peer
            </button>
          )}
          <button className="button" type="button" disabled={pending} onClick={onClose}>
            取消
          </button>
          <button
            className="button is-primary"
            type="submit"
            disabled={pending || !allowedIPsComplete}
          >
            {pending && <span className="spinner is-small" />}
            {pending ? "保存中" : initial ? "保存 Peer" : "添加 Peer"}
          </button>
        </footer>
      </form>
    </Modal>
  );
}
