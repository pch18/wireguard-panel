import { useState, type FormEvent } from "react";
import Icon from "../../ui/Icon";
import Modal from "../../ui/Modal";
import { useToast } from "../../ui/Toast";
import { interfaceNameOnly } from "./formUtils";

type InterfaceRenameModalProps = {
  currentName: string;
  pending: boolean;
  running?: boolean;
  onClose(): void;
  onSubmit(name: string): void;
};

export default function InterfaceRenameModal({
  currentName,
  pending,
  running = false,
  onClose,
  onSubmit,
}: InterfaceRenameModalProps) {
  const { showToast } = useToast();
  const [name, setName] = useState("");

  const submit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (running) {
      showToast("请先停止 Interface，再进行重命名", "warning");
      return;
    }
    if (name === currentName) {
      showToast("新名称必须与当前名称不同", "error");
      return;
    }
    onSubmit(name);
  };

  return (
    <Modal
      title="重命名 Interface"
      variant="input"
      closeDisabled={pending}
      onClose={onClose}
      className="is-compact interface-rename-modal"
    >
      <form className="modal-form rename-interface-form" onSubmit={submit}>
        <div className="rename-risk" role="note">
          <Icon name="alert" />
          <div>
            <strong>{running ? "请先停止 Interface" : "重命名配置文件"}</strong>
            <p>{running ? "面板不会为了重命名自动中断当前通道。" : "重命名后可使用新名称重新启动。"}</p>
          </div>
        </div>

        <div className="field">
          <label htmlFor="renamed-interface-name">
            新名称 <span aria-hidden="true">*</span>
          </label>
          <input
            id="renamed-interface-name"
            value={name}
            required
            maxLength={15}
            pattern={"[A-Za-z0-9_\\-]{1,15}"}
            autoFocus
            disabled={pending}
            placeholder="例如 tokyo-vpn"
            onChange={(event) =>
              setName(interfaceNameOnly(event.target.value))
            }
          />
          <small>仅限英文字母、数字、- 或 _，最多 15 个字符。</small>
        </div>

        <div className="rename-file-preview" aria-live="polite">
          <code>{currentName}.conf</code>
          <span aria-hidden="true">→</span>
          <code>{name || "新名称"}.conf</code>
        </div>

        <footer className="modal-actions">
          <button className="button" type="button" disabled={pending} onClick={onClose}>
            取消
          </button>
          <button className="button is-danger" type="submit" disabled={pending || running}>
            {pending && <span className="spinner is-small" />}
            {pending ? "重命名中" : "确认重命名"}
          </button>
        </footer>
      </form>
    </Modal>
  );
}
