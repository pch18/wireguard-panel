import { useEffect, useState, type FormEvent } from "react";
import Modal from "../../ui/Modal";

type ConfigTextModalProps = {
  title: string;
  description?: string;
  mode: "preview" | "import";
  value?: string;
  pending?: boolean;
  submitLabel?: string;
  placeholder?: string;
  onClose(): void;
  onSubmit?(value: string): void;
};

export default function ConfigTextModal({
  title,
  description,
  mode,
  value = "",
  pending = false,
  submitLabel = "校验并导入",
  placeholder = "粘贴 WireGuard 配置…",
  onClose,
  onSubmit,
}: ConfigTextModalProps) {
  const [text, setText] = useState(value);

  useEffect(() => setText(value), [value]);

  const submit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    onSubmit?.(text);
  };

  return (
    <Modal
      title={title}
      description={description}
      variant={mode === "preview" ? "display" : "input"}
      closeDisabled={pending}
      onClose={onClose}
      className="is-config-text"
    >
      {mode === "preview" ? (
        <div className="config-text-body">
          <textarea
            className="config-textarea"
            value={text}
            readOnly
            rows={20}
            spellCheck={false}
            aria-label={title}
          />
          <footer className="modal-actions">
            <button className="button" type="button" onClick={onClose}>
              关闭
            </button>
          </footer>
        </div>
      ) : (
        <form className="config-text-body" onSubmit={submit}>
          <textarea
            className="config-textarea"
            value={text}
            required
            autoFocus
            rows={20}
            spellCheck={false}
            placeholder={placeholder}
            disabled={pending}
            aria-label={title}
            onChange={(event) => setText(event.target.value)}
          />
          <footer className="modal-actions">
            <button className="button" type="button" disabled={pending} onClick={onClose}>
              取消
            </button>
            <button
              className="button is-primary"
              type="submit"
              disabled={pending || text.trim() === ""}
            >
              {pending && <span className="spinner is-small" />}
              {pending ? "导入中" : submitLabel}
            </button>
          </footer>
        </form>
      )}
    </Modal>
  );
}
