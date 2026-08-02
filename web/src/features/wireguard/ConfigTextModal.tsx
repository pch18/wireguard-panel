import { useEffect, useRef, useState, type FormEvent } from "react";
import Icon from "../../ui/Icon";
import Modal from "../../ui/Modal";
import { useToast } from "../../ui/Toast";
import { downloadWireGuardConfig } from "./configFile";

type ConfigTextModalProps = {
  title: string;
  description?: string;
  mode: "preview" | "import";
  value?: string;
  pending?: boolean;
  submitLabel?: string;
  placeholder?: string;
  downloadName?: string;
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
  downloadName,
  onClose,
  onSubmit,
}: ConfigTextModalProps) {
  const [text, setText] = useState(value);
  const [copied, setCopied] = useState(false);
  const previewRef = useRef<HTMLTextAreaElement>(null);
  const { showToast } = useToast();

  useEffect(() => {
    setText(value);
    setCopied(false);
  }, [value]);

  useEffect(() => {
    if (!copied) return;
    const timer = window.setTimeout(() => setCopied(false), 1_800);
    return () => window.clearTimeout(timer);
  }, [copied]);

  const submit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    onSubmit?.(text);
  };

  const copyPreview = async () => {
    let copiedSuccessfully = false;
    try {
      if (navigator.clipboard?.writeText) {
        await navigator.clipboard.writeText(text);
        copiedSuccessfully = true;
      }
    } catch {
      // Fall back to the selected textarea for non-secure local deployments.
    }
    if (!copiedSuccessfully && previewRef.current) {
      const previousFocus =
        document.activeElement instanceof HTMLElement
          ? document.activeElement
          : undefined;
      try {
        previewRef.current.focus();
        previewRef.current.select();
        copiedSuccessfully = document.execCommand("copy");
      } catch {
        copiedSuccessfully = false;
      } finally {
        previousFocus?.focus();
      }
    }
    if (!copiedSuccessfully) {
      showToast("复制失败，请手动选择配置内容复制", "error");
      return;
    }
    setCopied(true);
  };

  const downloadPreview = () => {
    if (!downloadName) return;
    try {
      downloadWireGuardConfig(text, downloadName);
    } catch {
      showToast("配置文件下载失败，请稍后重试", "error");
    }
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
            ref={previewRef}
            className="config-textarea"
            value={text}
            readOnly
            rows={20}
            spellCheck={false}
            aria-label={title}
          />
          <footer className="modal-actions">
            <button className="button" type="button" onClick={copyPreview}>
              <Icon name="copy" />
              {copied ? "已复制" : "复制配置"}
            </button>
            {downloadName && (
              <button
                className="button is-primary"
                type="button"
                onClick={downloadPreview}
              >
                <Icon name="download" />
                下载配置
              </button>
            )}
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
