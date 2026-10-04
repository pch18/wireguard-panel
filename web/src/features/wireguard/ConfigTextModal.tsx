import { useEffect, useRef, useState, type FormEvent } from "react";
import Icon from "../../ui/Icon";
import Modal from "../../ui/Modal";
import { useToast } from "../../ui/Toast";
import { downloadWireGuardConfig } from "./configFile";
import { createConfigQRCode } from "./configQRCode";

type ConfigTextModalProps = {
  title: string;
  description?: string;
  mode: "preview" | "client" | "import";
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
  const [qrCode, setQRCode] = useState<ReturnType<
    typeof createConfigQRCode
  > | null>(null);
  const previewRef = useRef<HTMLTextAreaElement>(null);
  const { showToast } = useToast();

  useEffect(() => {
    setText(value);
    setCopied(false);
    setQRCode(null);
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

  const generateQRCode = () => {
    try {
      // 生成的是点击瞬间的草稿快照，返回编辑后再次点击会重新编码。
      setQRCode(createConfigQRCode(text));
    } catch {
      showToast(
        text.trim()
          ? "配置内容过长或无法生成二维码，请精简后重试或下载配置"
          : "请先填写配置内容",
        "error",
      );
    }
  };

  return (
    <>
      <Modal
        title={title}
        description={description}
        variant={mode === "preview" ? "display" : "input"}
        covered={qrCode !== null}
        closeDisabled={pending}
        onClose={onClose}
        className="is-config-text"
      >
        {mode !== "import" ? (
          <div className="config-text-body">
            <textarea
              ref={previewRef}
              className="config-textarea"
              value={text}
              readOnly={mode === "preview"}
              onChange={(event) => {
                setText(event.target.value);
                setCopied(false);
              }}
              rows={20}
              spellCheck={false}
              aria-label={title}
            />
            <footer className="modal-actions">
              {mode === "client" && (
                <button
                  className="button"
                  type="button"
                  onClick={generateQRCode}
                  disabled={!text.trim()}
                >
                  <Icon name="qr-code" />
                  生成二维码
                </button>
              )}
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
              <button
                className="button"
                type="button"
                disabled={pending}
                onClick={onClose}
              >
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
      {qrCode && (
        <Modal
          title="客户端配置二维码"
          description="使用 WireGuard 客户端扫码导入当前编辑的配置。"
          variant="display"
          onClose={() => setQRCode(null)}
          className="is-config-qr"
        >
          <div className="config-qr-body">
            <svg
              className="config-qr-image"
              viewBox={`0 0 ${qrCode.size} ${qrCode.size}`}
              role="img"
              aria-label="客户端配置二维码"
              shapeRendering="crispEdges"
            >
              <rect width={qrCode.size} height={qrCode.size} fill="#fff" />
              <path d={qrCode.path} fill="#000" />
            </svg>
          </div>
          <footer className="modal-actions">
            <button
              className="button"
              type="button"
              onClick={() => setQRCode(null)}
            >
              返回编辑
            </button>
          </footer>
        </Modal>
      )}
    </>
  );
}
