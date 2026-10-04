import { useEffect, useId, useRef, type ReactNode } from "react";
import Icon from "./Icon";

type ModalProps = {
  title: string;
  description?: string;
  variant: "display" | "input";
  onClose(): void;
  children: ReactNode;
  className?: string;
  closeDisabled?: boolean;
  covered?: boolean;
};

export default function Modal({
  title,
  description,
  variant,
  onClose,
  children,
  className = "",
  closeDisabled = false,
  covered = false,
}: ModalProps) {
  const titleID = useId();
  const descriptionID = useId();
  const dialogRef = useRef<HTMLDivElement>(null);
  const coveredFocusRef = useRef<HTMLElement | null>(null);
  const onCloseRef = useRef(onClose);
  const closeDisabledRef = useRef(closeDisabled);
  const coveredRef = useRef(covered);
  onCloseRef.current = onClose;
  closeDisabledRef.current = closeDisabled;
  coveredRef.current = covered;

  useEffect(() => {
    // 被子弹窗覆盖时仍保留表单及草稿，但必须同时禁用键盘和指针交互。
    const dialog = dialogRef.current;
    if (!dialog) return;
    if (covered) {
      const activeElement = document.activeElement;
      coveredFocusRef.current =
        activeElement instanceof HTMLElement && dialog.contains(activeElement)
          ? activeElement
          : null;
      dialog.setAttribute("inert", "");
    } else {
      // 子弹窗卸载时父层可能仍处于 inert，须在解除禁用后恢复原触发点。
      dialog.removeAttribute("inert");
      coveredFocusRef.current?.focus();
      coveredFocusRef.current = null;
    }
  }, [covered]);

  useEffect(() => {
    const previousFocus =
      document.activeElement instanceof HTMLElement
        ? document.activeElement
        : undefined;
    const dialog = dialogRef.current;
    const focusTarget =
      dialog?.querySelector<HTMLElement>("[autofocus]") ??
      dialog?.querySelector<HTMLElement>("input:not(:disabled)") ??
      dialog?.querySelector<HTMLElement>("select:not(:disabled)") ??
      dialog?.querySelector<HTMLElement>("button:not(:disabled)");
    focusTarget?.focus();

    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        event.preventDefault();
        if (!coveredRef.current && !closeDisabledRef.current) {
          onCloseRef.current();
        }
      }
      if (coveredRef.current) return;
      if (event.key !== "Tab" || !dialog) return;
      const focusable = Array.from(
        dialog.querySelectorAll<HTMLElement>(
          'button:not(:disabled), input:not(:disabled), select:not(:disabled), textarea:not(:disabled), a[href], [tabindex]:not([tabindex="-1"])',
        ),
      );
      if (focusable.length === 0) return;
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    };

    document.addEventListener("keydown", handleKeyDown);
    return () => {
      document.removeEventListener("keydown", handleKeyDown);
      previousFocus?.focus();
    };
  }, []);

  return (
    <div
      className={`modal-backdrop ${covered ? "is-covered" : ""}`.trim()}
      data-modal-variant={variant}
      aria-hidden={covered || undefined}
      onMouseDown={(event) => {
        if (
          !covered &&
          !closeDisabled &&
          variant === "display" &&
          event.target === event.currentTarget
        ) {
          onClose();
        }
      }}
    >
      <div
        ref={dialogRef}
        className={`modal ${className}`.trim()}
        role="dialog"
        aria-modal={covered ? undefined : true}
        aria-labelledby={titleID}
        aria-describedby={description ? descriptionID : undefined}
      >
        <header className="modal-header">
          <div>
            <h2 id={titleID}>{title}</h2>
            {description && <p id={descriptionID}>{description}</p>}
          </div>
          <button
            className="icon-button"
            type="button"
            aria-label="关闭"
            disabled={closeDisabled}
            onClick={onClose}
          >
            <Icon name="close" />
          </button>
        </header>
        {children}
      </div>
    </div>
  );
}
