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
};

export default function Modal({
  title,
  description,
  variant,
  onClose,
  children,
  className = "",
  closeDisabled = false,
}: ModalProps) {
  const titleID = useId();
  const descriptionID = useId();
  const dialogRef = useRef<HTMLDivElement>(null);
  const onCloseRef = useRef(onClose);
  const closeDisabledRef = useRef(closeDisabled);
  onCloseRef.current = onClose;
  closeDisabledRef.current = closeDisabled;

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
        if (!closeDisabledRef.current) onCloseRef.current();
      }
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
      className="modal-backdrop"
      data-modal-variant={variant}
      onMouseDown={(event) => {
        if (
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
        aria-modal="true"
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
