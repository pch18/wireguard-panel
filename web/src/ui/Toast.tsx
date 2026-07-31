import {
  createContext,
  useCallback,
  useContext,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from "react";
import Icon from "./Icon";

export type ToastType = "info" | "success" | "warning" | "error" | "loading";

type ToastItem = {
  id: number;
  message: string;
  type: ToastType;
};

type ToastContextValue = {
  showToast(message: string, type?: ToastType, duration?: number): number;
  updateToast(id: number, message: string, type?: ToastType, duration?: number): void;
  dismissToast(id: number): void;
};

const ToastContext = createContext<ToastContextValue | null>(null);

export function ToastProvider({ children }: { children: ReactNode }) {
  const [items, setItems] = useState<ToastItem[]>([]);
  const nextID = useRef(1);
  const timers = useRef(new Map<number, number>());

  const dismissToast = useCallback((id: number) => {
    const timer = timers.current.get(id);
    if (timer) window.clearTimeout(timer);
    timers.current.delete(id);
    setItems((current) => current.filter((item) => item.id !== id));
  }, []);

  const scheduleDismiss = useCallback(
    (id: number, duration: number) => {
      const existing = timers.current.get(id);
      if (existing) window.clearTimeout(existing);
      if (duration <= 0) {
        timers.current.delete(id);
        return;
      }
      timers.current.set(
        id,
        window.setTimeout(() => dismissToast(id), duration),
      );
    },
    [dismissToast],
  );

  const showToast = useCallback(
    (message: string, type: ToastType = "info", duration = 3200) => {
      const id = nextID.current++;
      setItems((current) => [...current, { id, message, type }]);
      scheduleDismiss(id, duration);
      return id;
    },
    [scheduleDismiss],
  );

  const updateToast = useCallback(
    (
      id: number,
      message: string,
      type: ToastType = "info",
      duration = 3200,
    ) => {
      setItems((current) =>
        current.map((item) =>
          item.id === id ? { ...item, message, type } : item,
        ),
      );
      scheduleDismiss(id, duration);
    },
    [scheduleDismiss],
  );

  const value = useMemo(
    () => ({ showToast, updateToast, dismissToast }),
    [dismissToast, showToast, updateToast],
  );

  return (
    <ToastContext.Provider value={value}>
      {children}
      <div className="toast-viewport" aria-live="polite" aria-atomic="true">
        {items.map((item) => (
          <div key={item.id} className={`toast is-${item.type}`} role="status">
            <span className="toast-indicator" aria-hidden="true">
              {item.type === "loading" ? (
                <span className="spinner is-small" />
              ) : (
                <span />
              )}
            </span>
            <span>{item.message}</span>
            <button
              type="button"
              aria-label="关闭提示"
              onClick={() => dismissToast(item.id)}
            >
              <Icon name="close" />
            </button>
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  );
}

export function useToast() {
  const value = useContext(ToastContext);
  if (!value) {
    throw new Error("useToast must be used inside ToastProvider");
  }
  return value;
}
