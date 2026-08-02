import { useCallback, useEffect, useState } from "react";
import { Navigate, Outlet, useLocation } from "react-router-dom";
import Icon from "../../ui/Icon";
import { AuthProvider } from "./AuthContext";
import { getSession, type Session } from "./api";
import {
  isAnonymousSessionError,
  sessionLoadErrorMessage,
} from "./sessionState";

type AuthState =
  | { kind: "authenticated"; session: Session }
  | { kind: "checking" }
  | { kind: "anonymous" }
  | { kind: "error"; message: string };

export default function AuthGuard() {
  const location = useLocation();
  const [state, setState] = useState<AuthState>({ kind: "checking" });

  const refreshSession = useCallback(async () => {
    const session = await getSession();
    setState({ kind: "authenticated", session });
    return session;
  }, []);

  useEffect(() => {
    let active = true;
    getSession()
      .then((session) => {
        if (active) setState({ kind: "authenticated", session });
      })
      .catch((error: unknown) => {
        if (!active) return;
        setState(
          isAnonymousSessionError(error)
            ? { kind: "anonymous" }
            : { kind: "error", message: sessionLoadErrorMessage(error) },
        );
      });
    return () => {
      active = false;
    };
  }, []);

  if (state.kind === "checking") {
    return (
      <main className="route-loading" aria-label="正在检查登录状态">
        <span className="spinner" />
        <span>正在进入应用…</span>
      </main>
    );
  }
  if (state.kind === "anonymous") {
    return <Navigate to="/login" state={{ from: location }} replace />;
  }
  if (state.kind === "error") {
    return (
      <main className="route-loading route-load-error">
        <Icon name="alert" />
        <strong>无法确认登录状态</strong>
        <span>{state.message}</span>
        <button
          className="button is-primary"
          type="button"
          onClick={() => {
            setState({ kind: "checking" });
            getSession()
              .then((session) =>
                setState({ kind: "authenticated", session }),
              )
              .catch((error: unknown) => {
                setState(
                  isAnonymousSessionError(error)
                    ? { kind: "anonymous" }
                    : {
                        kind: "error",
                        message: sessionLoadErrorMessage(error),
                      },
                );
              });
          }}
        >
          <Icon name="refresh" />
          重试
        </button>
      </main>
    );
  }
  return (
    <AuthProvider value={{ session: state.session, refreshSession }}>
      <Outlet />
    </AuthProvider>
  );
}
