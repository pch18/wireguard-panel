import { useCallback, useEffect, useState } from "react";
import { Navigate, Outlet, useLocation } from "react-router-dom";
import { AuthProvider } from "./AuthContext";
import { getSession, type Session } from "./api";

type AuthState = Session | "checking" | "anonymous";

export default function AuthGuard() {
  const location = useLocation();
  const [state, setState] = useState<AuthState>("checking");

  const refreshSession = useCallback(async () => {
    const session = await getSession();
    setState(session);
    return session;
  }, []);

  useEffect(() => {
    let active = true;
    getSession()
      .then((session) => {
        if (active) setState(session);
      })
      .catch(() => {
        if (active) setState("anonymous");
      });
    return () => {
      active = false;
    };
  }, []);

  if (state === "checking") {
    return (
      <main className="route-loading" aria-label="正在检查登录状态">
        <span className="spinner" />
        <span>正在进入应用…</span>
      </main>
    );
  }
  if (state === "anonymous") {
    return <Navigate to="/login" state={{ from: location }} replace />;
  }
  return (
    <AuthProvider value={{ session: state, refreshSession }}>
      <Outlet />
    </AuthProvider>
  );
}
