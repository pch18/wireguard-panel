import { useCallback, useEffect, useRef, useState } from "react";
import { NavLink, Outlet, useNavigate } from "react-router-dom";
import { sessionExpiredEvent } from "../app/apiClient";
import { appConfig } from "../app/config";
import { logout } from "../features/auth/api";
import { useAuth } from "../features/auth/AuthContext";
import Icon from "../ui/Icon";
import Modal from "../ui/Modal";
import { useToast } from "../ui/Toast";

export default function AppLayout() {
  const navigate = useNavigate();
  const { session } = useAuth();
  const { showToast, updateToast } = useToast();
  const [mobileNavOpen, setMobileNavOpen] = useState(false);
  const [accountOpen, setAccountOpen] = useState(false);
  const [logoutOpen, setLogoutOpen] = useState(false);
  const [sessionExpired, setSessionExpired] = useState(false);
  const [logoutPending, setLogoutPending] = useState(false);
  const accountRef = useRef<HTMLDivElement>(null);
  const displayName = session.user.name || session.user.username;

  const goToLogin = useCallback(() => {
    setSessionExpired(false);
    navigate("/login", { replace: true });
  }, [navigate]);

  useEffect(() => {
    const handleExpired = () => setSessionExpired(true);
    window.addEventListener(sessionExpiredEvent, handleExpired);
    return () => window.removeEventListener(sessionExpiredEvent, handleExpired);
  }, []);

  useEffect(() => {
    if (!accountOpen) return;
    const close = (event: PointerEvent) => {
      if (
        event.target instanceof Node &&
        !accountRef.current?.contains(event.target)
      ) {
        setAccountOpen(false);
      }
    };
    document.addEventListener("pointerdown", close);
    return () => document.removeEventListener("pointerdown", close);
  }, [accountOpen]);

  useEffect(() => {
    if (!mobileNavOpen) return;
    const close = (event: KeyboardEvent) => {
      if (event.key === "Escape") setMobileNavOpen(false);
    };
    document.addEventListener("keydown", close);
    return () => document.removeEventListener("keydown", close);
  }, [mobileNavOpen]);

  const handleLogout = async () => {
    setLogoutPending(true);
    const toastID = showToast("正在安全退出…", "loading", 0);
    try {
      await logout();
      updateToast(toastID, "已退出登录", "success");
      navigate("/login", { replace: true });
    } catch (error) {
      updateToast(
        toastID,
        error instanceof Error ? error.message : "退出失败",
        "error",
      );
    } finally {
      setLogoutPending(false);
      setLogoutOpen(false);
    }
  };

  const closeMobileNav = () => setMobileNavOpen(false);

  return (
    <div className="app-shell">
      {mobileNavOpen && (
        <button
          className="mobile-nav-backdrop"
          type="button"
          aria-label="关闭导航"
          onClick={closeMobileNav}
        />
      )}
      <aside className={`sidebar ${mobileNavOpen ? "is-open" : ""}`}>
        <div className="sidebar-brand">
          <span className="brand-mark is-small">
            <Icon name="shield" />
          </span>
          <div>
            <strong>{appConfig.title}</strong>
            <span>Configuration panel</span>
          </div>
          <button
            className="icon-button sidebar-close"
            type="button"
            aria-label="关闭导航"
            onClick={closeMobileNav}
          >
            <Icon name="close" />
          </button>
        </div>

        <nav className="sidebar-nav" aria-label="主要导航">
          <p>工作区</p>
          <NavLink to="/" end onClick={closeMobileNav}>
            <Icon name="network" />
            <span>Interfaces</span>
          </NavLink>
        </nav>

        <div className="sidebar-foot">
          <span className="status-dot" />
          <span>配置目录已连接</span>
        </div>
      </aside>

      <div className="app-column">
        <header className="topbar">
          <button
            className="icon-button mobile-menu"
            type="button"
            aria-label="打开导航"
            onClick={() => setMobileNavOpen(true)}
          >
            <Icon name="menu" />
          </button>
          <div className="topbar-title">
            <span className="status-dot" />
            <span>WireGuard 文件管理</span>
          </div>
          <div className="account" ref={accountRef}>
            <button
              className="account-trigger"
              type="button"
              aria-expanded={accountOpen}
              onClick={() => setAccountOpen((open) => !open)}
            >
              <span className="avatar">
                {Array.from(displayName)[0]?.toUpperCase()}
              </span>
              <span className="account-copy">
                <strong>{displayName}</strong>
                <small>管理员</small>
              </span>
              <Icon name="chevron-down" />
            </button>
            {accountOpen && (
              <div className="account-menu">
                <div className="account-summary">
                  <strong>{session.user.username}</strong>
                  <span>环境变量账号</span>
                </div>
                <button
                  className="is-danger"
                  type="button"
                  onClick={() => {
                    setAccountOpen(false);
                    setLogoutOpen(true);
                  }}
                >
                  <Icon name="logout" />
                  退出登录
                </button>
              </div>
            )}
          </div>
        </header>

        <main className="app-content">
          <Outlet />
        </main>
      </div>

      {logoutOpen && (
        <Modal
          title="退出登录"
          description="确认结束当前会话并返回登录页？"
          variant="display"
          onClose={() => setLogoutOpen(false)}
          className="is-compact"
        >
          <footer className="modal-actions">
            <button
              className="button"
              type="button"
              onClick={() => setLogoutOpen(false)}
            >
              取消
            </button>
            <button
              className="button is-danger"
              type="button"
              disabled={logoutPending}
              onClick={() => void handleLogout()}
            >
              {logoutPending ? "退出中" : "退出登录"}
            </button>
          </footer>
        </Modal>
      )}

      {sessionExpired && (
        <Modal
          title="登录状态已失效"
          description="会话已过期或服务已经重启，请重新登录。"
          variant="display"
          onClose={goToLogin}
          className="is-compact"
        >
          <footer className="modal-actions">
            <button className="button is-primary" type="button" onClick={goToLogin}>
              返回登录页
            </button>
          </footer>
        </Modal>
      )}
    </div>
  );
}
