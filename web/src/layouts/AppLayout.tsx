import { useCallback, useEffect, useRef, useState } from "react";
import {
  Link,
  NavLink,
  Outlet,
  useLocation,
  useNavigate,
} from "react-router-dom";
import { ApiError, sessionExpiredEvent } from "../app/apiClient";
import { appConfig } from "../app/config";
import { logout } from "../features/auth/api";
import { useAuth } from "../features/auth/AuthContext";
import ChangePasswordModal from "../features/auth/ChangePasswordModal";
import InterfaceModal from "../features/wireguard/InterfaceModal";
import {
  createInterface,
  deleteInterface,
  interfacesChangedEvent,
  listInterfaces,
  nextInterfaceName,
  type InterfaceInput,
  type WireGuardInterface,
} from "../features/wireguard/api";
import Icon from "../ui/Icon";
import Modal from "../ui/Modal";
import { useToast } from "../ui/Toast";

export default function AppLayout() {
  const location = useLocation();
  const navigate = useNavigate();
  const { session } = useAuth();
  const { showToast, updateToast, dismissToast } = useToast();
  const [interfaces, setInterfaces] = useState<WireGuardInterface[]>([]);
  const [interfacesLoading, setInterfacesLoading] = useState(true);
  const [inventoryReady, setInventoryReady] = useState(false);
  const [interfacesError, setInterfacesError] = useState("");
  const [inventoryWarning, setInventoryWarning] = useState("");
  const [occupiedNames, setOccupiedNames] = useState<string[]>([]);
  const [mobileNavOpen, setMobileNavOpen] = useState(false);
  const [passwordOpen, setPasswordOpen] = useState(false);
  const [createOpen, setCreateOpen] = useState(false);
  const [createPending, setCreatePending] = useState(false);
  const [logoutOpen, setLogoutOpen] = useState(false);
  const [sessionExpired, setSessionExpired] = useState(false);
  const [logoutPending, setLogoutPending] = useState(false);
  const [deleting, setDeleting] = useState<WireGuardInterface | null>(null);
  const [deletePending, setDeletePending] = useState(false);
  const inventoryRequestRef = useRef(0);
  const displayName = session.user.name || session.user.username;

  const loadInterfaces = useCallback(async () => {
    const requestID = ++inventoryRequestRef.current;
    setInterfacesLoading(true);
    setInventoryReady(false);
    setInterfacesError("");
    setInventoryWarning("");
    try {
      const inventory = await listInterfaces();
      if (requestID !== inventoryRequestRef.current) return;
      setInterfaces(inventory.interfaces);
      setOccupiedNames(inventory.occupiedNames);
      setInventoryReady(true);
      setInventoryWarning(
        inventory.problems
          .map((problem) => `${problem.filename}：${problem.message}`)
          .join("；"),
      );
      return inventory;
    } catch (error) {
      if (requestID !== inventoryRequestRef.current) return;
      const message =
        error instanceof Error ? error.message : "Interface 列表加载失败";
      setInterfacesError(message);
      return undefined;
    } finally {
      if (requestID === inventoryRequestRef.current) {
        setInterfacesLoading(false);
      }
    }
  }, []);

  useEffect(() => {
    void loadInterfaces();
  }, [loadInterfaces]);

  useEffect(() => {
    if (
      interfacesLoading ||
      interfacesError ||
      interfaces.length === 0 ||
      location.pathname !== "/"
    ) {
      return;
    }

    navigate(`/interfaces/${encodeURIComponent(interfaces[0].id)}`, {
      replace: true,
    });
  }, [
    interfaces,
    interfacesError,
    interfacesLoading,
    location.pathname,
    navigate,
  ]);

  useEffect(() => {
    const refresh = () => {
      void loadInterfaces();
    };
    window.addEventListener(interfacesChangedEvent, refresh);
    return () => window.removeEventListener(interfacesChangedEvent, refresh);
  }, [loadInterfaces]);

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
    if (!mobileNavOpen) return;
    const close = (event: KeyboardEvent) => {
      if (event.key === "Escape") setMobileNavOpen(false);
    };
    document.addEventListener("keydown", close);
    return () => document.removeEventListener("keydown", close);
  }, [mobileNavOpen]);

  const handleLogout = async () => {
    setLogoutPending(true);
    try {
      await logout();
      navigate("/login", { replace: true });
    } catch (error) {
      showToast(
        error instanceof Error ? error.message : "退出失败",
        "error",
      );
    } finally {
      setLogoutPending(false);
      setLogoutOpen(false);
    }
  };

  const confirmDelete = async () => {
    if (!deleting) return;
    setDeletePending(true);
    const toastID = showToast(
      `正在停止并删除 ${deleting.filename}…`,
      "loading",
      0,
    );
    try {
      await deleteInterface(deleting.id, deleting.revision);
      setInterfaces((current) =>
        current.filter((item) => item.id !== deleting.id),
      );
      dismissToast(toastID);
      if (location.pathname === `/interfaces/${encodeURIComponent(deleting.id)}`) {
        navigate("/", { replace: true });
      }
      setDeleting(null);
      setMobileNavOpen(false);
    } catch (error) {
      if (error instanceof ApiError && error.status === 412) {
        updateToast(
          toastID,
          "配置已更新，请重新确认后删除。",
          "warning",
          6_000,
        );
        setDeleting(null);
        await loadInterfaces();
      } else {
        const inventory =
          !(error instanceof ApiError) || error.status >= 500
            ? await loadInterfaces()
            : undefined;
        if (
          !(error instanceof ApiError) &&
          inventory &&
          !inventory.occupiedNames.includes(deleting.id)
        ) {
          updateToast(
            toastID,
            "响应中断，但已确认后端已删除 Interface。",
            "warning",
            8_000,
          );
          if (
            location.pathname ===
            `/interfaces/${encodeURIComponent(deleting.id)}`
          ) {
            navigate("/", { replace: true });
          }
          setDeleting(null);
          setMobileNavOpen(false);
          return;
        }
        updateToast(
          toastID,
          `${error instanceof Error ? error.message : "删除 Interface 失败"}${
            inventory ? "；已重新同步后端当前状态" : ""
          }`,
          "error",
        );
      }
    } finally {
      setDeletePending(false);
    }
  };

  const create = async (input: InterfaceInput, name?: string) => {
    setCreatePending(true);
    const toastID = showToast("正在创建 Interface…", "loading", 0);
    try {
      const created = await createInterface(name ?? "", input);
      setCreateOpen(false);
      setMobileNavOpen(false);
      dismissToast(toastID);
      navigate(`/interfaces/${encodeURIComponent(created.id)}`);
    } catch (error) {
      if (error instanceof ApiError && error.status === 409) {
        updateToast(
          toastID,
          "名称已被占用，请重试。",
          "warning",
          6_000,
        );
        await loadInterfaces();
      } else {
        const inventory =
          !(error instanceof ApiError) || error.status >= 500
            ? await loadInterfaces()
            : undefined;
        const reconciled = inventory?.interfaces.find(
          (item) => item.id === (name ?? ""),
        );
        if (!(error instanceof ApiError) && reconciled) {
          setCreateOpen(false);
          setMobileNavOpen(false);
          updateToast(
            toastID,
            "响应中断，但已确认后端已创建 Interface。",
            "warning",
            8_000,
          );
          navigate(`/interfaces/${encodeURIComponent(reconciled.id)}`);
          return;
        }
        updateToast(
          toastID,
          `${error instanceof Error ? error.message : "Interface 创建失败"}${
            inventory ? "；已重新同步后端当前状态" : ""
          }`,
          "error",
        );
      }
    } finally {
      setCreatePending(false);
    }
  };

  const openCreate = () => {
    setCreateOpen(true);
    setMobileNavOpen(false);
  };

  const closeMobileNav = () => setMobileNavOpen(false);

  return (
    <div className="app-shell">
      {mobileNavOpen && (
        <button
          className="mobile-nav-backdrop"
          type="button"
          aria-label="关闭 Interface 侧栏"
          onClick={closeMobileNav}
        />
      )}
      <aside className={`sidebar ${mobileNavOpen ? "is-open" : ""}`}>
        <div className="sidebar-brand">
          <Link className="sidebar-brand-link" to="/" onClick={closeMobileNav}>
            <span className="brand-mark is-small">
              <Icon name="shield" />
            </span>
            <div>
              <strong>{appConfig.title}</strong>
            </div>
          </Link>
          <button
            className="icon-button sidebar-close"
            type="button"
            aria-label="关闭 Interface 侧栏"
            onClick={closeMobileNav}
          >
            <Icon name="close" />
          </button>
        </div>

        <section className="sidebar-interfaces" aria-labelledby="interfaces-title">
          <header className="sidebar-section-heading">
            <div>
              <span id="interfaces-title">Interfaces</span>
              {!interfacesLoading && <small>{occupiedNames.length} 个</small>}
            </div>
            <button
              className="sidebar-add-interface"
              type="button"
              aria-label="添加 Interface"
              title={
                !inventoryReady
                  ? "请等待 Interface 清单加载完成"
                  : "添加 Interface"
              }
              disabled={!inventoryReady || createPending}
              onClick={openCreate}
            >
              <Icon name="plus" />
            </button>
          </header>

          {inventoryWarning && (
            <div
              className="sidebar-inventory-warning"
              role="status"
              title={inventoryWarning}
            >
              <Icon name="alert" />
              <span>部分配置无法解析</span>
            </div>
          )}

          <nav className="interface-nav" aria-label="Interface 列表">
            {interfacesLoading ? (
              <div className="sidebar-list-state" aria-live="polite">
                <span className="spinner is-small" />
                <span>正在读取配置…</span>
              </div>
            ) : interfacesError ? (
              <div className="sidebar-list-state is-error">
                <Icon name="alert" />
                <span>{interfacesError}</span>
                <button
                  type="button"
                  onClick={() => {
                    void loadInterfaces();
                  }}
                >
                  重新加载
                </button>
              </div>
            ) : interfaces.length === 0 ? (
              <div className="sidebar-list-state">
                <Icon name="network" />
                <span>暂无 Interface</span>
              </div>
            ) : (
              interfaces.map((config) => (
                <div className="interface-nav-item" key={config.id}>
                  <NavLink
                    className="interface-nav-link"
                    to={`/interfaces/${encodeURIComponent(config.id)}`}
                    onClick={closeMobileNav}
                  >
                    <span className="interface-nav-icon">
                      <Icon name="network" />
                    </span>
                    <span className="interface-nav-copy">
                      <strong>{config.filename}</strong>
                      <small>
                        {config.peers?.length ?? 0} Peer
                        {(config.validationErrors?.length ?? 0) > 0
                          ? " · 配置待修正"
                          : ""}
                      </small>
                    </span>
                  </NavLink>
                  <button
                    className="interface-nav-delete"
                    type="button"
                    aria-label={`删除 ${config.filename}`}
                    title="删除 Interface"
                    onClick={() => setDeleting(config)}
                  >
                    <Icon name="trash" />
                  </button>
                </div>
              ))
            )}
          </nav>
        </section>

        <div className="sidebar-account">
          <div className="sidebar-user">
            <span className="avatar">
              {Array.from(displayName)[0]?.toUpperCase()}
            </span>
            <span>
              <strong>{displayName}</strong>
              {displayName !== session.user.username && (
                <small>{session.user.username}</small>
              )}
            </span>
          </div>
          <div className="sidebar-account-actions">
            <button type="button" onClick={() => setPasswordOpen(true)}>
              <Icon name="key" />
              修改密码
            </button>
            <button
              className="is-danger"
              type="button"
              onClick={() => setLogoutOpen(true)}
            >
              <Icon name="logout" />
              退出
            </button>
          </div>
        </div>
      </aside>

      <div className="app-column">
        <button
          className="mobile-sidebar-toggle"
          type="button"
          aria-label="打开 Interface 侧栏"
          onClick={() => setMobileNavOpen(true)}
        >
          <Icon name="menu" />
        </button>
        <main className="app-content">
          <Outlet />
        </main>
      </div>

      {deleting && (
        <Modal
          title={`删除 ${deleting.filename}`}
          description={`将停止并永久删除此 Interface 及其中的 ${deleting.peers.length} 个 Peer。`}
          variant="display"
          closeDisabled={deletePending}
          onClose={() => setDeleting(null)}
          className="is-compact"
        >
          <footer className="modal-actions">
            <button className="button" type="button" disabled={deletePending} onClick={() => setDeleting(null)}>
              取消
            </button>
            <button
              className="button is-danger"
              type="button"
              disabled={deletePending}
              onClick={() => void confirmDelete()}
            >
              {deletePending && <span className="spinner is-small" />}
              {deletePending ? "停止并删除中" : "确认删除"}
            </button>
          </footer>
        </Modal>
      )}

      {createOpen && (
        <InterfaceModal
          defaultName={nextInterfaceName(occupiedNames)}
          pending={createPending}
          onClose={() => setCreateOpen(false)}
          onSubmit={(input, name) => void create(input, name)}
        />
      )}

      {logoutOpen && (
        <Modal
          title="退出登录？"
          variant="display"
          closeDisabled={logoutPending}
          onClose={() => setLogoutOpen(false)}
          className="is-compact"
        >
          <footer className="modal-actions">
            <button
              className="button"
              type="button"
              disabled={logoutPending}
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

      {passwordOpen && (
        <ChangePasswordModal onClose={() => setPasswordOpen(false)} />
      )}

      {sessionExpired && (
        <Modal
          title="登录状态已失效"
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
