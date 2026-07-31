import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { ApiError } from "../app/apiClient";
import {
  deleteInterface,
  listInterfaces,
  type WireGuardInterface,
} from "../features/wireguard/api";
import Icon from "../ui/Icon";
import Modal from "../ui/Modal";
import { useToast } from "../ui/Toast";

export default function HomePage() {
  const { showToast, updateToast } = useToast();
  const [interfaces, setInterfaces] = useState<WireGuardInterface[]>([]);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState("");
  const [deleting, setDeleting] = useState<WireGuardInterface | null>(null);
  const [deletePending, setDeletePending] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    setLoadError("");
    try {
      setInterfaces(await listInterfaces());
    } catch (error) {
      const message =
        error instanceof Error ? error.message : "Interface 列表加载失败";
      setLoadError(message);
      showToast(message, "error");
    } finally {
      setLoading(false);
    }
  }, [showToast]);

  useEffect(() => {
    void load();
  }, [load]);

  const confirmDelete = async () => {
    if (!deleting) return;
    setDeletePending(true);
    const toastID = showToast(`正在删除 ${deleting.filename}…`, "loading", 0);
    try {
      await deleteInterface(deleting.id, deleting.revision);
      setInterfaces((current) =>
        current.filter((item) => item.id !== deleting.id),
      );
      updateToast(toastID, `${deleting.filename} 已删除`, "success");
      setDeleting(null);
    } catch (error) {
      if (error instanceof ApiError && error.status === 412) {
        updateToast(
          toastID,
          "该配置已被另一个客户端修改，列表已刷新，请重新确认后再删除。",
          "warning",
          6_000,
        );
        setDeleting(null);
        await load();
        return;
      }
      updateToast(
        toastID,
        error instanceof Error ? error.message : "删除 Interface 失败",
        "error",
      );
    } finally {
      setDeletePending(false);
    }
  };

  return (
    <div className="page interfaces-page">
      <header className="page-header is-compact">
        <div>
          <p className="eyebrow">WIREGUARD</p>
          <h1>Interfaces</h1>
          <p>每个 Interface 对应一个独立的原生配置文件。</p>
        </div>
        <Link className="button is-primary" to="/interfaces/new">
          <Icon name="plus" />
          新建 Interface
        </Link>
      </header>

      <section className="summary-strip" aria-label="Interface 概览">
        <div>
          <span>Interfaces</span>
          <strong>{interfaces.length}</strong>
        </div>
        <div>
          <span>Peers</span>
          <strong>
            {interfaces.reduce((total, item) => total + item.peers.length, 0)}
          </strong>
        </div>
        <div>
          <span>存储方式</span>
          <strong>原生 .conf</strong>
        </div>
      </section>

      {loading ? (
        <section className="content-state" aria-live="polite">
          <span className="spinner" />
          <h2>正在读取配置目录</h2>
          <p>解析所有 wg&lt;ID&gt;.conf 文件…</p>
        </section>
      ) : loadError ? (
        <section className="content-state is-error">
          <Icon name="alert" />
          <h2>配置暂时无法读取</h2>
          <p>{loadError}</p>
          <button className="button" type="button" onClick={() => void load()}>
            <Icon name="refresh" />
            重新加载
          </button>
        </section>
      ) : interfaces.length === 0 ? (
        <section className="content-state">
          <span className="empty-workspace-icon">
            <Icon name="network" />
          </span>
          <p className="section-kicker">NO INTERFACES</p>
          <h2>还没有 WireGuard Interface</h2>
          <p>创建第一个配置，系统会自动分配 wg0.conf。</p>
          <Link className="button is-primary" to="/interfaces/new">
            <Icon name="plus" />
            创建 wg0.conf
          </Link>
        </section>
      ) : (
        <section className="interface-grid" aria-label="Interface 列表">
          {interfaces.map((config) => (
            <article className="interface-card" key={config.id}>
              <div className="interface-card-head">
                <span className="interface-glyph">
                  <Icon name="network" />
                </span>
                <div>
                  <h2>{config.name}</h2>
                  <code>{config.filename}</code>
                </div>
                <span className="id-badge">ID {config.id}</span>
              </div>

              <dl className="interface-facts">
                <div>
                  <dt>Address</dt>
                  <dd>
                    {config.address.length > 0
                      ? config.address.join(", ")
                      : "未配置"}
                  </dd>
                </div>
                <div>
                  <dt>ListenPort</dt>
                  <dd>{config.listenPort ?? "自动"}</dd>
                </div>
                <div>
                  <dt>Peers</dt>
                  <dd>{config.peers.length}</dd>
                </div>
              </dl>

              <footer className="interface-card-actions">
                <Link
                  className="button is-quiet"
                  to={`/interfaces/${config.id}`}
                >
                  <Icon name="edit" />
                  编辑配置
                </Link>
                <button
                  className="button is-danger-quiet"
                  type="button"
                  onClick={() => setDeleting(config)}
                >
                  <Icon name="trash" />
                  删除
                </button>
              </footer>
            </article>
          ))}
        </section>
      )}

      {deleting && (
        <Modal
          title={`删除 ${deleting.filename}`}
          description={`将永久删除“${deleting.name}”以及其中的 ${deleting.peers.length} 个 Peer。`}
          variant="display"
          onClose={() => setDeleting(null)}
          className="is-compact"
        >
          <div className="danger-note">
            <Icon name="alert" />
            <p>
              配置文件会从 WireGuard 目录中删除，此操作不会自动停止已经运行的
              Interface。
            </p>
          </div>
          <footer className="modal-actions">
            <button
              className="button"
              type="button"
              onClick={() => setDeleting(null)}
            >
              取消
            </button>
            <button
              className="button is-danger"
              type="button"
              disabled={deletePending}
              onClick={() => void confirmDelete()}
            >
              {deletePending && <span className="spinner is-small" />}
              {deletePending ? "删除中" : "确认删除"}
            </button>
          </footer>
        </Modal>
      )}
    </div>
  );
}
