import { useMemo, useState, type FormEvent } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { appConfig } from "../../app/config";
import { safeDestination } from "../../app/navigation";
import Icon from "../../ui/Icon";
import { useToast } from "../../ui/Toast";
import { login } from "./api";

export default function LoginPage() {
  const location = useLocation();
  const navigate = useNavigate();
  const { showToast, updateToast } = useToast();
  const destination = useMemo(
    () => safeDestination(location.state),
    [location.state],
  );
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [invalid, setInvalid] = useState(false);

  const handleSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setInvalid(false);
    setLoading(true);
    const toastID = showToast("正在验证身份…", "loading", 0);
    try {
      await login(username.trim(), password);
      updateToast(toastID, "登录成功", "success");
      navigate(destination, { replace: true });
    } catch (error) {
      setInvalid(true);
      updateToast(
        toastID,
        error instanceof Error ? error.message : "登录失败，请重试",
        "error",
      );
    } finally {
      setLoading(false);
    }
  };

  return (
    <main className="login-page">
      <section className="login-panel" aria-labelledby="login-title">
        <header className="login-brand">
          <span className="brand-mark" aria-hidden="true">
            <Icon name="shield" />
          </span>
          <div>
            <p className="eyebrow">WIREGUARD PANEL</p>
            <h1 id="login-title">{appConfig.title}</h1>
            <p>使用环境变量配置的管理员账号进入应用</p>
          </div>
        </header>

        <form className="login-form" onSubmit={handleSubmit}>
          <label htmlFor="username">用户名</label>
          <div className="input-control">
            <Icon name="user" />
            <input
              id="username"
              name="username"
              value={username}
              autoComplete="username"
              autoFocus
              required
              aria-invalid={invalid}
              onChange={(event) => setUsername(event.target.value)}
            />
          </div>

          <label htmlFor="password">密码</label>
          <div className="input-control">
            <Icon name="lock" />
            <input
              id="password"
              name="password"
              type="password"
              value={password}
              autoComplete="current-password"
              required
              aria-invalid={invalid}
              onChange={(event) => setPassword(event.target.value)}
            />
          </div>

          <button className="button is-primary is-wide" type="submit" disabled={loading}>
            {loading && <span className="spinner is-small" />}
            {loading ? "正在登录" : "登录"}
          </button>
        </form>

        <footer className="login-footer">
          <Icon name="lock" />
          <span>本地密码认证 · HttpOnly Cookie 会话</span>
        </footer>
      </section>
    </main>
  );
}
