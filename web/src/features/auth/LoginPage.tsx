import { useMemo, useState, type FormEvent } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { ApiError } from "../../app/apiClient";
import { appConfig } from "../../app/config";
import { safeDestination } from "../../app/navigation";
import Icon from "../../ui/Icon";
import { useToast } from "../../ui/Toast";
import { login } from "./api";

export default function LoginPage() {
  const location = useLocation();
  const navigate = useNavigate();
  const { showToast } = useToast();
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
    try {
      await login(username.trim(), password);
      navigate(destination, { replace: true });
    } catch (error) {
      setInvalid(
        error instanceof ApiError && error.code === "invalid_credentials",
      );
      showToast(
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
            <h1 id="login-title">{appConfig.title}</h1>
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
              disabled={loading}
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
              disabled={loading}
              aria-invalid={invalid}
              onChange={(event) => setPassword(event.target.value)}
            />
          </div>

          <button className="button is-primary is-wide" type="submit" disabled={loading}>
            {loading && <span className="spinner is-small" />}
            {loading ? "正在登录" : "登录"}
          </button>
        </form>
      </section>
    </main>
  );
}
