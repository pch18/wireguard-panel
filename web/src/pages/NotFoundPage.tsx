import { Link } from "react-router-dom";
import Icon from "../ui/Icon";

export default function NotFoundPage() {
  return (
    <section className="not-found">
      <span>404</span>
      <h1>页面不存在</h1>
      <p>这个路由尚未接入页面框架。</p>
      <Link className="button is-primary" to="/">
        <Icon name="arrow-left" />
        返回首页
      </Link>
    </section>
  );
}
