import { Link } from "react-router-dom";
import Icon from "../ui/Icon";

export default function NotFoundPage() {
  return (
    <section className="not-found">
      <span>404</span>
      <h1>页面不存在</h1>
      <Link className="button is-primary" to="/">
        <Icon name="arrow-left" />
        返回首页
      </Link>
    </section>
  );
}
