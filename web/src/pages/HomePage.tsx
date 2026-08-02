import Icon from "../ui/Icon";

export default function HomePage() {
  return (
    <div className="page workspace-home">
      <section className="workspace-welcome">
        <span className="workspace-welcome-icon">
          <Icon name="network" />
        </span>
        <h1>选择一个 Interface</h1>
      </section>
    </div>
  );
}
