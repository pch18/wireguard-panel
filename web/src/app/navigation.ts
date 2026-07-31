export type LoginDestinationState = {
  from?: {
    pathname?: string;
    search?: string;
    hash?: string;
  };
};

export function safeDestination(state: unknown) {
  const from = (state as LoginDestinationState | null)?.from;
  if (!from?.pathname?.startsWith("/") || from.pathname.startsWith("//")) {
    return "/";
  }
  return `${from.pathname}${from.search || ""}${from.hash || ""}`;
}
