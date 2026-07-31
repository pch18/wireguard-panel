export const sessionExpiredEvent = "pure-app:session-expired";

type ApiErrorBody = {
  error?: {
    code?: string;
    message?: string;
  };
};

export class ApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
    readonly code = "",
  ) {
    super(message);
    this.name = "ApiError";
  }
}

export function notifySessionExpired() {
  window.dispatchEvent(new Event(sessionExpiredEvent));
}

export async function request<T>(
  path: string,
  init?: RequestInit,
): Promise<T> {
  const response = await fetch(path, {
    credentials: "same-origin",
    ...init,
    headers: {
      Accept: "application/json",
      ...init?.headers,
    },
  });

  if (!response.ok) {
    const body = (await response.json().catch(() => ({}))) as ApiErrorBody;
    if (response.status === 401) {
      notifySessionExpired();
    }
    throw new ApiError(
      body.error?.message || `请求失败（${response.status}）`,
      response.status,
      body.error?.code,
    );
  }
  if (response.status === 204) {
    return undefined as T;
  }
  return (await response.json()) as T;
}

export function jsonRequest(method: string, body: unknown): RequestInit {
  return {
    method,
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  };
}
