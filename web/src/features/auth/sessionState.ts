export function isAnonymousSessionError(error: unknown) {
  return (
    error instanceof Error &&
    "status" in error &&
    (error as Error & { status?: unknown }).status === 401
  );
}

export function sessionLoadErrorMessage(error: unknown) {
  if (error instanceof Error && "status" in error) return error.message;
  return "暂时无法连接后端，请检查服务状态后重试";
}
