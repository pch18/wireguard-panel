export function wireGuardKeyOnly(value: string) {
  return value.replace(/\s/g, "");
}

export function isWireGuardKey(value: string) {
  const key = value.trim();
  if (!/^[A-Za-z0-9+/]{43}=$/.test(key)) return false;
  try {
    const decoded = atob(key);
    return decoded.length === 32 && btoa(decoded) === key;
  } catch {
    return false;
  }
}
