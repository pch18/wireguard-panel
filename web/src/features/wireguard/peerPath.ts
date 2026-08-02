export function peerPublicKeyPath(publicKey: string) {
  return publicKey
    .trim()
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}
