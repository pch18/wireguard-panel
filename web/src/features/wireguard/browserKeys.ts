export type WireGuardKeyPair = {
  privateKey: string;
  publicKey: string;
};

const X25519_PKCS8_PREFIX = Uint8Array.from([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06,
  0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20,
]);

function bytesToBase64(bytes: Uint8Array) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function base64ToBytes(value: string) {
  const binary = atob(value);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

function browserCrypto() {
  if (!globalThis.crypto?.subtle || !globalThis.crypto.getRandomValues) {
    throw new Error("当前浏览器不支持本地生成 WireGuard 密钥");
  }
  return globalThis.crypto;
}

export async function deriveWireGuardPublicKey(privateKey: string) {
  const rawPrivateKey = base64ToBytes(privateKey.trim());
  if (rawPrivateKey.length !== 32) {
    throw new Error("PrivateKey 必须是 WireGuard 使用的 32 字节 Base64 密钥");
  }
  const pkcs8 = new Uint8Array(X25519_PKCS8_PREFIX.length + rawPrivateKey.length);
  pkcs8.set(X25519_PKCS8_PREFIX);
  pkcs8.set(rawPrivateKey, X25519_PKCS8_PREFIX.length);
  const subtle = browserCrypto().subtle;
  const importedPrivateKey = await subtle.importKey(
    "pkcs8",
    pkcs8,
    { name: "X25519" },
    false,
    ["deriveBits"],
  );
  const basePoint = new Uint8Array(32);
  basePoint[0] = 9;
  const importedBasePoint = await subtle.importKey(
    "raw",
    basePoint,
    { name: "X25519" },
    false,
    [],
  );
  const publicKey = await subtle.deriveBits(
    { name: "X25519", public: importedBasePoint },
    importedPrivateKey,
    256,
  );
  return bytesToBase64(new Uint8Array(publicKey));
}

export async function generateWireGuardKeyPair(): Promise<WireGuardKeyPair> {
  const privateBytes = browserCrypto().getRandomValues(new Uint8Array(32));
  privateBytes[0] &= 248;
  privateBytes[31] &= 127;
  privateBytes[31] |= 64;
  const privateKey = bytesToBase64(privateBytes);
  return {
    privateKey,
    publicKey: await deriveWireGuardPublicKey(privateKey),
  };
}

export function generateWireGuardPresharedKey() {
  return bytesToBase64(browserCrypto().getRandomValues(new Uint8Array(32)));
}
