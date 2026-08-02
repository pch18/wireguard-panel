export type WireGuardKeyPair = {
  privateKey: string;
  publicKey: string;
};

const X25519_PKCS8_PREFIX = Uint8Array.from([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06,
  0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20,
]);
const X25519_PRIME = (1n << 255n) - 19n;
const X25519_A24 = 121665n;

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
  if (!globalThis.crypto?.getRandomValues) {
    throw new Error("当前浏览器不支持安全生成 WireGuard 密钥");
  }
  return globalThis.crypto;
}

function modulo(value: bigint) {
  const result = value % X25519_PRIME;
  return result < 0n ? result + X25519_PRIME : result;
}

function modularPower(base: bigint, exponent: bigint) {
  let result = 1n;
  let factor = modulo(base);
  let remaining = exponent;
  while (remaining > 0n) {
    if ((remaining & 1n) === 1n) result = modulo(result * factor);
    factor = modulo(factor * factor);
    remaining >>= 1n;
  }
  return result;
}

function littleEndianToBigInt(bytes: Uint8Array) {
  let value = 0n;
  for (let index = bytes.length - 1; index >= 0; index -= 1) {
    value = (value << 8n) | BigInt(bytes[index]);
  }
  return value;
}

function bigIntToLittleEndian(value: bigint, length: number) {
  const bytes = new Uint8Array(length);
  let remaining = value;
  for (let index = 0; index < length; index += 1) {
    bytes[index] = Number(remaining & 0xffn);
    remaining >>= 8n;
  }
  return bytes;
}

// RFC 7748 Montgomery ladder fallback for ordinary HTTP origins, where
// getRandomValues remains available but WebCrypto subtle/X25519 does not.
function deriveX25519PublicKey(rawPrivateKey: Uint8Array) {
  const scalarBytes = rawPrivateKey.slice();
  scalarBytes[0] &= 248;
  scalarBytes[31] &= 127;
  scalarBytes[31] |= 64;
  const scalar = littleEndianToBigInt(scalarBytes);
  const x1 = 9n;
  let x2 = 1n;
  let z2 = 0n;
  let x3 = x1;
  let z3 = 1n;
  let swap = 0n;

  for (let bit = 254n; bit >= 0n; bit -= 1n) {
    const scalarBit = (scalar >> bit) & 1n;
    swap ^= scalarBit;
    if (swap === 1n) {
      [x2, x3] = [x3, x2];
      [z2, z3] = [z3, z2];
    }
    swap = scalarBit;

    const a = modulo(x2 + z2);
    const aa = modulo(a * a);
    const b = modulo(x2 - z2);
    const bb = modulo(b * b);
    const e = modulo(aa - bb);
    const c = modulo(x3 + z3);
    const d = modulo(x3 - z3);
    const da = modulo(d * a);
    const cb = modulo(c * b);
    x3 = modulo((da + cb) * (da + cb));
    z3 = modulo(x1 * modulo((da - cb) * (da - cb)));
    x2 = modulo(aa * bb);
    z2 = modulo(e * modulo(aa + X25519_A24 * e));
  }
  if (swap === 1n) {
    [x2, x3] = [x3, x2];
    [z2, z3] = [z3, z2];
  }
  return bigIntToLittleEndian(
    modulo(x2 * modularPower(z2, X25519_PRIME - 2n)),
    32,
  );
}

async function deriveWithWebCrypto(rawPrivateKey: Uint8Array) {
  const subtle = globalThis.crypto?.subtle;
  if (!subtle) return undefined;
  try {
    const pkcs8 = new Uint8Array(
      X25519_PKCS8_PREFIX.length + rawPrivateKey.length,
    );
    pkcs8.set(X25519_PKCS8_PREFIX);
    pkcs8.set(rawPrivateKey, X25519_PKCS8_PREFIX.length);
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
    return new Uint8Array(
      await subtle.deriveBits(
        { name: "X25519", public: importedBasePoint },
        importedPrivateKey,
        256,
      ),
    );
  } catch {
    return undefined;
  }
}

export async function deriveWireGuardPublicKey(privateKey: string) {
  const rawPrivateKey = base64ToBytes(privateKey.trim());
  if (rawPrivateKey.length !== 32) {
    throw new Error("PrivateKey 必须是 WireGuard 使用的 32 字节 Base64 密钥");
  }
  const webCryptoPublicKey = await deriveWithWebCrypto(rawPrivateKey);
  return bytesToBase64(
    webCryptoPublicKey ?? deriveX25519PublicKey(rawPrivateKey),
  );
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
