/**
 * P-256 helpers for remote signers that return hex: a SEC1 public key to a
 * JWK, and separate `r` and `s` hex values to the 64-byte JOSE `r || s`
 * signature.
 */
import { base64url, calculateJwkThumbprint, type JWK } from "jose";

/** P-256 field prime, curve constant b, and group order. */
const P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn;
const B = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604bn;
export const N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;

export type PublicJwk = { kty: "EC"; crv: "P-256"; x: string; y: string };

export function fromHex(h: string): Uint8Array {
  const clean = h.startsWith("0x") ? h.slice(2) : h;
  if (clean.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(clean)) throw new Error("invalid hex");
  return Uint8Array.from(clean.match(/../g) ?? [], (b) => parseInt(b, 16));
}

function toBig(b: Uint8Array): bigint {
  return BigInt("0x" + (Buffer.from(b).toString("hex") || "0"));
}

function toBytes32(n: bigint): Uint8Array {
  return fromHex(n.toString(16).padStart(64, "0"));
}

function modPow(base: bigint, exp: bigint, mod: bigint): bigint {
  let result = 1n;
  base %= mod;
  while (exp > 0n) {
    if (exp & 1n) result = (result * base) % mod;
    base = (base * base) % mod;
    exp >>= 1n;
  }
  return result;
}

/**
 * Converts a SEC1 public key (compressed `02`/`03` or uncompressed `04`), as
 * many signing services return it in hex, to a public JWK.
 */
export function publicKeyHexToJwk(publicKeyHex: string): PublicJwk {
  const bytes = fromHex(publicKeyHex);
  let x: Uint8Array;
  let y: Uint8Array;
  if (bytes.length === 65 && bytes[0] === 0x04) {
    x = bytes.slice(1, 33);
    y = bytes.slice(33);
  } else if (bytes.length === 33 && (bytes[0] === 0x02 || bytes[0] === 0x03)) {
    x = bytes.slice(1);
    const xn = toBig(x);
    const rhs = (((xn * xn * xn - 3n * xn + B) % P) + P) % P;
    // P ≡ 3 (mod 4), so the square root is rhs^((P+1)/4).
    let yn = modPow(rhs, (P + 1n) / 4n, P);
    if ((yn * yn) % P !== rhs) throw new Error("point is not on P-256");
    if (Number(yn & 1n) !== (bytes[0] & 1)) yn = P - yn;
    y = toBytes32(yn);
  } else {
    throw new Error("expected a 33- or 65-byte SEC1 P-256 public key");
  }
  return { kty: "EC", crv: "P-256", x: base64url.encode(x), y: base64url.encode(y) };
}

/** RFC 7638 thumbprint, used as `kid`. */
export function jwkKid(jwk: PublicJwk): Promise<string> {
  return calculateJwkThumbprint(jwk as JWK, "sha256");
}

/**
 * Converts `r` and `s` hex values to a JOSE signature. A service can drop
 * leading zeros, so each value is left-padded to 32 bytes. `s` is not changed
 * to low-s form: ES256 does not require it.
 */
export function joseSignature(rHex: string, sHex: string): Uint8Array {
  const r = toBig(fromHex(rHex.length % 2 ? "0" + rHex : rHex));
  const s = toBig(fromHex(sHex.length % 2 ? "0" + sHex : sHex));
  if (r <= 0n || r >= N || s <= 0n || s >= N) throw new Error("signature value out of range");
  const out = new Uint8Array(64);
  out.set(toBytes32(r), 0);
  out.set(toBytes32(s), 32);
  return out;
}
