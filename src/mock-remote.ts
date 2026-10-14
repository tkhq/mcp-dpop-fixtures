/**
 * A mock remote signing service, and the `DpopSigner` adapter for it.
 *
 * The service holds a P-256 key that the client process never sees. Like many
 * remote signing APIs, it returns the public key as SEC1 hex and each
 * signature as separate `r` and `s` hex values. It waits `delayMs` before each
 * answer, to stand in for the network round trip and the service's own work.
 *
 * Nothing here talks to a network. The point is to measure what one remote
 * signature per HTTP request costs the MCP client.
 */
import type { JWK } from "jose";
import type { DpopSigner } from "./external-session.ts";
import { joseSignature, publicKeyHexToJwk } from "./p256.ts";

export const DEFAULT_MOCK_DELAY_MS = 230;

const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");

export class MockRemoteSigningService {
  calls = 0;

  private constructor(
    private readonly privateKey: CryptoKey,
    /** Uncompressed SEC1 public key, hex (`04 || x || y`). */
    readonly publicKeyHex: string,
    readonly delayMs: number,
  ) {}

  static async create(opts: { delayMs?: number } = {}): Promise<MockRemoteSigningService> {
    const kp = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"])) as CryptoKeyPair;
    const raw = new Uint8Array(await crypto.subtle.exportKey("raw", kp.publicKey));
    return new MockRemoteSigningService(kp.privateKey, hex(raw), opts.delayMs ?? DEFAULT_MOCK_DELAY_MS);
  }

  /** Hash the UTF-8 payload with SHA-256 and sign it (ECDSA P-256). Returns `r` and `s` as hex. */
  async signPayload(payload: string): Promise<{ r: string; s: string }> {
    this.calls++;
    if (this.delayMs > 0) await Bun.sleep(this.delayMs);
    const sig = new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, this.privateKey, new TextEncoder().encode(payload)));
    // Drop leading zero bytes, as some services do, so the adapter has to pad.
    const trim = (b: Uint8Array) => hex(b).replace(/^(00)+/, "") || "00";
    return { r: trim(sig.slice(0, 32)), s: trim(sig.slice(32)) };
  }
}

/** Adapts a hex-returning signing service to the `DpopSigner` interface. */
export function remoteSigner(service: Pick<MockRemoteSigningService, "publicKeyHex" | "signPayload">): DpopSigner {
  return {
    alg: "ES256",
    publicJwk: publicKeyHexToJwk(service.publicKeyHex) as JWK,
    async sign(signingInput) {
      const { r, s } = await service.signPayload(signingInput);
      return joseSignature(r, s);
    },
  };
}
