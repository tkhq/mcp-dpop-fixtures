/**
 * A duck-typed stand-in for the SDK's `DpopSession` whose private key lives
 * outside the process (a KMS, an HSM, a secure enclave, a remote signing
 * service, or a test mock).
 *
 * The SDK's `DpopSession` has a private constructor and signs with
 * `jose.SignJWT(...).sign(privateKey)`, which needs a WebCrypto `CryptoKey`.
 * A remote key has no `CryptoKey`, so this class builds the RFC 9449 §4.2
 * header and claims itself and hands the JWS signing input to `signer.sign`.
 *
 * At runtime the SDK (2.3.1) only calls `buildProof`, `observeNonce` and,
 * through our own `buildProof`, `nonceFor`. The public surface below mirrors
 * the SDK class so `thumbprint`, `alg` and `publicJwk` also work.
 */
import { base64url, calculateJwkThumbprint, type JWK } from "jose";
import type { DpopProofRequest, DpopSession } from "@modelcontextprotocol/client";

/** What an external key has to provide. */
export interface DpopSigner {
  alg: "ES256";
  publicJwk: JWK;
  /** Sign the ASCII JWS signing input; return the raw JWS signature (for ES256, 64-byte r || s). */
  sign(signingInput: string): Promise<Uint8Array>;
}

export type SignStats = { count: number; totalMs: number; samples: number[] };

async function sha256b64u(s: string): Promise<string> {
  return base64url.encode(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s))));
}

export class ExternalSignerDpopSession {
  private readonly nonces = new Map<string, string>();
  readonly stats: SignStats = { count: 0, totalMs: 0, samples: [] };

  private constructor(
    private readonly signer: DpopSigner,
    readonly thumbprint: string,
  ) {}

  static async create(signer: DpopSigner): Promise<ExternalSignerDpopSession> {
    if ("d" in signer.publicJwk) throw new Error("publicJwk must not contain a private key");
    return new ExternalSignerDpopSession(signer, await calculateJwkThumbprint(signer.publicJwk, "sha256"));
  }

  get alg(): "ES256" {
    return this.signer.alg;
  }

  get publicJwk(): JWK {
    return this.signer.publicJwk;
  }

  nonceFor(url: string | URL): string | undefined {
    return this.nonces.get(new URL(url.toString()).origin);
  }

  rememberNonce(url: string | URL, nonce: string): void {
    this.nonces.set(new URL(url.toString()).origin, nonce);
  }

  observeNonce(response: Response, url: string | URL): void {
    const nonce = response.headers.get("dpop-nonce");
    if (nonce) this.rememberNonce(url, nonce);
  }

  async buildProof(request: DpopProofRequest): Promise<string> {
    const u = new URL(request.htu.toString());
    const nonce = request.nonce ?? this.nonceFor(u);
    const claims: Record<string, unknown> = {
      jti: base64url.encode(crypto.getRandomValues(new Uint8Array(16))),
      htm: request.htm.toUpperCase(),
      htu: `${u.origin}${u.pathname}`,
      iat: Math.floor(Date.now() / 1000),
    };
    if (request.accessToken !== undefined) claims.ath = await sha256b64u(request.accessToken);
    if (nonce !== undefined) claims.nonce = nonce;
    const header = { alg: this.signer.alg, typ: "dpop+jwt", jwk: this.signer.publicJwk };
    const signingInput = `${base64url.encode(JSON.stringify(header))}.${base64url.encode(JSON.stringify(claims))}`;
    const started = performance.now();
    const sig = await this.signer.sign(signingInput);
    const ms = performance.now() - started;
    this.stats.count++;
    this.stats.totalMs += ms;
    this.stats.samples.push(ms);
    return `${signingInput}.${base64url.encode(sig)}`;
  }

  /**
   * The cast an external signer needs today. `DpopSession` has private members, so TypeScript
   * will not accept this class structurally; see probes/ducktype.ts for the
   * exact errors.
   */
  asDpopSession(): DpopSession {
    return this as unknown as DpopSession;
  }
}

/** A local WebCrypto P-256 key behind the `DpopSigner` interface (mock signer, optional added latency). */
export async function localSigner(opts: { delayMs?: number } = {}): Promise<DpopSigner> {
  const kp = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"])) as CryptoKeyPair;
  const jwk = await crypto.subtle.exportKey("jwk", kp.publicKey);
  const publicJwk: JWK = { kty: "EC", crv: "P-256", x: jwk.x!, y: jwk.y! };
  return {
    alg: "ES256",
    publicJwk,
    async sign(signingInput) {
      if (opts.delayMs) await Bun.sleep(opts.delayMs);
      // WebCrypto ECDSA already returns IEEE P1363 r || s, which is what JWS wants.
      return new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, kp.privateKey, new TextEncoder().encode(signingInput)));
    },
  };
}
