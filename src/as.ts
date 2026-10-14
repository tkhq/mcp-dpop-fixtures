/**
 * Stub OAuth authorization server for the fixtures.
 *
 * - RFC 8414 metadata with `dpop_signing_alg_values_supported`.
 * - One pre-registered confidential client (`client_secret_basic`), grant
 *   type `client_credentials` only. No dynamic registration, no browser.
 * - The token endpoint requires a DPoP proof (RFC 9449 §5) and checks it:
 *   `typ`, asymmetric `alg`, public `jwk`, signature, `htm`, `htu`, `iat`
 *   window, and `jti` replay. It can also demand an AS nonce (RFC 9449 §8).
 * - It issues an ES256 JWT access token (`typ: at+jwt`) with `cnf.jkt`, and
 *   answers `token_type: "DPoP"`.
 */
import {
  base64url,
  calculateJwkThumbprint,
  decodeProtectedHeader,
  exportJWK,
  generateKeyPair,
  importJWK,
  jwtVerify,
  SignJWT,
  type JWK,
} from "jose";

export const CLIENT_ID = "fixture-client";
export const CLIENT_SECRET = "fixture-secret-not-a-real-secret";
export const SCOPE = "mcp";

export type AuthServerOptions = {
  /** Demand an AS-issued nonce in the token-request proof (RFC 9449 §8). */
  requireNonce?: boolean;
  /** Seconds either side of now that a proof `iat` may be. */
  iatSkewSeconds?: number;
};

export type AuthServer = {
  issuer: string;
  tokenEndpoint: string;
  publicJwk: JWK;
  /** Resources (RFC 8707) the AS will mint tokens for. Set after the RS starts. */
  allowedResources: Set<string>;
  /** Proof claims of every accepted token request, for the trace. */
  tokenRequests: { jkt: string; claims: Record<string, unknown>; nonceChallenged: boolean }[];
  /** Mint a token directly (tests). */
  mint(opts: { jkt?: string; resource: string; scope?: string; expiresIn?: number }): Promise<string>;
  stop(): void;
};

const ALGS = ["ES256", "ES384", "ES512", "RS256", "PS256", "EdDSA"];

function oauthError(status: number, error: string, description: string, headers: Record<string, string> = {}): Response {
  return Response.json({ error, error_description: description }, { status, headers: { "cache-control": "no-store", ...headers } });
}

export async function startAuthServer(opts: AuthServerOptions = {}): Promise<AuthServer> {
  const { privateKey, publicKey } = await generateKeyPair("ES256");
  const publicJwk = { ...(await exportJWK(publicKey)), alg: "ES256", use: "sig" };
  const kid = await calculateJwkThumbprint(publicJwk);
  const seenJti = new Map<string, number>();
  const nonces = new Map<string, number>();
  const skew = opts.iatSkewSeconds ?? 60;
  const allowedResources = new Set<string>();
  const tokenRequests: AuthServer["tokenRequests"] = [];

  let issuer = "";
  let tokenEndpoint = "";

  async function mint(o: { jkt?: string; resource: string; scope?: string; expiresIn?: number }): Promise<string> {
    const jwt = new SignJWT({ scope: o.scope ?? SCOPE, client_id: CLIENT_ID, ...(o.jkt ? { cnf: { jkt: o.jkt } } : {}) })
      .setProtectedHeader({ alg: "ES256", typ: "at+jwt", kid })
      .setIssuer(issuer)
      .setSubject(CLIENT_ID)
      .setAudience(o.resource)
      .setIssuedAt()
      .setJti(crypto.randomUUID())
      .setExpirationTime(`${o.expiresIn ?? 600}s`);
    return jwt.sign(privateKey);
  }

  function issueNonce(): string {
    const n = base64url.encode(crypto.getRandomValues(new Uint8Array(16)));
    nonces.set(n, Date.now() + 5 * 60_000);
    return n;
  }

  async function token(req: Request): Promise<Response> {
    const basic = req.headers.get("authorization");
    const expected = `Basic ${btoa(`${encodeURIComponent(CLIENT_ID)}:${encodeURIComponent(CLIENT_SECRET)}`)}`;
    if (basic !== expected) return oauthError(401, "invalid_client", "client authentication failed");
    const form = new URLSearchParams(await req.text());
    if (form.get("grant_type") !== "client_credentials") return oauthError(400, "unsupported_grant_type", "only client_credentials");
    const resource = form.get("resource");
    if (!resource || !allowedResources.has(resource.replace(/\/$/, ""))) {
      return oauthError(400, "invalid_target", `unknown resource ${resource}`);
    }

    // RFC 9449 §4.3, at the token endpoint.
    const proof = req.headers.get("dpop");
    if (!proof) return oauthError(400, "invalid_dpop_proof", "missing DPoP header");
    let header: ReturnType<typeof decodeProtectedHeader>;
    try {
      header = decodeProtectedHeader(proof);
    } catch {
      return oauthError(400, "invalid_dpop_proof", "malformed proof");
    }
    if (header.typ !== "dpop+jwt") return oauthError(400, "invalid_dpop_proof", "typ must be dpop+jwt");
    if (!header.alg || !ALGS.includes(header.alg)) return oauthError(400, "invalid_dpop_proof", "unsupported alg");
    const jwk = header.jwk as JWK | undefined;
    if (!jwk || "d" in jwk || "k" in jwk) return oauthError(400, "invalid_dpop_proof", "jwk must be a public key");
    let claims: Record<string, unknown>;
    try {
      const key = await importJWK(jwk, header.alg);
      ({ payload: claims } = await jwtVerify(proof, key, { typ: "dpop+jwt", algorithms: ALGS }));
    } catch (e) {
      return oauthError(400, "invalid_dpop_proof", `signature: ${(e as Error).message}`);
    }
    if (claims.htm !== "POST") return oauthError(400, "invalid_dpop_proof", "htm mismatch");
    if (claims.htu !== tokenEndpoint) return oauthError(400, "invalid_dpop_proof", `htu mismatch: ${claims.htu}`);
    const now = Math.floor(Date.now() / 1000);
    if (typeof claims.iat !== "number" || Math.abs(now - claims.iat) > skew) return oauthError(400, "invalid_dpop_proof", "iat outside window");
    if (typeof claims.jti !== "string" || !claims.jti) return oauthError(400, "invalid_dpop_proof", "missing jti");
    if (seenJti.has(claims.jti)) return oauthError(400, "invalid_dpop_proof", "jti replayed");
    seenJti.set(claims.jti, now);

    let nonceChallenged = false;
    if (opts.requireNonce) {
      const n = typeof claims.nonce === "string" ? claims.nonce : undefined;
      const exp = n ? nonces.get(n) : undefined;
      if (!exp || exp < Date.now()) {
        // RFC 9449 §8: 400 use_dpop_nonce with a DPoP-Nonce header.
        return oauthError(400, "use_dpop_nonce", "AS requires a nonce in the DPoP proof", { "DPoP-Nonce": issueNonce() });
      }
      nonceChallenged = true;
    }

    const jkt = await calculateJwkThumbprint(jwk);
    tokenRequests.push({ jkt, claims, nonceChallenged });
    const accessToken = await mint({ jkt, resource: resource.replace(/\/$/, "") });
    return Response.json(
      { access_token: accessToken, token_type: "DPoP", expires_in: 600, scope: SCOPE },
      { headers: { "cache-control": "no-store", ...(opts.requireNonce ? { "DPoP-Nonce": issueNonce() } : {}) } },
    );
  }

  const server = Bun.serve({
    port: 0,
    hostname: "localhost",
    async fetch(req) {
      const url = new URL(req.url);
      if (url.pathname === "/.well-known/oauth-authorization-server") {
        return Response.json({
          issuer,
          authorization_endpoint: `${issuer}/authorize`,
          token_endpoint: tokenEndpoint,
          response_types_supported: ["code"],
          grant_types_supported: ["client_credentials"],
          token_endpoint_auth_methods_supported: ["client_secret_basic"],
          code_challenge_methods_supported: ["S256"],
          dpop_signing_alg_values_supported: ALGS,
          scopes_supported: [SCOPE],
        });
      }
      if (url.pathname === "/token" && req.method === "POST") return token(req);
      if (url.pathname === "/jwks") return Response.json({ keys: [{ ...publicJwk, kid }] });
      return new Response("not found", { status: 404 });
    },
  });
  issuer = `http://localhost:${server.port}`;
  tokenEndpoint = `${issuer}/token`;

  return {
    issuer,
    tokenEndpoint,
    publicJwk: { ...publicJwk, kid },
    allowedResources,
    tokenRequests,
    mint,
    stop: () => server.stop(true),
  };
}

/** Access-token verification shared by both resource-server gates. */
export async function verifyAccessTokenJwt(token: string, as: { issuer: string; publicJwk: JWK }, resource: string) {
  const key = await importJWK(as.publicJwk, "ES256");
  const { payload } = await jwtVerify(token, key, { issuer: as.issuer, audience: resource, typ: "at+jwt", algorithms: ["ES256"] });
  return payload as {
    sub: string;
    client_id: string;
    scope: string;
    exp: number;
    aud: string;
    cnf?: { jkt?: string };
  };
}
