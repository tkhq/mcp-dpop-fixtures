import { base64url, calculateJwkThumbprint, exportJWK, generateKeyPair, SignJWT, type JWK } from "jose";

export type TestKey = { privateKey: CryptoKey; publicJwk: JWK; jkt: string };

export async function newKey(alg: "ES256" | "ES384" = "ES256"): Promise<TestKey> {
  const { privateKey, publicKey } = await generateKeyPair(alg, { extractable: true });
  const publicJwk = await exportJWK(publicKey);
  return { privateKey: privateKey as CryptoKey, publicJwk, jkt: await calculateJwkThumbprint(publicJwk) };
}

export async function ath(token: string): Promise<string> {
  return base64url.encode(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(token))));
}

export type ProofOpts = {
  key: TestKey;
  htm?: string;
  htu: string;
  token?: string;
  /** Override or delete (`null`) claims. */
  claims?: Record<string, unknown | null>;
  /** Override header members. */
  header?: Record<string, unknown>;
  alg?: string;
};

export async function proof(o: ProofOpts): Promise<string> {
  const claims: Record<string, unknown> = {
    jti: crypto.randomUUID(),
    htm: o.htm ?? "POST",
    htu: o.htu,
    iat: Math.floor(Date.now() / 1000),
  };
  if (o.token !== undefined) claims.ath = await ath(o.token);
  for (const [k, v] of Object.entries(o.claims ?? {})) {
    if (v === null) delete claims[k];
    else claims[k] = v;
  }
  return new SignJWT(claims)
    .setProtectedHeader({ alg: o.alg ?? "ES256", typ: "dpop+jwt", jwk: o.key.publicJwk, ...(o.header ?? {}) } as never)
    .sign(o.key.privateKey);
}

/** An unsigned (`alg: none`) proof, built by hand since jose refuses to make one. */
export function unsignedProof(publicJwk: JWK, htu: string): string {
  const h = base64url.encode(JSON.stringify({ alg: "none", typ: "dpop+jwt", jwk: publicJwk }));
  const p = base64url.encode(JSON.stringify({ jti: crypto.randomUUID(), htm: "POST", htu, iat: Math.floor(Date.now() / 1000) }));
  return `${h}.${p}.`;
}

export function mcpRequest(url: string, auth: string | undefined, dpop: string | string[] | undefined, method = "POST"): Request {
  const headers = new Headers({ "content-type": "application/json", accept: "application/json, text/event-stream" });
  if (auth) headers.set("authorization", auth);
  if (typeof dpop === "string") headers.set("dpop", dpop);
  else if (Array.isArray(dpop)) for (const d of dpop) headers.append("dpop", d);
  return new Request(url, {
    method,
    headers,
    body: method === "POST" ? JSON.stringify({ jsonrpc: "2.0", id: 1, method: "ping" }) : undefined,
  });
}
