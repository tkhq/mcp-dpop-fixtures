/**
 * Negative tests against PR #2630's `requireDpopAuth` (pkg.pr.new build of
 * commit 4393c9b). Each test calls the real gate with a real `Request`, so the
 * `htu` it checks is exactly `request.url`.
 *
 * Tests named "GAP:" assert what the PR does today where it differs from what
 * RFC 9449 recommends. They pass because they document current behavior.
 */
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { startAuthServer, type AuthServer } from "../src/as.ts";
import { startResourceServer, type ResourceServer } from "../src/rs.ts";
import { ath, mcpRequest, newKey, proof, unsignedProof, type TestKey } from "./helpers.ts";

type Outcome = { ok: true } | { ok: false; status: number; error?: string; description?: string; www?: string; nonce?: string };

async function run(rs: ResourceServer, req: Request): Promise<Outcome> {
  const r = await rs.gate(req);
  if (!(r instanceof Response)) return { ok: true };
  const body = (await r.json().catch(() => ({}))) as { error?: string; error_description?: string };
  return {
    ok: false,
    status: r.status,
    error: body.error,
    description: body.error_description,
    www: r.headers.get("www-authenticate") ?? undefined,
    nonce: r.headers.get("dpop-nonce") ?? undefined,
  };
}

let as: AuthServer;
let rs: ResourceServer;
let rsGuard: ResourceServer;
let rsNonce: ResourceServer;
let rsTight: ResourceServer;
let key: TestKey;
let other: TestKey;
let token: string;

beforeAll(async () => {
  as = await startAuthServer();
  rs = await startResourceServer({ gate: "pr-dpop", as });
  rsGuard = await startResourceServer({ gate: "pr-dpop", as, replayGuard: true });
  rsNonce = await startResourceServer({ gate: "pr-dpop", as, nonce: true });
  rsTight = await startResourceServer({ gate: "pr-dpop", as, iatSkewSeconds: 30 });
  key = await newKey();
  other = await newKey();
  token = await as.mint({ jkt: key.jkt, resource: rs.resource });
});

afterAll(() => {
  for (const s of [rs, rsGuard, rsNonce, rsTight]) s.stop();
  as.stop();
});

const now = () => Math.floor(Date.now() / 1000);

describe("PR #2630 requireDpopAuth: accepted", () => {
  test("valid proof + bound token", async () => {
    const p = await proof({ key, htu: rs.url, token });
    expect(await run(rs, mcpRequest(rs.url, `DPoP ${token}`, p))).toEqual({ ok: true });
  });

  test("scheme is case-insensitive (`dpop`)", async () => {
    const p = await proof({ key, htu: rs.url, token });
    expect((await run(rs, mcpRequest(rs.url, `dpop ${token}`, p))).ok).toBe(true);
  });
});

describe("PR #2630 requireDpopAuth: caught", () => {
  test("proof signed by another key (valid signature, wrong cnf.jkt)", async () => {
    const p = await proof({ key: other, htu: rs.url, token });
    const o = await run(rs, mcpRequest(rs.url, `DPoP ${token}`, p));
    expect(o).toMatchObject({ ok: false, status: 401, error: "invalid_token" });
    expect((o as { description: string }).description).toContain("cnf.jkt");
  });

  test("proof whose jwk does not match the signing key (bad signature)", async () => {
    const p = await proof({ key: { ...other, publicJwk: key.publicJwk }, htu: rs.url, token });
    expect(await run(rs, mcpRequest(rs.url, `DPoP ${token}`, p))).toMatchObject({ status: 401, error: "invalid_dpop_proof", description: "DPoP proof signature does not verify" });
  });

  test("wrong htu path", async () => {
    const p = await proof({ key, htu: rs.url.replace("/mcp", "/other"), token });
    expect(await run(rs, mcpRequest(rs.url, `DPoP ${token}`, p))).toMatchObject({ status: 401, error: "invalid_dpop_proof" });
  });

  test("wrong htu origin (port)", async () => {
    const p = await proof({ key, htu: "http://localhost:1/mcp", token });
    expect(await run(rs, mcpRequest(rs.url, `DPoP ${token}`, p))).toMatchObject({ status: 401, error: "invalid_dpop_proof" });
  });

  test("htu with a query string", async () => {
    const p = await proof({ key, htu: `${rs.url}?x=1`, token });
    expect(await run(rs, mcpRequest(rs.url, `DPoP ${token}`, p))).toMatchObject({ status: 401, error: "invalid_dpop_proof" });
  });

  test("htm mismatch (proof for GET, request is POST)", async () => {
    const p = await proof({ key, htm: "GET", htu: rs.url, token });
    expect(await run(rs, mcpRequest(rs.url, `DPoP ${token}`, p))).toMatchObject({ status: 401, error: "invalid_dpop_proof" });
  });

  test("missing ath", async () => {
    const p = await proof({ key, htu: rs.url });
    expect(await run(rs, mcpRequest(rs.url, `DPoP ${token}`, p))).toMatchObject({ status: 401, error: "invalid_dpop_proof" });
  });

  test("mismatched ath (hash of a different token)", async () => {
    const p = await proof({ key, htu: rs.url, claims: { ath: await ath("some-other-token") } });
    expect(await run(rs, mcpRequest(rs.url, `DPoP ${token}`, p))).toMatchObject({ status: 401, error: "invalid_dpop_proof" });
  });

  test("stale iat (now - 301 s, default window 300 s)", async () => {
    const p = await proof({ key, htu: rs.url, token, claims: { iat: now() - 301 } });
    expect(await run(rs, mcpRequest(rs.url, `DPoP ${token}`, p))).toMatchObject({ status: 401, error: "invalid_dpop_proof" });
  });

  test("stale iat with iatSkewSeconds: 30 (now - 60 s)", async () => {
    const t = await as.mint({ jkt: key.jkt, resource: rsTight.resource });
    const p = await proof({ key, htu: rsTight.url, token: t, claims: { iat: now() - 60 } });
    expect(await run(rsTight, mcpRequest(rsTight.url, `DPoP ${t}`, p))).toMatchObject({ status: 401, error: "invalid_dpop_proof" });
  });

  test("missing jti", async () => {
    const p = await proof({ key, htu: rs.url, token, claims: { jti: null } });
    expect(await run(rs, mcpRequest(rs.url, `DPoP ${token}`, p))).toMatchObject({ status: 401, error: "invalid_dpop_proof" });
  });

  test("typ is not dpop+jwt", async () => {
    const p = await proof({ key, htu: rs.url, token, header: { typ: "JWT" } });
    expect(await run(rs, mcpRequest(rs.url, `DPoP ${token}`, p))).toMatchObject({ status: 401, error: "invalid_dpop_proof" });
  });

  test("alg none", async () => {
    expect(await run(rs, mcpRequest(rs.url, `DPoP ${token}`, unsignedProof(key.publicJwk, rs.url)))).toMatchObject({ status: 401, error: "invalid_dpop_proof" });
  });

  test("jwk carries a private key member (d)", async () => {
    const p = await proof({ key, htu: rs.url, token, header: { jwk: { ...key.publicJwk, d: "AAAA" } } });
    expect(await run(rs, mcpRequest(rs.url, `DPoP ${token}`, p))).toMatchObject({ status: 401, error: "invalid_dpop_proof" });
  });

  test("two DPoP headers", async () => {
    const p1 = await proof({ key, htu: rs.url, token });
    const p2 = await proof({ key, htu: rs.url, token });
    expect(await run(rs, mcpRequest(rs.url, `DPoP ${token}`, [p1, p2]))).toMatchObject({ status: 401, error: "invalid_dpop_proof" });
  });

  test("no DPoP header", async () => {
    expect(await run(rs, mcpRequest(rs.url, `DPoP ${token}`, undefined))).toMatchObject({ status: 401, error: "invalid_dpop_proof" });
  });

  test("bound token sent as Bearer (with a valid proof)", async () => {
    const p = await proof({ key, htu: rs.url, token });
    const o = await run(rs, mcpRequest(rs.url, `Bearer ${token}`, p));
    expect(o).toMatchObject({ status: 401, error: "invalid_token" });
    expect((o as { www: string }).www).toStartWith("DPoP ");
  });

  test("unbound token (no cnf) presented with DPoP", async () => {
    const t = await as.mint({ resource: rs.resource });
    const p = await proof({ key, htu: rs.url, token: t });
    expect(await run(rs, mcpRequest(rs.url, `DPoP ${t}`, p))).toMatchObject({ status: 401, error: "invalid_token" });
  });

  test("server nonce required: missing nonce -> 401 use_dpop_nonce + DPoP-Nonce", async () => {
    const t = await as.mint({ jkt: key.jkt, resource: rsNonce.resource });
    const p = await proof({ key, htu: rsNonce.url, token: t });
    const o = await run(rsNonce, mcpRequest(rsNonce.url, `DPoP ${t}`, p));
    expect(o).toMatchObject({ status: 401, error: "use_dpop_nonce" });
    const n = (o as { nonce: string }).nonce;
    expect(n).toBeString();
    const retry = await proof({ key, htu: rsNonce.url, token: t, claims: { nonce: n } });
    expect((await run(rsNonce, mcpRequest(rsNonce.url, `DPoP ${t}`, retry))).ok).toBe(true);
  });

  test("server nonce required: unknown nonce -> 401 use_dpop_nonce", async () => {
    const t = await as.mint({ jkt: key.jkt, resource: rsNonce.resource });
    const p = await proof({ key, htu: rsNonce.url, token: t, claims: { nonce: "made-up" } });
    expect(await run(rsNonce, mcpRequest(rsNonce.url, `DPoP ${t}`, p))).toMatchObject({ status: 401, error: "use_dpop_nonce" });
  });

  test("replayed jti is caught only with the fixture's replay guard wrapped around the gate", async () => {
    const t = await as.mint({ jkt: key.jkt, resource: rsGuard.resource });
    const p = await proof({ key, htu: rsGuard.url, token: t });
    expect((await run(rsGuard, mcpRequest(rsGuard.url, `DPoP ${t}`, p))).ok).toBe(true);
    expect(await run(rsGuard, mcpRequest(rsGuard.url, `DPoP ${t}`, p))).toMatchObject({ status: 401, error: "invalid_dpop_proof" });
  });
});

describe("PR #2630 requireDpopAuth: not caught (GAP)", () => {
  test("GAP: replayed proof (same jti) is accepted again; no jti store", async () => {
    const p = await proof({ key, htu: rs.url, token });
    expect((await run(rs, mcpRequest(rs.url, `DPoP ${token}`, p))).ok).toBe(true);
    expect((await run(rs, mcpRequest(rs.url, `DPoP ${token}`, p))).ok).toBe(true);
    expect((await run(rs, mcpRequest(rs.url, `DPoP ${token}`, p))).ok).toBe(true);
  });

  test("GAP: future iat up to +300 s is accepted, so one proof is replayable for up to ~600 s", async () => {
    const p = await proof({ key, htu: rs.url, token, claims: { iat: now() + 290 } });
    expect((await run(rs, mcpRequest(rs.url, `DPoP ${token}`, p))).ok).toBe(true);
  });

  test("GAP: htu is compared with request.url; behind a proxy or Host rewrite the public URL is refused", async () => {
    // The client signs the public URL. The fetch gate sees the internal URL.
    const publicUrl = rs.url;
    const internalUrl = rs.url.replace("localhost", "127.0.0.1");
    const p = await proof({ key, htu: publicUrl, token });
    expect(await run(rs, mcpRequest(internalUrl, `DPoP ${token}`, p))).toMatchObject({ status: 401, error: "invalid_dpop_proof", description: "DPoP proof 'htu' does not match the request URI" });
  });

  test("lenient: htu with one trailing slash is accepted", async () => {
    const p = await proof({ key, htu: `${rs.url}/`, token });
    expect((await run(rs, mcpRequest(rs.url, `DPoP ${token}`, p))).ok).toBe(true);
  });

  test("note: Authorization with two spaces after the scheme is refused", async () => {
    const p = await proof({ key, htu: rs.url, token });
    expect(await run(rs, mcpRequest(rs.url, `DPoP  ${token}`, p))).toMatchObject({ status: 401, error: "invalid_token" });
  });

  test("note: key-binding mismatch answers invalid_token, not invalid_dpop_proof", async () => {
    const p = await proof({ key: other, htu: rs.url, token });
    expect(await run(rs, mcpRequest(rs.url, `DPoP ${token}`, p))).toMatchObject({ error: "invalid_token" });
  });
});
