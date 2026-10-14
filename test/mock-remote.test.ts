/**
 * The external-signer adapter with the mock remote signing service: hex key
 * and signature conversion, and a full SDK flow against PR #2630 with AS and
 * RS nonces on. The mock delay is 0 here; the benchmark sets it.
 */
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { importJWK, jwtVerify } from "jose";
import { startAuthServer, type AuthServer } from "../src/as.ts";
import { connect, toolText } from "../src/client.ts";
import { ExternalSignerDpopSession } from "../src/external-session.ts";
import { MockRemoteSigningService, remoteSigner } from "../src/mock-remote.ts";
import { fromHex, joseSignature, publicKeyHexToJwk } from "../src/p256.ts";
import { startResourceServer, type ResourceServer } from "../src/rs.ts";
import { Trace } from "../src/trace.ts";

let as: AuthServer;
let rs: ResourceServer;

beforeAll(async () => {
  as = await startAuthServer({ requireNonce: true });
  rs = await startResourceServer({ gate: "pr-dpop", as, nonce: true, replayGuard: true });
});
afterAll(() => {
  rs.stop();
  as.stop();
});

describe("p256 helpers", () => {
  test("compressed and uncompressed SEC1 keys give the same JWK", async () => {
    const service = await MockRemoteSigningService.create({ delayMs: 0 });
    const full = fromHex(service.publicKeyHex);
    const prefix = (full[64]! & 1) === 1 ? "03" : "02";
    const compressed = prefix + service.publicKeyHex.slice(2, 66);
    expect(publicKeyHexToJwk(compressed)).toEqual(publicKeyHexToJwk(service.publicKeyHex));
  });

  test("short r and s hex values are left-padded to 32 bytes", () => {
    const sig = joseSignature("01", "0abc");
    expect(sig.length).toBe(64);
    expect(sig[31]).toBe(1);
    expect(sig[62]).toBe(0x0a);
    expect(sig[63]).toBe(0xbc);
  });

  test("out-of-range r is refused", () => {
    expect(() => joseSignature("00", "01")).toThrow("out of range");
  });
});

describe("external-signer adapter with a mock remote signer", () => {
  test("a proof signed by the mock service verifies with its public JWK", async () => {
    const signer = remoteSigner(await MockRemoteSigningService.create({ delayMs: 0 }));
    const session = await ExternalSignerDpopSession.create(signer);
    const proof = await session.buildProof({ htm: "POST", htu: rs.url });
    const { payload } = await jwtVerify(proof, await importJWK(signer.publicJwk, "ES256"), { typ: "dpop+jwt" });
    expect(payload.htu).toBe(rs.url);
  });

  test("full SDK auth() + tool call; one service call per proof on the wire", async () => {
    const service = await MockRemoteSigningService.create({ delayMs: 0 });
    const session = await ExternalSignerDpopSession.create(remoteSigner(service));
    const trace = new Trace();
    const { client } = await connect({ serverUrl: rs.url, issuer: as.issuer, session: session.asDpopSession(), fetch: trace.fetch });
    const out = toolText(await client.callTool({ name: "echo", arguments: { text: "remote" } }));
    await client.close();
    expect(out).toContain(`cnf.jkt=${session.thumbprint}`);
    expect(service.calls).toBe(trace.entries.filter((e) => e.proofClaims).length);
  });
});
