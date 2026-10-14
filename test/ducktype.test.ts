/**
 * The duck-typed external-signer session (with a
 * local mock signer) drives the released 2.3.1 client through the full flow
 * against PR #2630, with both AS and RS nonces on. Also records what breaks
 * at runtime with the other approaches.
 */
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { DpopSession, generateDpopKeyPair, type DpopKeyPair } from "@modelcontextprotocol/client";
import { startAuthServer, type AuthServer } from "../src/as.ts";
import { connect, toolText } from "../src/client.ts";
import { ExternalSignerDpopSession, localSigner } from "../src/external-session.ts";
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

describe("duck-typed DpopSession with an external signer", () => {
  test("full SDK auth() + tool call works through `as unknown as DpopSession`", async () => {
    const ext = await ExternalSignerDpopSession.create(await localSigner());
    const trace = new Trace();
    const { client } = await connect({ serverUrl: rs.url, issuer: as.issuer, session: ext.asDpopSession(), fetch: trace.fetch });
    const out = toolText(await client.callTool({ name: "echo", arguments: { text: "external" } }));
    await client.close();

    expect(out).toContain(`cnf.jkt=${ext.thumbprint}`);
    // AS nonce: 400 then retry; RS nonce: 401 then retry. Both went through our observeNonce/nonceFor.
    const tokens = trace.entries.filter((e) => e.url.endsWith("/token"));
    expect(tokens.map((e) => e.status)).toEqual([400, 200]);
    expect(tokens[1]!.proofClaims!.nonce).toBe(tokens[0]!.dpopNonce!);
    const nonceChallenges = trace.entries.filter((e) => e.wwwAuthenticate?.includes("use_dpop_nonce"));
    expect(nonceChallenges.length).toBe(1);
    // Every signature was made by the external signer (token + MCP requests incl. retries).
    expect(ext.stats.count).toBe(trace.entries.filter((e) => e.proofClaims).length);
  });

  test("RUNTIME: DpopSession.create with a non-CryptoKey privateKey throws inside jose on first buildProof", async () => {
    const kp = await generateDpopKeyPair();
    const remote = { sign: async () => new Uint8Array(64) };
    const s = await DpopSession.create({ keyPair: { ...kp, privateKey: remote } as unknown as DpopKeyPair });
    const err = await s.buildProof({ htm: "POST", htu: rs.url }).catch((e: Error) => e);
    expect(err).toBeInstanceOf(TypeError);
    console.log(`  DpopSession.create({ keyPair: { privateKey: <remote> } }).buildProof() -> ${(err as Error).name}: ${(err as Error).message}`);
  });

  test("RUNTIME: subclassing DpopSession works in JS even though TS forbids it (private constructor is type-only)", async () => {
    const Base = DpopSession as unknown as new (kp: DpopKeyPair) => DpopSession;
    class Overridden extends Base {
      override async buildProof(_req: Parameters<DpopSession["buildProof"]>[0]): Promise<string> {
        return "overridden";
      }
    }
    const s = new Overridden(await generateDpopKeyPair());
    expect(await s.buildProof({ htm: "POST", htu: rs.url })).toBe("overridden");
    expect(s).toBeInstanceOf(DpopSession);
  });

  test("RUNTIME: SDK never reads thumbprint/alg/publicJwk or checks instanceof (a bare object works)", async () => {
    const ext = await ExternalSignerDpopSession.create(await localSigner());
    const calls: string[] = [];
    const bare = {
      buildProof: (r: Parameters<ExternalSignerDpopSession["buildProof"]>[0]) => (calls.push("buildProof"), ext.buildProof(r)),
      observeNonce: (res: Response, u: string | URL) => (calls.push("observeNonce"), ext.observeNonce(res, u)),
      nonceFor: (u: string | URL) => (calls.push("nonceFor"), ext.nonceFor(u)),
      rememberNonce: (u: string | URL, n: string) => (calls.push("rememberNonce"), ext.rememberNonce(u, n)),
    };
    const { client } = await connect({ serverUrl: rs.url, issuer: as.issuer, session: bare as unknown as DpopSession });
    expect(toolText(await client.callTool({ name: "echo", arguments: { text: "bare" } }))).toContain(ext.thumbprint);
    await client.close();
    const used = [...new Set(calls)].sort();
    console.log(`  methods the SDK called on the session object: ${used.join(", ")}`);
    expect(used).toEqual(["buildProof", "observeNonce"]);
  });
});
