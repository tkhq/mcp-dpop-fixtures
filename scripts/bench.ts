/**
 * Per-call latency of `client.callTool("echo")` behind PR #2630's
 * `requireDpopAuth`, over N calls after one warm-up call. Each callTool is one
 * HTTP POST, so it needs one DPoP proof.
 *
 * Variants:
 * - sdk-webcrypto:   the SDK's own `DpopSession` (non-extractable WebCrypto key).
 * - external-local:  the external-signer adapter with a local WebCrypto key.
 *                    This isolates the cost of the adapter itself.
 * - external-mock-remote: the adapter with a mock remote signing service that
 *                    waits MOCK_SIGNER_DELAY_MS (default 230) before each signature.
 *
 * Environment: BENCH_N (default 25, minimum 20), MOCK_SIGNER_DELAY_MS.
 * Writes evidence/bench.json.
 */
import { DpopSession } from "@modelcontextprotocol/client";
import { writeFileSync } from "node:fs";
import { join } from "node:path";
import { startAuthServer } from "../src/as.ts";
import { connect } from "../src/client.ts";
import { ExternalSignerDpopSession, localSigner } from "../src/external-session.ts";
import { DEFAULT_MOCK_DELAY_MS, MockRemoteSigningService, remoteSigner } from "../src/mock-remote.ts";
import { startResourceServer } from "../src/rs.ts";

const N = Number(process.env.BENCH_N ?? 25);
if (!Number.isInteger(N) || N < 20) throw new Error("BENCH_N must be an integer >= 20");
const DELAY = Number(process.env.MOCK_SIGNER_DELAY_MS ?? DEFAULT_MOCK_DELAY_MS);
if (!Number.isFinite(DELAY) || DELAY < 0) throw new Error("MOCK_SIGNER_DELAY_MS must be a number >= 0");

function pct(sorted: number[], p: number): number {
  // Nearest-rank percentile.
  const i = Math.max(0, Math.ceil((p / 100) * sorted.length) - 1);
  return sorted[i]!;
}

type Row = { variant: string; n: number; p50: number; p95: number; min: number; max: number; mean: number; signP50?: number; signP95?: number };

async function bench(variant: string, session: DpopSession, signSamples?: () => number[]): Promise<Row> {
  const as = await startAuthServer();
  const rs = await startResourceServer({ gate: "pr-dpop", as });
  const { client } = await connect({ serverUrl: rs.url, issuer: as.issuer, session });
  await client.callTool({ name: "echo", arguments: { text: "warm-up" } });
  const before = signSamples?.().length ?? 0;
  const samples: number[] = [];
  for (let i = 0; i < N; i++) {
    const t = performance.now();
    await client.callTool({ name: "echo", arguments: { text: `call ${i}` } });
    samples.push(performance.now() - t);
  }
  await client.close();
  rs.stop();
  as.stop();
  const s = [...samples].sort((a, b) => a - b);
  const r = (x: number) => Math.round(x * 10) / 10;
  const row: Row = { variant, n: N, p50: r(pct(s, 50)), p95: r(pct(s, 95)), min: r(s[0]!), max: r(s.at(-1)!), mean: r(s.reduce((a, b) => a + b, 0) / s.length) };
  if (signSamples) {
    const sig = signSamples().slice(before).sort((a, b) => a - b);
    row.signP50 = r(pct(sig, 50));
    row.signP95 = r(pct(sig, 95));
  }
  return row;
}

const rows: Row[] = [];
rows.push(await bench("sdk-webcrypto", await DpopSession.create()));
const extLocal = await ExternalSignerDpopSession.create(await localSigner());
rows.push(await bench("external-local", extLocal.asDpopSession(), () => extLocal.stats.samples));
const service = await MockRemoteSigningService.create({ delayMs: DELAY });
const extRemote = await ExternalSignerDpopSession.create(remoteSigner(service));
rows.push(await bench("external-mock-remote", extRemote.asDpopSession(), () => extRemote.stats.samples));

console.log(`\ncallTool latency, N=${N} per variant (ms; warm-up excluded; nearest-rank percentiles)`);
console.log(`mock remote signer delay: ${DELAY} ms per signature`);
console.log("variant                p50      p95      min      max      mean     sign p50  sign p95");
for (const r of rows) {
  const f = (x?: number) => (x === undefined ? "-" : String(x)).padEnd(9);
  console.log(`${r.variant.padEnd(23)}${f(r.p50)}${f(r.p95)}${f(r.min)}${f(r.max)}${f(r.mean)}${f(r.signP50)}${f(r.signP95)}`);
}
writeFileSync(join(import.meta.dir, "..", "evidence", "bench.json"), JSON.stringify({ at: new Date().toISOString(), n: N, mockSignerDelayMs: DELAY, rows }, null, 2) + "\n");
console.log("\nwrote evidence/bench.json");
