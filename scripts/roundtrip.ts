/**
 * Round trip with PR #2630's `requireDpopAuth`.
 *
 * A. No nonces: token request proof, per-request proofs with `ath`, tool call.
 * B. RS nonce: `use_dpop_nonce` 401 challenge and the client's single retry.
 * C. AS nonce: `use_dpop_nonce` 400 at the token endpoint and the retry.
 * D. The bound token sent as `Bearer`: refused by the DPoP gate and by the
 *    PR's `requireBearerAuth` (RFC 9449 §7.2).
 */
import { DpopSession } from "@modelcontextprotocol/client";
import { startAuthServer } from "../src/as.ts";
import { connect, toolText } from "../src/client.ts";
import { startResourceServer } from "../src/rs.ts";
import { Trace } from "../src/trace.ts";

let failures = 0;
function check(label: string, ok: boolean): void {
  console.log(`${ok ? "PASS" : "FAIL"}  ${label}`);
  if (!ok) failures++;
}

// ---------- A ----------
{
  const as = await startAuthServer();
  const rs = await startResourceServer({ gate: "pr-dpop", as });
  const trace = new Trace();
  const session = await DpopSession.create();
  console.log(`\n=== A. PR #2630 requireDpopAuth, no nonces ===`);
  console.log(`AS ${as.issuer}  RS ${rs.url}  key jkt=${session.thumbprint}`);
  const { client } = await connect({ serverUrl: rs.url, issuer: as.issuer, session, fetch: trace.fetch });
  const out: string[] = [];
  for (const text of ["one", "two", "three"]) out.push(toolText(await client.callTool({ name: "echo", arguments: { text } })));
  trace.print("HTTP trace");
  console.log(`\ntool results:\n  ${out.join("\n  ")}`);
  const tokenReq = trace.entries.find((e) => e.url.endsWith("/token"));
  const mcpDpop = trace.entries.filter((e) => e.authScheme === "DPoP");
  check("token request carried a DPoP proof with htm=POST, htu=token endpoint, no ath", tokenReq?.proofClaims?.htu === as.tokenEndpoint && !tokenReq?.proofClaims?.ath);
  check("AS bound the token to the client key (cnf.jkt == session.thumbprint)", as.tokenRequests[0]?.jkt === session.thumbprint);
  check(`every MCP request after the token used Authorization: DPoP + proof with ath (${mcpDpop.length} requests)`, mcpDpop.length > 0 && mcpDpop.every((e) => typeof e.proofClaims?.ath === "string"));
  check("every proof had a unique jti", new Set(trace.entries.map((e) => e.proofClaims?.jti).filter(Boolean)).size === trace.entries.filter((e) => e.proofClaims).length);
  // 202 = notifications/initialized, 405 = optional GET SSE stream (stateless server); neither is an auth failure.
  check("no DPoP MCP request was refused by the gate (no 401/403)", mcpDpop.every((e) => e.status !== 401 && e.status !== 403));
  check("echo tool saw the bound key", out[0]?.includes(session.thumbprint) ?? false);
  console.log(`MCP HTTP requests with a proof: ${mcpDpop.length} = connect (initialize POST, initialized POST, GET stream) + 3 callTool POSTs; one signature each`);
  await client.close();
  rs.stop();
  as.stop();
}

// ---------- B ----------
{
  const as = await startAuthServer();
  const rs = await startResourceServer({ gate: "pr-dpop", as, nonce: true });
  const trace = new Trace();
  const session = await DpopSession.create();
  console.log(`\n=== B. PR #2630 requireDpopAuth with a server nonce (RFC 9449 §9) ===`);
  const { client } = await connect({ serverUrl: rs.url, issuer: as.issuer, session, fetch: trace.fetch });
  const r1 = toolText(await client.callTool({ name: "echo", arguments: { text: "nonce-1" } }));
  const r2 = toolText(await client.callTool({ name: "echo", arguments: { text: "nonce-2" } }));
  trace.print("HTTP trace");
  console.log(`\ntool results:\n  ${r1}\n  ${r2}`);
  const challenge = trace.entries.findIndex((e) => e.status === 401 && e.wwwAuthenticate?.includes("use_dpop_nonce"));
  const retry = trace.entries[challenge + 1];
  check("RS answered 401 use_dpop_nonce with a DPoP-Nonce header", challenge >= 0 && !!trace.entries[challenge]!.dpopNonce);
  check("client retried once with the nonce in a fresh proof (new jti)", retry?.proofClaims?.nonce === trace.entries[challenge]?.dpopNonce && retry?.proofClaims?.jti !== trace.entries[challenge]?.proofClaims?.jti && retry?.status === 200);
  check("only one nonce challenge in the whole session (nonce remembered per origin)", trace.entries.filter((e) => e.wwwAuthenticate?.includes("use_dpop_nonce")).length === 1);
  console.log(`RS nonce stats: ${JSON.stringify(rs.nonceStats)}`);
  await client.close();
  rs.stop();
  as.stop();
}

// ---------- C ----------
{
  const as = await startAuthServer({ requireNonce: true });
  const rs = await startResourceServer({ gate: "pr-dpop", as });
  const trace = new Trace();
  const session = await DpopSession.create();
  console.log(`\n=== C. AS nonce at the token endpoint (RFC 9449 §8) ===`);
  const { client } = await connect({ serverUrl: rs.url, issuer: as.issuer, session, fetch: trace.fetch });
  const r = toolText(await client.callTool({ name: "echo", arguments: { text: "as-nonce" } }));
  trace.print("HTTP trace");
  console.log(`\ntool result: ${r}`);
  const tokens = trace.entries.filter((e) => e.url.endsWith("/token"));
  check("token endpoint answered 400 use_dpop_nonce, client retried once with the nonce", tokens.length === 2 && tokens[0]!.status === 400 && tokens[1]!.status === 200 && tokens[1]!.proofClaims?.nonce === tokens[0]!.dpopNonce);
  check("AS nonce did not leak into RS proofs (separate per-origin slots)", trace.entries.filter((e) => e.authScheme === "DPoP").every((e) => e.proofClaims?.nonce === undefined));
  await client.close();
  rs.stop();
  as.stop();
}

// ---------- D ----------
{
  const as = await startAuthServer();
  const dpopRs = await startResourceServer({ gate: "pr-dpop", as });
  const bearerRs = await startResourceServer({ gate: "pr-bearer", as });
  const session = await DpopSession.create();
  console.log(`\n=== D. DPoP-bound token sent as Bearer ===`);
  const body = JSON.stringify({ jsonrpc: "2.0", id: 1, method: "ping" });
  const headers = (token: string) => ({ authorization: `Bearer ${token}`, "content-type": "application/json", accept: "application/json, text/event-stream" });

  const t1 = await as.mint({ jkt: session.thumbprint, resource: dpopRs.resource });
  const p1 = await session.buildProof({ htm: "POST", htu: dpopRs.url, accessToken: t1 });
  const r1 = await fetch(dpopRs.url, { method: "POST", headers: { ...headers(t1), dpop: p1 }, body });
  console.log(`PR requireDpopAuth, "Bearer <bound token>" + valid proof -> ${r1.status} ${r1.headers.get("www-authenticate")}`);
  check("PR requireDpopAuth refuses the Bearer scheme", r1.status === 401);

  const t2 = await as.mint({ jkt: session.thumbprint, resource: bearerRs.resource });
  const r2 = await fetch(bearerRs.url, { method: "POST", headers: headers(t2), body });
  console.log(`PR requireBearerAuth, "Bearer <bound token>" -> ${r2.status} ${r2.headers.get("www-authenticate")}`);
  check("PR requireBearerAuth refuses a token with cnf.jkt (RFC 9449 §7.2)", r2.status === 401 && (r2.headers.get("www-authenticate") ?? "").includes("DPoP-bound"));

  const t3 = await as.mint({ resource: bearerRs.resource });
  const r3 = await fetch(bearerRs.url, { method: "POST", headers: headers(t3), body });
  console.log(`PR requireBearerAuth, "Bearer <unbound token>" -> ${r3.status}`);
  check("PR requireBearerAuth still accepts an unbound token", r3.status !== 401);
  dpopRs.stop();
  bearerRs.stop();
  as.stop();
}

console.log(`\n${failures === 0 ? "ALL CHECKS PASSED" : `${failures} CHECK(S) FAILED`}`);
process.exit(failures === 0 ? 0 : 1);
