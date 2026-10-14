/**
 * Baseline: stock 2.3.1 server gate.
 *
 * Released 2.3.1 server behind the stock `requireBearerAuth`. Released 2.3.1
 * client with `dpop()`. The AS issues a DPoP-bound token, the client presents
 * it as `Authorization: DPoP ...`, and the stock gate refuses the scheme.
 *
 * Second part: the same DPoP-bound token sent as `Bearer` is ACCEPTED by the
 * stock gate, because 2.3.1 has no notion of `cnf.jkt`.
 */
import { DpopSession } from "@modelcontextprotocol/client";
import { startAuthServer } from "../src/as.ts";
import { connect, toolText } from "../src/client.ts";
import { startResourceServer } from "../src/rs.ts";
import { Trace } from "../src/trace.ts";

const as = await startAuthServer();
const rs = await startResourceServer({ gate: "stock-bearer", as });
const trace = new Trace();
const session = await DpopSession.create();
console.log(`AS ${as.issuer}  RS ${rs.url}  gate=stock 2.3.1 requireBearerAuth`);
console.log(`client DPoP key thumbprint ${session.thumbprint}`);

let outcome = "unexpected success";
try {
  const { client } = await connect({ serverUrl: rs.url, issuer: as.issuer, session, fetch: trace.fetch });
  const r = await client.callTool({ name: "echo", arguments: { text: "hello" } });
  console.log(toolText(r));
} catch (e) {
  outcome = `${(e as Error).name}: ${(e as Error).message}`;
}
trace.print("HTTP trace (2.3.1 client with dpop() -> stock requireBearerAuth)");
console.log(`\nRESULT: ${outcome}`);
const rejected = trace.entries.filter((e) => e.authScheme === "DPoP" && e.status === 401);
console.log(`DPoP-scheme requests rejected by the stock gate: ${rejected.length}`);

// Part 2: the bound token, stripped of its proof, sent as Bearer.
const token = await as.mint({ jkt: session.thumbprint, resource: rs.resource });
const res = await fetch(rs.url, {
  method: "POST",
  headers: { authorization: `Bearer ${token}`, "content-type": "application/json", accept: "application/json, text/event-stream" },
  body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "ping" }),
});
console.log(`\nDPoP-bound token (cnf.jkt=${session.thumbprint.slice(0, 10)}...) sent as Bearer, no proof -> HTTP ${res.status}`);
console.log(`gate result: ${rs.lastAuth ? `ACCEPTED (clientId=${rs.lastAuth.clientId})` : "rejected"}`);
console.log("The stock gate cannot tell a bound token from a bearer token, so a stolen bound token works without the key.");

rs.stop();
as.stop();
const ok = rejected.length > 0 && rs.lastAuth !== undefined;
process.exit(ok ? 0 : 1);
