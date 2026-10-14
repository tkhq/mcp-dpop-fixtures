/**
 * A fetch wrapper that records every HTTP exchange the MCP client makes:
 * discovery, the token request, and MCP requests. DPoP proofs are decoded
 * (header and claims) so scripts can show `htm`, `htu`, `ath`, `nonce`, `jti`.
 *
 * The MCP transport wraps this fetch with `withDpopFromProvider`, so this
 * layer sees the final `Authorization` and `DPoP` headers on the wire.
 */
import { decodeJwt, decodeProtectedHeader } from "jose";

export type TraceEntry = {
  n: number;
  method: string;
  url: string;
  authScheme?: string;
  tokenPrefix?: string;
  proofHeader?: Record<string, unknown>;
  proofClaims?: Record<string, unknown>;
  status: number;
  wwwAuthenticate?: string;
  dpopNonce?: string;
  error?: string;
  ms: number;
};

export class Trace {
  entries: TraceEntry[] = [];

  fetch: typeof fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const req = new Request(input, init);
    const started = performance.now();
    const auth = req.headers.get("authorization") ?? undefined;
    const proof = req.headers.get("dpop") ?? undefined;
    const entry: TraceEntry = {
      n: this.entries.length + 1,
      method: req.method,
      url: req.url,
      status: 0,
      ms: 0,
    };
    if (auth) {
      const [scheme, token] = auth.split(" ");
      entry.authScheme = scheme;
      entry.tokenPrefix = token ? `${token.slice(0, 12)}...` : undefined;
    }
    if (proof) {
      entry.proofHeader = decodeProtectedHeader(proof) as Record<string, unknown>;
      entry.proofClaims = decodeJwt(proof) as Record<string, unknown>;
    }
    this.entries.push(entry);
    const res = await fetch(input, init);
    entry.status = res.status;
    entry.ms = Math.round(performance.now() - started);
    entry.wwwAuthenticate = res.headers.get("www-authenticate") ?? undefined;
    entry.dpopNonce = res.headers.get("dpop-nonce") ?? undefined;
    if (res.status >= 400) {
      entry.error = await res.clone().text().then((t) => t.slice(0, 200)).catch(() => undefined);
    }
    return res;
  }) as typeof fetch;

  clear(): void {
    this.entries = [];
  }

  print(title?: string): void {
    if (title) console.log(`\n--- ${title} ---`);
    for (const e of this.entries) {
      const path = new URL(e.url).pathname;
      const auth = e.authScheme ? ` auth=${e.authScheme}` : "";
      console.log(`#${e.n} ${e.method} ${new URL(e.url).origin}${path} -> ${e.status}${auth} (${e.ms} ms)`);
      if (e.proofClaims) {
        const c = e.proofClaims;
        const h = e.proofHeader ?? {};
        console.log(
          `    proof: typ=${h.typ} alg=${h.alg} htm=${c.htm} htu=${c.htu} iat=${c.iat} jti=${String(c.jti).slice(0, 8)}...` +
            (c.ath ? ` ath=${String(c.ath).slice(0, 10)}...` : " ath=(none)") +
            (c.nonce ? ` nonce=${c.nonce}` : ""),
        );
      }
      if (e.wwwAuthenticate) console.log(`    WWW-Authenticate: ${e.wwwAuthenticate}`);
      if (e.dpopNonce) console.log(`    DPoP-Nonce: ${e.dpopNonce}`);
      if (e.error) console.log(`    body: ${e.error}`);
    }
  }
}
