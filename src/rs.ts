/**
 * MCP resource server for the fixtures: one `echo` tool on the released 2.3.1
 * `McpServer` + `createMcpHandler`, served by `Bun.serve`. Only the auth gate
 * in front of it changes:
 *
 * - `stock-bearer`: released 2.3.1 `requireBearerAuth` (baseline).
 * - `pr-dpop`:      PR #2630 `requireDpopAuth` from the pkg.pr.new preview.
 * - `pr-bearer`:    PR #2630 `requireBearerAuth`, to show it refuses a bound token.
 *
 * Protected Resource Metadata (RFC 9728) is served with the 2.3.1
 * `oauthMetadataResponse` helper in every mode.
 */
import {
  createMcpHandler,
  getOAuthProtectedResourceMetadataUrl,
  McpServer,
  oauthMetadataResponse,
  OAuthError as StockOAuthError,
  OAuthErrorCode as StockOAuthErrorCode,
  requireBearerAuth as stockRequireBearerAuth,
  type AuthInfo,
} from "@modelcontextprotocol/server";
import * as pr from "mcp-server-pr2630";
import { base64url, decodeJwt } from "jose";
import { z } from "zod";
import { verifyAccessTokenJwt, type AuthServer } from "./as.ts";

export type GateKind = "stock-bearer" | "pr-dpop" | "pr-bearer";

export type ResourceServerOptions = {
  gate: GateKind;
  as: Pick<AuthServer, "issuer" | "publicJwk" | "allowedResources">;
  /** PR #2630 only: require a server-provided nonce (RFC 9449 §9). */
  nonce?: boolean;
  /** PR #2630 only: `iatSkewSeconds` (default 300). */
  iatSkewSeconds?: number;
  /** Add a jti replay check around the PR gate (the PR has none). */
  replayGuard?: boolean;
};

export type ResourceServer = {
  url: string;
  resource: string;
  prmUrl: string;
  /** The raw gate, for unit tests: Request -> AuthInfo | Response. */
  gate: (req: Request) => Promise<AuthInfo | Response>;
  /** AuthInfo of the last request the gate accepted. */
  lastAuth?: AuthInfo;
  nonceStats: { issued: number; verified: number; rejected: number };
  stop(): void;
};

type PrAuthInfo = Awaited<ReturnType<pr.OAuthTokenVerifier["verifyAccessToken"]>>;

export function makeVerifier(gate: GateKind, as: ResourceServerOptions["as"], resource: string) {
  // Each package checks `error instanceof OAuthError` against its own copy of
  // core, so the verifier must throw the class from the gate's package.
  const Err = gate === "stock-bearer" ? StockOAuthError : pr.OAuthError;
  const code = gate === "stock-bearer" ? StockOAuthErrorCode.InvalidToken : pr.OAuthErrorCode.InvalidToken;
  return {
    async verifyAccessToken(token: string) {
      let claims;
      try {
        claims = await verifyAccessTokenJwt(token, as, resource);
      } catch (e) {
        throw new Err(code as never, `access token rejected: ${(e as Error).message}`);
      }
      const info: PrAuthInfo = {
        token,
        clientId: claims.client_id,
        scopes: claims.scope.split(" "),
        expiresAt: claims.exp,
        resource: new URL(claims.aud),
        cnf: claims.cnf,
      };
      return info;
    },
  };
}

function makeNonceState(stats: ResourceServer["nonceStats"]): { issue(): string; verify(n: string | undefined): boolean } {
  const live = new Map<string, number>();
  return {
    issue() {
      const n = base64url.encode(crypto.getRandomValues(new Uint8Array(16)));
      live.set(n, Date.now() + 5 * 60_000);
      stats.issued++;
      return n;
    },
    verify(n) {
      const ok = n !== undefined && (live.get(n) ?? 0) > Date.now();
      if (ok) stats.verified++;
      else stats.rejected++;
      return ok;
    },
  };
}

export async function startResourceServer(opts: ResourceServerOptions): Promise<ResourceServer> {
  const asMetadata = await (await fetch(`${opts.as.issuer}/.well-known/oauth-authorization-server`)).json();
  const nonceStats = { issued: 0, verified: 0, rejected: 0 };
  let resource = "";
  let prmUrl = "";
  let gate: ResourceServer["gate"] = async () => new Response("not ready", { status: 503 });
  const state: { lastAuth?: AuthInfo } = {};

  const handler = createMcpHandler((ctx) => {
    const server = new McpServer({ name: "fixture-echo", version: "0.0.1" });
    server.registerTool(
      "echo",
      { description: "Echo the input back", inputSchema: z.object({ text: z.string() }) },
      async ({ text }) => {
        const jkt = (ctx.authInfo as { cnf?: { jkt?: string } } | undefined)?.cnf?.jkt;
        return { content: [{ type: "text", text: `echo: ${text} (client=${ctx.authInfo?.clientId}, cnf.jkt=${jkt ?? "none"})` }] };
      },
    );
    return server;
  });

  const seenJti = new Set<string>();

  const server = Bun.serve({
    port: 0,
    hostname: "localhost",
    async fetch(req) {
      const meta = oauthMetadataResponse(req, { oauthMetadata: asMetadata, resourceServerUrl: new URL(resource), scopesSupported: ["mcp"] });
      if (meta) return meta;
      const url = new URL(req.url);
      if (url.pathname !== "/mcp") return new Response("not found", { status: 404 });
      const auth = await gate(req);
      if (auth instanceof Response) return auth;
      state.lastAuth = auth;
      return handler.fetch(req, { authInfo: auth });
    },
  });
  resource = `http://localhost:${server.port}/mcp`;
  prmUrl = getOAuthProtectedResourceMetadataUrl(new URL(resource));
  opts.as.allowedResources.add(resource);

  if (opts.gate === "stock-bearer") {
    gate = stockRequireBearerAuth({
      verifier: makeVerifier("stock-bearer", opts.as, resource) as never,
      resourceMetadataUrl: prmUrl,
      requiredScopes: ["mcp"],
    });
  } else if (opts.gate === "pr-bearer") {
    gate = pr.requireBearerAuth({
      verifier: makeVerifier("pr-bearer", opts.as, resource),
      resourceMetadataUrl: prmUrl,
      requiredScopes: ["mcp"],
    }) as ResourceServer["gate"];
  } else {
    const prGate = pr.requireDpopAuth({
      verifier: makeVerifier("pr-dpop", opts.as, resource),
      resourceMetadataUrl: prmUrl,
      requiredScopes: ["mcp"],
      iatSkewSeconds: opts.iatSkewSeconds,
      nonce: opts.nonce ? makeNonceState(nonceStats) : undefined,
    });
    gate = async (req) => {
      const result = await prGate(req);
      if (result instanceof Response || !opts.replayGuard) return result as AuthInfo | Response;
      // The gate verified the proof but does not return its claims, so the
      // jti has to be decoded again from the (now trusted) header.
      const jti = decodeJwt(req.headers.get("dpop") ?? "").jti;
      if (!jti || seenJti.has(jti)) {
        return pr.dpopAuthChallengeResponse(new pr.OAuthError(pr.OAuthErrorCode.InvalidDpopProof, "DPoP proof jti was already used"), {
          resourceMetadataUrl: prmUrl,
        });
      }
      seenJti.add(jti);
      return result as AuthInfo;
    };
  }

  return {
    url: resource,
    resource,
    prmUrl,
    get gate() {
      return gate;
    },
    get lastAuth() {
      return state.lastAuth;
    },
    nonceStats,
    stop: () => server.stop(true),
  };
}
