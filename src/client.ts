/**
 * MCP client side: the released 2.3.1 `Client` + `StreamableHTTPClientTransport`
 * with a `ClientCredentialsProvider` that also implements `dpop()`.
 *
 * This uses the SDK's real `auth()` flow end to end: 401 challenge ->
 * RFC 9728 PRM discovery -> RFC 8414 AS discovery -> client_credentials token
 * request with a DPoP proof -> DPoP-bound MCP requests.
 */
import { Client, ClientCredentialsProvider, DpopSession, StreamableHTTPClientTransport } from "@modelcontextprotocol/client";
import { CLIENT_ID, CLIENT_SECRET, SCOPE } from "./as.ts";

export class DpopClientCredentialsProvider extends ClientCredentialsProvider {
  constructor(
    issuer: string,
    private readonly session: DpopSession,
  ) {
    super({ clientId: CLIENT_ID, clientSecret: CLIENT_SECRET, scope: SCOPE, expectedIssuer: issuer });
  }

  dpop(): DpopSession {
    return this.session;
  }
}

export async function connect(opts: { serverUrl: string; issuer: string; session: DpopSession; fetch?: typeof fetch }) {
  const provider = new DpopClientCredentialsProvider(opts.issuer, opts.session);
  const transport = new StreamableHTTPClientTransport(new URL(opts.serverUrl), { authProvider: provider, fetch: opts.fetch });
  const client = new Client({ name: "mcp-dpop-fixtures", version: "0.0.1" });
  await client.connect(transport);
  return { client, transport, provider };
}

export function toolText(result: unknown): string {
  const content = (result as { content?: { type: string; text?: string }[] }).content ?? [];
  return content.map((c) => c.text ?? `[${c.type}]`).join("\n");
}
