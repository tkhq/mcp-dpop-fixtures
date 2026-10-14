# mcp-dpop-fixtures

Test fixtures for DPoP (RFC 9449) with the MCP TypeScript SDK. They go with a review of [modelcontextprotocol/typescript-sdk#2630](https://github.com/modelcontextprotocol/typescript-sdk/pull/2630) (server DPoP validation) and with a proposal to let the client `DpopSession` use an external signer.

Maintained by Turnkey (https://www.turnkey.com).

Everything runs locally: a stub authorization server (AS), an MCP resource server (RS), and the released SDK client. The tests and scripts need no network after `bun install`.

## Versions

| Package | Version | Used for |
|---|---|---|
| `@modelcontextprotocol/client` | 2.3.1 | the client in every script |
| `@modelcontextprotocol/server` | 2.3.1 | the MCP handler, and the stock `requireBearerAuth` in the baseline |
| `mcp-server-pr2630` | `https://pkg.pr.new/@modelcontextprotocol/server@2630` | the PR #2630 gates (`requireDpopAuth`, `requireBearerAuth`) |
| `jose` | 6.1.3 | the stub AS and the test proofs |

The PR preview was built from head `4393c9b`. `bun.lock` records that build's hash. If the PR head changes, `bun install` gets a new build, and `bun install --frozen-lockfile` fails. To pin by commit instead, use `https://pkg.pr.new/@modelcontextprotocol/server@4393c9b`.

The preview build is based on an older `main` (its `package.json` says 2.0.0). The fixtures use only its gates. The 2.3.1 MCP handler runs behind them.

## Run

Requires [Bun](https://bun.sh) 1.4 or later.

```sh
bun install
bun run typecheck
bun test
bun run baseline
bun run roundtrip
bun run bench
bun run probe:types   # expected to fail: it records the TypeScript errors
```

Captured output is in `evidence/`.

## What each part shows

| File | What it shows |
|---|---|
| `src/as.ts` | Stub AS. RFC 8414 metadata with `dpop_signing_alg_values_supported`. One `client_credentials` client. It checks the token-request proof (`typ`, `alg`, public `jwk`, signature, `htm`, `htu`, `iat`, `jti` replay) and can require an AS nonce. It issues an ES256 `at+jwt` with `cnf.jkt` and `token_type: "DPoP"`. |
| `src/rs.ts` | RS. The released 2.3.1 `McpServer` and `createMcpHandler` with one `echo` tool, and RFC 9728 metadata. Only the gate changes: stock 2.3.1 `requireBearerAuth`, PR `requireDpopAuth`, or PR `requireBearerAuth`. An optional `jti` replay guard wraps the PR gate. |
| `src/client.ts` | The released 2.3.1 `Client` and `StreamableHTTPClientTransport`, with a `ClientCredentialsProvider` that adds `dpop()`. This is the SDK's real `auth()` flow. |
| `src/trace.ts` | A `fetch` wrapper that decodes every proof on the wire. |
| `src/external-session.ts` | `ExternalSignerDpopSession`: a generic adapter that builds the RFC 9449 header and claims and sends the JWS signing input to any `DpopSigner.sign()`. |
| `src/mock-remote.ts`, `src/p256.ts` | A mock remote signing service that returns hex keys and `r`/`s` signatures after a set delay, and the helpers that convert them to a JWK and a JOSE signature. |
| `scripts/baseline.ts` | The 2.3.1 client against the stock 2.3.1 gate. |
| `scripts/roundtrip.ts` | The 2.3.1 client against the PR gate: no nonces, RS nonce, AS nonce, and a bound token sent as `Bearer`. 14 checks. |
| `test/pr2630-negative.test.ts` | Calls the PR gate with real `Request` objects. Tests named `GAP:` pass because they record what the PR does today. |
| `test/pr2630-base.test.ts` | Shows that the preview build has no `expectedResource`, and that 2.3.1 has it. |
| `test/ducktype.test.ts`, `probes/ducktype.ts` | What works and what fails when you give the client a session that is not the SDK's own `DpopSession`. |
| `test/mock-remote.test.ts` | The adapter with the mock remote signer, through the full SDK flow. |
| `scripts/bench.ts` | Latency per `callTool` for three proof signers. |

## Findings: server

### Baseline: stock 2.3.1 `requireBearerAuth`

| Case | Result |
|---|---|
| Client sends `Authorization: DPoP` with a valid proof | Refused: 401, "expected 'Bearer TOKEN'". The client fails with "Server returned 401 after re-authentication". |
| The same DPoP-bound token sent as `Bearer`, with no proof | **Accepted** (200). The stock gate does not read `cnf.jkt`, so a stolen bound token works without the key. |

### PR #2630 `requireDpopAuth`

The full round trip works. This includes the RS nonce challenge (401 `use_dpop_nonce`), the AS nonce challenge (400 `use_dpop_nonce`), and one retry for each. The PR's `requireBearerAuth` refuses a token that has `cnf.jkt`, and it still accepts an unbound token.

The PR catches 20 of the 23 negative cases:

| Case | Result |
|---|---|
| Proof from another key (valid signature, wrong `cnf.jkt`) | Caught: `invalid_token` |
| `jwk` header does not match the signing key | Caught |
| Wrong `htu` path, wrong origin, `htu` with a query | Caught |
| `htm` mismatch | Caught |
| Missing `ath`, wrong `ath` | Caught |
| Old `iat` (default window, and `iatSkewSeconds: 30`) | Caught |
| Missing `jti`, `typ` not `dpop+jwt`, `alg: none`, `jwk` with `d` | Caught |
| Two `DPoP` headers, no `DPoP` header | Caught |
| Bound token sent as `Bearer` with a valid proof | Caught: 401 with a `DPoP` challenge |
| Unbound token sent with DPoP | Caught: `invalid_token` |
| Server nonce missing or unknown | Caught: 401 `use_dpop_nonce` with `DPoP-Nonce`. A retry with that nonce is accepted. |

### Gaps

| Gap | Evidence |
|---|---|
| **`jti` replay.** The same proof is accepted again until `iat` leaves the window. There is no `jti` store and no hook for one. The gate does not return the proof claims, so a caller must decode the `DPoP` header again to add a store (`src/rs.ts`, `replayGuard`). | `GAP: replayed proof` |
| **Symmetric `iat` window.** The check is `abs(now - iat) <= 300`, so a proof with `iat = now + 290` is accepted. With no `jti` store, one proof can be replayed for about 10 minutes. | `GAP: future iat` |
| **`htu` comes from `request.url`.** Behind TLS termination or a Host rewrite, the client signs the public URL and the gate compares it with the internal URL. The fetch gate has no option to set the expected URL. | `GAP: htu is compared with request.url` |
| **Nonce `verify` is synchronous.** `DpopNonceState.verify` returns `boolean`. A nonce store that several instances share (for example Redis) needs `Promise<boolean>`. | type of `DpopAuthOptions.nonce` |
| **No `expectedResource` check.** The PR branch is older than 2.3.1, which added `VerifyBearerTokenOptions.expectedResource`. After a rebase, `verifyDpopToken` needs the same check, or DPoP endpoints skip a check that Bearer endpoints make. | `test/pr2630-base.test.ts` |

Smaller notes: an `htu` with one trailing slash is accepted. `DPoP  <token>` (two spaces) is refused. A key-binding mismatch answers `invalid_token`, not `invalid_dpop_proof`.

## Findings: client external signer

The 2.3.1 client needs a `DpopSession` from `OAuthClientProvider.dpop()`. `DpopSession` signs with a WebCrypto `CryptoKey`, so a key in a KMS, an HSM, an enclave, or a remote service cannot be used directly.

TypeScript errors (`evidence/ducktype-tsc.txt`):

| Attempt | Result |
|---|---|
| `const s: DpopSession = ext` | TS2741: `keyPair` is missing |
| `ext as DpopSession` | TS2352: the types do not overlap enough |
| `dpop: () => ext` | TS2322 (same cause) |
| `new DpopSession()` | TS2673: the constructor is private |
| `class X extends DpopSession` | TS2675: cannot extend; the constructor is private |
| `DpopSession.create({ keyPair: { ...kp, privateKey: remote } })` | TS2739: not a `CryptoKey` |
| `ext as unknown as DpopSession` | Compiles. This is the only approach that does. |

`DpopSession` has private members, so TypeScript compares it nominally, and no other object matches the type.

At runtime (`test/ducktype.test.ts`):

- The double-cast session completes `auth()`, both nonce retries, and tool calls.
- A bare object with only `buildProof`, `observeNonce`, `nonceFor`, and `rememberNonce` also works. The SDK calls only `buildProof` and `observeNonce`. It does not read `thumbprint`, `alg`, or `publicJwk`, and it does no `instanceof` check.
- `DpopSession.create` with a non-`CryptoKey` private key compiles with a cast, but the first `buildProof` throws a `TypeError` inside `jose`.
- A JavaScript subclass of `DpopSession` works at runtime. The private constructor is a TypeScript check only.

So the cast works today, but it depends on internal behavior. If a later SDK version calls another member or adds a brand check, the cast breaks with no compile error.

## Latency

Local key against a mock remote signer. Each sample is one `client.callTool("echo")` (one HTTP POST, one proof) behind PR #2630's `requireDpopAuth`. N = 25 per variant, after one warm-up call. Nearest-rank percentiles. Everything runs in one process on one machine. The mock signer waits 230 ms per signature (`MOCK_SIGNER_DELAY_MS`).

| Proof signer | p50 (ms) | p95 (ms) | min | max | sign p50 | sign p95 |
|---|---|---|---|---|---|---|
| SDK `DpopSession` (WebCrypto, non-extractable) | 1.1 | 1.8 | 0.8 | 2.9 | n/a | n/a |
| External-signer adapter, local WebCrypto key | 0.7 | 0.8 | 0.6 | 0.9 | <0.1 | <0.1 |
| External-signer adapter, mock remote signer (230 ms) | 237.3 | 244.3 | 232.7 | 247.6 | 231.6 | 237.1 |

- The adapter adds no measurable time.
- With a remote signer, each MCP HTTP request waits for one signature. A proof binds `htm`, `htu`, `ath`, `iat`, and the nonce, so it cannot be signed in advance or reused.
- `connect()` signs at least 4 proofs: the token request, `initialize`, `notifications/initialized`, and the GET stream. Each nonce retry adds one more.

## License

Apache-2.0. See `LICENSE`.
