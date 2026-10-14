/**
 * Type-level probe: every way we tried to hand an external-signer
 * session to the 2.3.1 client. Run `bun run probe:types`; the errors are
 * recorded in evidence/ducktype-tsc.txt. This file is meant NOT to compile.
 */
import { DpopSession, generateDpopKeyPair, type DpopKeyPair, type OAuthClientProvider } from "@modelcontextprotocol/client";
import { ExternalSignerDpopSession, localSigner } from "../src/external-session.ts";

const ext = await ExternalSignerDpopSession.create(await localSigner());

// P1. Plain assignment of a structurally identical public surface.
const p1: DpopSession = ext;

// P2. Direct type assertion.
const p2 = ext as DpopSession;

// P3. Return it from an OAuthClientProvider.dpop().
const p3: Pick<OAuthClientProvider, "dpop"> = { dpop: () => ext };

// P4. Construct the SDK class directly.
const p4 = new DpopSession();

// P5. Subclass the SDK class and override buildProof.
class P5 extends DpopSession {
  override async buildProof(): Promise<string> {
    return "x";
  }
}

// P6. DpopSession.create with a keyPair whose privateKey is not a CryptoKey.
const remoteKey = { sign: async (_input: string) => new Uint8Array(64) };
const kp = await generateDpopKeyPair();
const p6 = await DpopSession.create({ keyPair: { ...kp, privateKey: remoteKey } });

// P7. What compiles: double cast through unknown.
const p7 = ext as unknown as DpopSession;

// P8. What also compiles: a keyPair typed as DpopKeyPair via a cast (fails at runtime, see test/ducktype.test.ts).
const p8 = await DpopSession.create({ keyPair: { ...kp, privateKey: remoteKey } as unknown as DpopKeyPair });

export { p1, p2, p3, p4, P5, p6, p7, p8 };
