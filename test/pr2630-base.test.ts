/**
 * The PR #2630 preview build is based on an older `main`. Released 2.3.1 added
 * `VerifyBearerTokenOptions.expectedResource` (an audience check). The
 * preview build does not have it, so after a rebase `verifyDpopToken` needs
 * the same check, or DPoP endpoints will skip it.
 */
import { describe, expect, test } from "bun:test";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";

const root = join(import.meta.dir, "..", "node_modules");
const read = (pkg: string, file: string) => readFileSync(join(root, pkg, file), "utf8");
const count = (s: string, needle: string) => s.split(needle).length - 1;
/** All type declarations in a package's dist, concatenated (the build splits them into chunks). */
const types = (pkg: string) =>
  readdirSync(join(root, pkg, "dist"))
    .filter((f) => f.endsWith(".d.mts"))
    .map((f) => read(pkg, join("dist", f)))
    .join("\n");

describe("PR #2630 preview base", () => {
  test("preview package.json version is 2.0.0 (older main)", () => {
    expect(JSON.parse(read("mcp-server-pr2630", "package.json")).version).toBe("2.0.0");
  });

  test("released 2.3.1 types declare expectedResource", () => {
    expect(count(types("@modelcontextprotocol/server"), "expectedResource")).toBeGreaterThan(0);
  });

  test("GAP: preview types have no expectedResource", () => {
    expect(count(types("mcp-server-pr2630"), "expectedResource")).toBe(0);
    expect(types("mcp-server-pr2630")).toContain("requireDpopAuth");
  });
});
