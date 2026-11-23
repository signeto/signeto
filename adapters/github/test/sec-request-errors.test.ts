// Security review 2026-11-23: fetch rejects a header value with a line break with an error that quotes the whole
// value. A token reaching a header that way must not reach an error message, the agent or the ledger.
import { describe, expect, it } from "vitest";
import { createReadOnlyClient, requestErrorText, GithubApiError } from "../src/client.js";

const TOKEN = "ghs_secretTOKENvalue1234567890";

describe("request errors never quote request headers", () => {
  it("the read-only client reports a failed request by its error class only", async () => {
    const leaky: typeof fetch = async (_url, init) => {
      const h = (init?.headers ?? {}) as Record<string, string>;
      throw new TypeError(`Headers.append: "${h["authorization"]}" is an invalid header value.`);
    };
    const client = createReadOnlyClient({ token: `${TOKEN}\nx`, fetch: leaky });
    const e = await client.get("/repos/acme/api/pulls/1").catch((x: unknown) => x as Error);
    expect(String(e) + JSON.stringify(e)).not.toContain(TOKEN);
    expect((e as Error).message).toMatch(/GitHub unreachable on GET \/repos\/acme\/api\/pulls\/1: TypeError$/);
  });

  it("keeps our own errors' messages", () => {
    expect(requestErrorText(new GithubApiError(404, "/x", "not found here"))).toBe("not found here");
    expect(requestErrorText(new TypeError(`bad "${TOKEN}"`))).toBe("TypeError");
    expect(requestErrorText("a string")).toBe("Error");
  });
});
