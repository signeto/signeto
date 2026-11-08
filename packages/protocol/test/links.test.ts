// §3.5 review links: properties the vectors cannot enumerate. Whatever a signed value contains, a rendered
// link stays on its allowlisted host, has no userinfo or port, and decodes back to exactly the value.
import { describe, expect, it } from "vitest";
import { encodeLinkSegment, renderLinks, templateLinksError, templateProblems, templateSha256, type TemplateBody } from "../src/index.js";

const template: TemplateBody = {
  text: "{v}",
  links: [
    { label: "plain", url: "https://example.com/p/{v}" },
    { label: "path", url: "https://example.com/{v:path}/end" },
    { label: "query", url: "https://example.com/s?q={v}#top" },
  ],
  link_hosts: ["example.com"],
};

// xorshift32, so a failure reproduces
let seed = 0x1ee7;
const rnd = (n: number) => {
  seed ^= seed << 13;
  seed >>>= 0;
  seed ^= seed >>> 17;
  seed ^= seed << 5;
  seed >>>= 0;
  return seed % n;
};
const alphabet = ["/", "?", "#", "@", ":", "%", "2", "F", ".", "..", "\\", " ", "\t", "\n", "a", "Z", "é", "😀", "‮", "́", "&", "=", "+", "[", "]", "evil.com", "//", "%2e", "%2F"];

describe("renderLinks", () => {
  it("never leaves the allowlisted host and always decodes back to the signed value", () => {
    for (let i = 0; i < 5000; i++) {
      const v = Array.from({ length: 1 + rnd(8) }, () => alphabet[rnd(alphabet.length)]).join("");
      const { links, error } = renderLinks(template, { v });
      expect(error).toBeUndefined();
      for (const l of links) {
        const u = new URL(l.url);
        expect([u.protocol, u.hostname, u.port, u.username, u.password]).toEqual(["https:", "example.com", "", "", ""]);
        expect(u.pathname.split("/")).not.toContain("..");
        expect(/^[\x21-\x7e]+$/.test(l.url)).toBe(true); // ASCII, no spaces or controls
        if (l.label === "plain") expect(decodeURIComponent(l.url.slice("https://example.com/p/".length))).toBe(v);
        if (l.label === "path") expect(l.url.slice("https://example.com/".length, -"/end".length).split("/").map(decodeURIComponent).join("/")).toBe(v);
        if (l.label === "query") {
          expect(u.hash).toBe("#top");
          expect(decodeURIComponent(l.url.slice("https://example.com/s?q=".length, -"#top".length))).toBe(v);
        }
      }
    }
  });

  it("drops a link whose value is a lone surrogate (not UTF-8 encodable)", () => {
    expect(renderLinks(template, { v: "a\uD800" }).links).toEqual([]);
  });

  it("percent-encodes everything but RFC 3986 unreserved characters, uppercase hex", () => {
    expect(encodeLinkSegment("AZaz09-._~")).toBe("AZaz09-._~");
    expect(encodeLinkSegment("/?#[]@!$&'()*+,;=% é")).toBe("%2F%3F%23%5B%5D%40%21%24%26%27%28%29%2A%2B%2C%3B%3D%25%20%C3%A9");
  });
});

describe("template rules", () => {
  it("templateProblems reports bad text, note formatters and links", () => {
    expect(templateProblems(template)).toEqual([]);
    expect(templateProblems({ text: "{a:short}" })).toHaveLength(1);
    expect(templateProblems({ text: "{a}", note: "{a:path}" })).toHaveLength(1);
    expect(templateProblems({ text: "{a}", links: [{ label: "x", url: "http://example.com/" }], link_hosts: ["example.com"] })).toEqual(["links are invalid: url_not_https"]);
  });

  it("templateLinksError is null without links", () => {
    expect(templateLinksError({ text: "x" })).toBeNull();
  });

  it("a text-only template hashes its text; elide, note and links select the extended form", () => {
    expect(templateSha256({ text: "Read PR #{pr} on {repo}" })).toBe(templateSha256("Read PR #{pr} on {repo}"));
    expect(templateSha256({ text: "Read PR #{pr} on {repo}", elide: [] })).toBe(templateSha256("Read PR #{pr} on {repo}"));
    expect(templateSha256({ text: "Read PR #{pr} on {repo}", elide: ["x"] })).not.toBe(templateSha256("Read PR #{pr} on {repo}"));
    expect(templateSha256({ text: "Read PR #{pr} on {repo}", note: "n" })).not.toBe(templateSha256("Read PR #{pr} on {repo}"));
  });
});
