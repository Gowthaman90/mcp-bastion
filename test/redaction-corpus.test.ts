import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";

import { prepareArgs } from "../src/audit/index.js";
import { BastionConfigSchema } from "../src/config/index.js";
import { UpstreamManager } from "../src/core/index.js";
import { redactSecrets } from "../src/security/dlp.js";

/**
 * Redaction corpus (plan R3). Each SECRET case must lose its secret; each BENIGN control must come
 * back byte-identical. Values are fake but shaped like the real thing.
 */
const SECRETS: Array<[string, string, string]> = [
  ["AWS access key id", "key AK" + "IAIOSFODNN7EXAMPLE in use", "AK" + "IAIOSFODNN7EXAMPLE"],
  ["AWS temporary key id", "AS" + "IAY34FZKBOKMUTVV7A", "AS" + "IAY34FZKBOKMUTVV7A"],
  [
    "AWS secret assignment",
    "aws_secret_access_key = wJalrXUtn" + "FEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "wJalrXUtn" + "FEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
  ],
  [
    "GitHub classic PAT",
    "token gh" + "p_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789",
    "gh" + "p_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789",
  ],
  [
    "GitHub fine-grained PAT",
    "github" + "_pat_11ABCDEFG0123456789_abcdefghijklmnopqrstuvwxyzABCDEFGHIJ",
    "github" + "_pat_11ABCDEFG0123456789_abcdefghijklmnopqrstuvwxyzABCDEFGHIJ",
  ],
  [
    "GitHub OAuth token",
    "gh" + "o_16C7e42F292c6912E7710c838347Ae178B4a",
    "gh" + "o_16C7e42F292c6912E7710c838347Ae178B4a",
  ],
  [
    "OpenAI project key",
    "OPENAI sk-" + "proj-Ab3dEf6hIj9kLm2nOp5qRs8tUv1wXy4z",
    "sk-" + "proj-Ab3dEf6hIj9kLm2nOp5qRs8tUv1wXy4z",
  ],
  [
    "Anthropic key",
    "sk-" + "ant-api03-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789",
    "sk-" + "ant-api03-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789",
  ],
  [
    "Stripe live secret",
    "stripe: sk_" + "live_51H8xYzAbCdEfGhIjKlMnOp",
    "sk_" + "live_51H8xYzAbCdEfGhIjKlMnOp",
  ],
  ["Stripe restricted key", "rk_live_51H8xYzAbCdEfGhIjKlMnOp", "rk_live_51H8xYzAbCdEfGhIjKlMnOp"],
  [
    "Google API key",
    "maps key AI" + "zaSyD-9tSrke72PouQMnMX-a7eZSW0jkFMBWY",
    "AI" + "zaSyD-9tSrke72PouQMnMX-a7eZSW0jkFMBWY",
  ],
  [
    "Slack bot token",
    "xox" + "b-123456789012-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx",
    "xox" + "b-123456789012-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx",
  ],
  [
    "Slack webhook URL",
    "post to https://hooks.slack" + ".com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX",
    "XXXXXXXXXXXXXXXXXXXXXXXX",
  ],
  [
    "npm token",
    "//registry.npmjs.org/:_authToken=np" + "m_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789",
    "np" + "m_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789",
  ],
  [
    "JWT",
    "id_token eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9" +
      ".eyJzdWIiOiJ1c2VyLTEyMyIsImV4cCI6MTc5MDAwMDAwMH0.c2lnbmF0dXJlLWJ5dGVzLWhlcmUtb2stb2s",
    "eyJzdWIiOiJ1c2VyLTEyMyIsImV4cCI6MTc5MDAwMDAwMH0",
  ],
  [
    "Bearer header",
    "Authorization: Bearer 4f9c2a7e1b8d4c3a9e6f0b2d7a5c8e1f",
    "4f9c2a7e1b8d4c3a9e6f0b2d7a5c8e1f",
  ],
  [
    "Postgres URL password",
    "postgres://app_user" + ":Pa55w0rd-Prod@db.internal:5432/orders",
    "Pa55w0rd-Prod",
  ],
  [
    "Mongo URL password",
    "mongodb+srv://admin" + ":S3cr3tMongo!@cluster0.example.net/test",
    "S3cr3tMongo!",
  ],
  [
    "Azure storage AccountKey",
    "DefaultEndpointsProtocol=https;AccountName=acct;Account" +
      "Key=bXlTZWNyZXRLZXlWYWx1ZTEyMw==;EndpointSuffix=core.windows.net",
    "bXlTZWNyZXRLZXlWYWx1ZTEyMw==",
  ],
  ["env PASSWORD", "DB_PASSWORD=hunter2!x", "hunter2!x"],
  ["env API_KEY", "API_KEY: 9d1f3c5e7a9b1d3f", "9d1f3c5e7a9b1d3f"],
  ["name starting with PASSWORD", "PASSWORD=hunter2!x", "hunter2!x"],
  ["name starting with TOKEN", "TOKEN: q8Zr2LmN5vXp", "q8Zr2LmN5vXp"],
  [
    "bare token, long random value",
    "retrying with token=8f3kq2vlx9zp4mwn7rty1sbc",
    "8f3kq2vlx9zp4mwn7rty1sbc",
  ],
  ["bare secret, mixed-case value", "secret: Xq7mR2pL9vWz", "Xq7mR2pL9vWz"],
  ["client secret", "client_secret=Zk3Q~abcDEF.ghiJKL-mnoPQR_stu", "Zk3Q~abcDEF.ghiJKL-mnoPQR_stu"],
  [
    "URL query token",
    "https://api.example.com/v1/export?access_token=ya2" + "9.a0AfH6SMBx3kLm9Q",
    "ya2" + "9.a0AfH6SMBx3kLm9Q",
  ],
  [
    "RSA private key",
    "-----BEGIN RSA PRIVATE" +
      " KEY-----\nMIIEowIBAAKCAQEAu1SU1LfVLPHCozMxH2Mo\n-----END RSA PRIVATE" +
      " KEY-----",
    "MIIEowIBAAKCAQEAu1SU1LfVLPHCozMxH2Mo",
  ],
  [
    "OpenSSH private key",
    "-----BEGIN OPENSSH PRIVATE" +
      " KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmU=\n-----END OPENSSH PRIVATE" +
      " KEY-----",
    "b3BlbnNzaC1rZXktdjEAAAAABG5vbmU=",
  ],
];

const BENIGN: Array<[string, string]> = [
  [
    "prose mentioning key prefixes",
    "AWS access keys start with AK" + "IA and GitHub tokens with gh" + "p_.",
  ],
  ["token count", "max_tokens: 1500"],
  ["boolean flag", "api_key_required: true"],
  ["null value", "SECRET_ARN: null"],
  ["password reset prose", "We sent a password reset link to your email."],
  ["git SHA", "commit 9fceb02d0ae598e95dc970b74767f19372d61af8"],
  ["UUID", "request 3f2504e0-4f89-11d3-9a0c-0305e82c3301"],
  [
    "public key PEM",
    "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE=\n-----END PUBLIC KEY-----",
  ],
  ["URL without credentials", "https://db.internal:5432/orders?sslmode=require"],
  ["skill name with dash", "the sk-learn tutorial"],
  ["base64 image prefix", "data:image/png;base64,iVBORw0KGgo"],
  ["email address", "contact ana.k@example.com"],
  ["log line with a cache key", "2026-09-05T10:00:04Z INFO  cache invalidated key=users:*"],
  ["bare cache key pattern", "key=users:*"],
  ["token in prose", "token refresh took 1.9s"],
  ["sort key column name", "sort key=created_at"],
];

describe("redaction corpus", () => {
  it.each(SECRETS)("redacts: %s", (_label, text, secret) => {
    const { text: out, redactions } = redactSecrets(text);
    expect(redactions).toBeGreaterThan(0);
    expect(out).not.toContain(secret);
  });

  it.each(BENIGN)("leaves alone: %s", (_label, text) => {
    expect(redactSecrets(text)).toEqual({ text, redactions: 0 });
  });

  it("redacts nested arguments by key and by value", () => {
    const args = {
      query: "select 1",
      connection: { url: "postgres://u" + ":Pa55w0rd-Prod@db/x", password: "plain-pass" },
      headers: [{ name: "Authorization", value: "Bearer 4f9c2a7e1b8d4c3a9e6f0b2d7a5c8e1f" }],
      max_tokens: 1500,
    };
    const out = JSON.stringify(prepareArgs(args, "redacted", ["password"]));
    expect(out).not.toMatch(/Pa55w0rd-Prod|plain-pass|4f9c2a7e1b8d4c3a9e6f0b2d7a5c8e1f/);
    expect(out).toContain('"max_tokens":1500');
    expect(out).toContain('"query":"select 1"');
  });
});

describe("what never leaves the process (R2)", () => {
  let mgr: UpstreamManager | undefined;
  afterEach(async () => {
    await mgr?.closeAll();
  });

  it("audit events never carry the tool result, even with includeArgs: full", async () => {
    const mutating = fileURLToPath(new URL("./fixtures/mutating-server.mjs", import.meta.url));
    const d = mkdtempSync(join(tmpdir(), "bastion-r2-"));
    const desc = join(d, "desc.txt");
    writeFileSync(desc, "echoes its input");
    const log = join(d, "audit.jsonl");
    mgr = new UpstreamManager(
      BastionConfigSchema.parse({
        servers: { mut: { command: process.execPath, args: [mutating, desc] } },
        reconnect: { auto: false },
        healthCheck: { enabled: false },
        security: { validateArguments: false },
        audit: { enabled: true, includeArgs: "full", sinks: [{ type: "file", path: log }] },
      }),
    );
    await mgr.connectAll();
    // The fixture echoes `echo` back; the result marker must never reach the audit log.
    await mgr.callUpstreamTool("mut__op", { echo: "RESULT-ONLY-7f3a" });
    await mgr.closeAll();
    mgr = undefined;
    const text = readFileSync(log, "utf8");
    const event = JSON.parse(text.trim().split("\n")[0]);
    expect(event.args).toEqual({ echo: "RESULT-ONLY-7f3a" }); // the argument is recorded (full)…
    expect(Object.keys(event)).not.toContain("result"); // …the result is not
    expect(text.match(/RESULT-ONLY-7f3a/g)).toHaveLength(1); // only inside args
  });
});
