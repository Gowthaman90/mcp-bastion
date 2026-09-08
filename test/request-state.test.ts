import { describe, expect, it } from "vitest";

import { isSealedRequestState, openRequestState, sealRequestState } from "../src/security/index.js";

const key = "k".repeat(32);
const bind = { server: "vault", tool: "transfer_funds", principal: "alice" };

describe("requestState custody (MCP 2026-07-28 MRTR)", () => {
  it("seals and opens a continuation bound to principal, server and tool", () => {
    const sealed = sealRequestState("upstream-opaque", { key, ...bind });
    expect(isSealedRequestState(sealed)).toBe(true);
    const opened = openRequestState(sealed, { key, ...bind });
    expect(opened.ok).toBe(true);
    if (opened.ok) expect(opened.upstreamState).toBe("upstream-opaque");
  });

  it("rejects a tampered envelope (integrity)", () => {
    const sealed = sealRequestState("x", { key, ...bind });
    const [p, body, sig] = sealed.split(".");
    const forgedBody = Buffer.from(JSON.stringify({ ...JSON.parse(Buffer.from(body.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString()), sub: "bob" })).toString("base64url");
    const r = openRequestState(`${p}.${forgedBody}.${sig}`, { key, ...bind, principal: "bob" });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.findings[0].rule).toBe("requeststate-forged");
  });

  it("rejects replay by a different principal", () => {
    const sealed = sealRequestState("x", { key, ...bind });
    const r = openRequestState(sealed, { key, ...bind, principal: "mallory" });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.findings[0].rule).toBe("requeststate-cross-principal");
  });

  it("rejects replay after the TTL", () => {
    let now = 1_000_000_000_000;
    const sealed = sealRequestState("x", { key, ...bind, ttlSeconds: 60, now: () => now });
    now += 61_000;
    const r = openRequestState(sealed, { key, ...bind, now: () => now });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.findings[0].rule).toBe("requeststate-expired");
  });

  it("rejects a continuation presented to a different server/tool", () => {
    const sealed = sealRequestState("x", { key, ...bind });
    const r = openRequestState(sealed, { key, ...bind, tool: "read_balance" });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.findings[0].rule).toBe("requeststate-cross-request");
  });

  it("refuses raw (unsealed) upstream state on a retry", () => {
    const r = openRequestState("eyJwcmluY2lwYWwiOiJib2IifQ==", { key, ...bind });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.findings[0].rule).toBe("requeststate-unsealed");
  });

  it("rejects an envelope sealed under another key", () => {
    const sealed = sealRequestState("x", { key: "other-key-other-key-other-key-00", ...bind });
    const r = openRequestState(sealed, { key, ...bind });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.findings[0].rule).toBe("requeststate-forged");
  });
});
