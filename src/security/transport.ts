/**
 * Transport-layer security checks — the layer most MCP defenses ignore.
 *
 *   - {@link checkTransportSecurity}: flags a remote server reachable over plaintext HTTP
 *     (a man-in-the-middle exposure); local/loopback HTTP and any HTTPS are fine.
 *   - {@link checkRequestOrigin}: flags a request that targets a loopback server but carries a
 *     foreign `Origin` — the shape of a DNS-rebinding attack against a local MCP server.
 *
 * Both are pure and dependency-free so they can be unit-tested and reused by tooling.
 *
 * @packageDocumentation
 */
import type { SecurityFinding } from "./types.js";

/** Strip an optional `:port` and brackets, l-case; is this an IPv4/IPv6 loopback or localhost? */
function isLoopbackHost(hostHeader: string | undefined): boolean {
  if (!hostHeader) return false;
  let host = hostHeader.trim().toLowerCase();
  // IPv6 literal: [::1]:port or [::1]
  if (host.startsWith("["))
    host = host.slice(1, host.indexOf("]") === -1 ? undefined : host.indexOf("]"));
  else host = host.split(":")[0]; // drop :port for IPv4/hostname
  return host === "localhost" || host === "::1" || host === "0.0.0.0" || /^127\./.test(host);
}

/** Flag a remote MCP endpoint reachable over plaintext HTTP (MITM exposure). */
export function checkTransportSecurity(endpoint: string | undefined): SecurityFinding[] {
  if (!endpoint) return [];
  let url: URL;
  try {
    url = new URL(endpoint);
  } catch {
    return [];
  }
  if (url.protocol === "http:" && !isLoopbackHost(url.host)) {
    return [
      {
        rule: "insecure-transport",
        severity: "high",
        excerpt: `plaintext http:// to remote host ${url.host}`,
      },
    ];
  }
  return [];
}

/** Flag a request to a loopback server carrying a foreign Origin (DNS-rebinding shape). */
export function checkRequestOrigin(
  host: string | undefined,
  origin: string | undefined,
): SecurityFinding[] {
  if (!origin || !isLoopbackHost(host)) return [];
  let originHost: string | undefined;
  try {
    originHost = new URL(origin).host;
  } catch {
    // A non-URL Origin against a loopback server is itself suspicious.
    return [
      { rule: "cross-origin-request", severity: "high", excerpt: `malformed origin ${origin}` },
    ];
  }
  if (!isLoopbackHost(originHost)) {
    return [
      {
        rule: "cross-origin-request",
        severity: "high",
        excerpt: `foreign origin ${origin} to loopback server`,
      },
    ];
  }
  return [];
}
