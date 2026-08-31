/**
 * Header/body coherence for the Streamable HTTP transport (protocol revision 2026-07-28).
 *
 * The 2026-07-28 revision mirrors selected JSON-RPC body fields into HTTP headers
 * (`MCP-Protocol-Version`, `Mcp-Method`, `Mcp-Name`, `Mcp-Param-*`) so that intermediaries can route
 * and inspect requests without parsing the body. The body remains the source of truth, and the spec
 * requires servers to reject a request whose headers disagree with it — HTTP 400 plus JSON-RPC error
 * `-32020` (`HeaderMismatch`) — precisely because "different components in the network rely on
 * different sources of truth (e.g., a load balancer routing on the header value while the MCP server
 * executes based on the body value)".
 *
 * Bastion is one of those intermediaries, so the spec's note to intermediaries applies directly: one
 * that enforces policy on mirrored headers SHOULD verify that `MCP-Protocol-Version` indicates a
 * revision requiring header-body validation, and SHOULD reject rather than trust the headers when the
 * version is older or absent.
 *
 * Every rule here fires only on an unambiguous disagreement, so the check stays at zero false
 * positives against conforming traffic — including pre-2026-07-28 clients, which are never required
 * to send these headers and are therefore never flagged for omitting them.
 *
 * @packageDocumentation
 */
import type { SecurityFinding } from "./types.js";

/** The first protocol revision that mirrors body fields into headers and mandates validation. */
export const HEADER_VALIDATION_REVISION = "2026-07-28";

/** Body `_meta` key carrying the protocol version in 2026-07-28. */
const META_VERSION_KEY = "io.modelcontextprotocol/protocolVersion";

/** Base64 sentinel wrapper for header values that are not plain-ASCII safe: `=?base64?...?=`. */
const SENTINEL = /^=\?base64\?([A-Za-z0-9+/=]*)\?=$/;

/**
 * Characters no HTTP field value may contain. Per RFC 9110 a field value is visible ASCII, space, or
 * horizontal tab; CR and LF additionally carry a header-splitting risk. U+0009 (HTAB) is allowed.
 */
// Matching control characters is the point of this rule: they are exactly what must be rejected.
// eslint-disable-next-line no-control-regex
const ILLEGAL_HEADER_CHARS = /[\u0000-\u0008\u000A-\u001F\u007F]/;

/** Raw header bag, in the shape Node's `IncomingMessage.headers` provides. */
export type HeaderBag = Record<string, string | string[] | undefined>;

/** Optional context that lets the check validate `Mcp-Param-*` headers against a tool's schema. */
export interface HeaderCheckContext {
  /**
   * The invoked tool's `inputSchema`. When supplied, `Mcp-Param-*` headers are resolved against the
   * `x-mcp-header` annotations in it and compared with the call arguments. Omit it and only the
   * always-invalid cases (bad characters, conflicting duplicates) are checked.
   */
  inputSchema?: unknown;
}

/**
 * MCP protocol revisions are ISO dates, so lexicographic order is chronological order.
 * Returns true when the declared revision mandates header-body validation.
 */
export function requiresHeaderValidation(version: string | undefined): boolean {
  return typeof version === "string" && version >= HEADER_VALIDATION_REVISION;
}

/**
 * Decode the spec's Base64 sentinel form (streamable-http, Value Encoding). Servers MUST decode an
 * encoded `Mcp-Name` or `Mcp-Param-{Name}` before comparing it to the body, so a defender that
 * compares raw strings has a spec-defined blind spot. Non-sentinel values pass through unchanged.
 */
export function decodeHeaderValue(value: string): string {
  const m = SENTINEL.exec(value);
  if (!m) return value;
  try {
    return Buffer.from(m[1], "base64").toString("utf8");
  } catch {
    return value;
  }
}

/**
 * Read one header. Returns `undefined` when absent, or `{ conflict: true }` when the same header
 * arrived more than once with differing values — itself a desync, so we never silently pick one.
 */
function readHeader(headers: HeaderBag, name: string): { value?: string; conflict?: boolean } {
  const raw = headers[name.toLowerCase()];
  if (raw === undefined) return {};
  if (Array.isArray(raw)) {
    const distinct = [...new Set(raw.map((v) => v.trim()))];
    if (distinct.length === 0) return {};
    if (distinct.length > 1) return { conflict: true };
    return { value: distinct[0] };
  }
  return { value: raw.trim() };
}

function hasIllegalHeaderChars(value: string): boolean {
  return ILLEGAL_HEADER_CHARS.test(value);
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/**
 * The body field `Mcp-Name` mirrors, per method. `undefined` means this method does not carry the
 * header, so nothing is compared.
 */
function expectedNameField(method: string, params: Record<string, unknown>): string | undefined {
  switch (method) {
    case "tools/call":
    case "prompts/get":
      return typeof params.name === "string" ? params.name : undefined;
    case "resources/read":
      return typeof params.uri === "string" ? params.uri : undefined;
    // ext-tasks: the client MUST set Mcp-Name to params.taskId on task methods.
    case "tasks/get":
    case "tasks/update":
    case "tasks/cancel":
      return typeof params.taskId === "string" ? params.taskId : undefined;
    default:
      return undefined;
  }
}

/** Collect `x-mcp-header` annotations that are statically reachable through `properties` chains. */
function collectHeaderAnnotations(
  schema: unknown,
  path: string[] = [],
  out: Map<string, string[]> = new Map(),
): Map<string, string[]> {
  if (!isRecord(schema)) return out;
  const props = schema.properties;
  if (!isRecord(props)) return out;
  for (const [key, sub] of Object.entries(props)) {
    if (!isRecord(sub)) continue;
    const here = [...path, key];
    const ann = sub["x-mcp-header"];
    if (typeof ann === "string" && ann.length > 0) out.set(ann.toLowerCase(), here);
    collectHeaderAnnotations(sub, here, out);
  }
  return out;
}

/** Read the value at an exact property path in the call arguments. */
function valueAtPath(args: unknown, path: string[]): unknown {
  let cur: unknown = args;
  for (const seg of path) {
    if (!isRecord(cur)) return undefined;
    cur = cur[seg];
  }
  return cur;
}

/** Render a primitive argument the way a conforming client would before comparing. */
function renderParam(value: unknown): string | undefined {
  if (typeof value === "string") return value;
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number" && Number.isInteger(value)) return String(value);
  return undefined;
}

/**
 * Compare the mirrored HTTP headers of an MCP request against its JSON-RPC body.
 *
 * @param headers - Incoming HTTP headers (names are matched case-insensitively, as RFC 9110 requires).
 * @param body - The parsed JSON-RPC request body.
 * @param ctx - Optional tool `inputSchema`, enabling `Mcp-Param-*` validation.
 * @returns One finding per disagreement; an empty array for conforming traffic.
 */
export function checkHeaderBodyCoherence(
  headers: HeaderBag,
  body: unknown,
  ctx: HeaderCheckContext = {},
): SecurityFinding[] {
  const findings: SecurityFinding[] = [];
  if (!isRecord(body) || typeof body.method !== "string") return findings;

  const bodyMethod = body.method;
  const params = isRecord(body.params) ? body.params : {};
  const meta = isRecord(params._meta) ? params._meta : {};
  const bodyVersion =
    typeof meta[META_VERSION_KEY] === "string" ? (meta[META_VERSION_KEY] as string) : undefined;

  const version = readHeader(headers, "mcp-protocol-version");
  const method = readHeader(headers, "mcp-method");
  const name = readHeader(headers, "mcp-name");

  const hasRoutingHeaders = method.value !== undefined || name.value !== undefined;
  const declared = version.value ?? bodyVersion;
  const validated = requiresHeaderValidation(declared);

  // --- conflicting duplicates: never guess which copy is authoritative ---
  for (const [label, read] of [
    ["MCP-Protocol-Version", version],
    ["Mcp-Method", method],
    ["Mcp-Name", name],
  ] as const) {
    if (read.conflict) {
      findings.push({
        rule: "header-duplicate-conflict",
        severity: "high",
        excerpt: `${label} sent more than once with differing values`,
      });
    }
  }

  // --- illegal characters: invalid under every revision ---
  for (const [label, read] of [
    ["Mcp-Method", method],
    ["Mcp-Name", name],
  ] as const) {
    if (read.value !== undefined && hasIllegalHeaderChars(read.value)) {
      findings.push({
        rule: "header-invalid-value",
        severity: "high",
        excerpt: `${label} contains control characters`,
      });
    }
  }

  // --- protocol version: header vs body _meta ---
  if (version.value !== undefined && bodyVersion !== undefined && version.value !== bodyVersion) {
    findings.push({
      rule: "header-body-mismatch",
      severity: "high",
      excerpt: `MCP-Protocol-Version header ${version.value} != body _meta ${bodyVersion}`,
    });
  }

  // --- an intermediary must not enforce policy on headers no server has validated ---
  if (hasRoutingHeaders && !validated) {
    findings.push({
      rule: "unvalidated-header-routing",
      severity: "medium",
      excerpt: declared
        ? `routing headers under protocol version ${declared}, which does not mandate header-body validation`
        : "routing headers present with no MCP-Protocol-Version to validate them against",
    });
  }

  // --- Mcp-Method vs body.method ---
  if (method.value !== undefined && method.value !== bodyMethod) {
    findings.push({
      rule: "header-body-mismatch",
      severity: "high",
      excerpt: `Mcp-Method header ${method.value} != body method ${bodyMethod}`,
    });
  }

  // --- Mcp-Name vs the body field it mirrors (decoding the sentinel first) ---
  if (name.value !== undefined) {
    const expected = expectedNameField(bodyMethod, params);
    if (expected !== undefined) {
      const decoded = decodeHeaderValue(name.value);
      if (decoded !== expected) {
        const via = decoded === name.value ? "" : " (base64-sentinel)";
        findings.push({
          rule: "header-body-mismatch",
          severity: "high",
          excerpt: `Mcp-Name header ${decoded}${via} != body value ${expected}`,
        });
      }
    }
  }

  // --- required headers, but only for a revision that requires them ---
  if (validated) {
    if (version.value === undefined) {
      findings.push({
        rule: "header-missing-required",
        severity: "medium",
        excerpt: `MCP-Protocol-Version required from ${HEADER_VALIDATION_REVISION}`,
      });
    }
    if (method.value === undefined) {
      findings.push({
        rule: "header-missing-required",
        severity: "medium",
        excerpt: `Mcp-Method required from ${HEADER_VALIDATION_REVISION}`,
      });
    }
    if (name.value === undefined && expectedNameField(bodyMethod, params) !== undefined) {
      findings.push({
        rule: "header-missing-required",
        severity: "medium",
        excerpt: `Mcp-Name required on ${bodyMethod} from ${HEADER_VALIDATION_REVISION}`,
      });
    }
  }

  // --- Mcp-Param-* against the tool's x-mcp-header annotations ---
  const paramHeaders = Object.keys(headers).filter((h) => h.toLowerCase().startsWith("mcp-param-"));
  for (const h of paramHeaders) {
    const read = readHeader(headers, h);
    if (read.conflict) {
      findings.push({
        rule: "header-duplicate-conflict",
        severity: "high",
        excerpt: `${h} sent more than once with differing values`,
      });
      continue;
    }
    if (read.value === undefined) continue;
    if (hasIllegalHeaderChars(read.value)) {
      findings.push({
        rule: "header-invalid-value",
        severity: "high",
        excerpt: `${h} contains control characters`,
      });
      continue;
    }
    if (ctx.inputSchema === undefined || bodyMethod !== "tools/call") continue;
    const annotations = collectHeaderAnnotations(ctx.inputSchema);
    const annName = h.slice("mcp-param-".length).toLowerCase();
    const path = annotations.get(annName);
    if (path === undefined) {
      findings.push({
        rule: "header-unknown-param",
        severity: "medium",
        excerpt: `${h} has no matching x-mcp-header annotation in the tool schema`,
      });
      continue;
    }
    const expected = renderParam(valueAtPath(params.arguments, path));
    // An absent value means a conforming client omits the header entirely, so nothing can mismatch.
    if (expected === undefined) continue;
    const decoded = decodeHeaderValue(read.value);
    if (decoded !== expected) {
      findings.push({
        rule: "header-body-mismatch",
        severity: "high",
        excerpt: `${h} value ${decoded} != argument ${path.join(".")} value ${expected}`,
      });
    }
  }

  return findings;
}
