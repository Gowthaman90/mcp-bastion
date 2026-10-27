/**
 * Audit sinks and a factory that instantiates them from configuration.
 *
 * @packageDocumentation
 */
import type { SinkConfig } from "../../config/index.js";
import { logger } from "../../observability/index.js";
import type { AuditSink } from "../types.js";
import { ConsoleSink } from "./console.js";
import { FileSink } from "./file.js";
import { WebhookSink } from "./webhook.js";
import { OtlpSink } from "./otlp.js";

export { ConsoleSink } from "./console.js";
export { FileSink } from "./file.js";
export { WebhookSink } from "./webhook.js";
export { OtlpSink, toOtlpLogs } from "./otlp.js";
export { HttpBatchSink, backoffMs } from "./http-batch.js";

/**
 * Resolve an HTTP sink's headers: static `headers`, then `headersEnv` values read from the
 * environment. A missing or empty variable throws, so a misconfigured sink stops startup rather
 * than silently sending unauthenticated requests.
 */
export function resolveSinkHeaders(
  sink: string,
  headers: Record<string, string> | undefined,
  headersEnv: Record<string, string> | undefined,
  env: NodeJS.ProcessEnv = process.env,
): Record<string, string> | undefined {
  const out: Record<string, string> = { ...(headers ?? {}) };
  for (const [header, variable] of Object.entries(headersEnv ?? {})) {
    const value = env[variable];
    if (value === undefined || value === "") {
      throw new Error(
        `audit sink ${sink}: environment variable ${variable} (for header "${header}") is not set`,
      );
    }
    out[header] = value;
  }
  return Object.keys(out).length > 0 ? out : undefined;
}

function warnInsecure(sink: string, target: string, allow: boolean): void {
  if (allow && /^http:/i.test(target)) {
    logger.warn(
      { sink, target },
      "audit sink sends events over plain HTTP (allowInsecureTransport is on)",
    );
  }
}

/** Instantiate the configured sinks, each carrying its own `includeArgs` override when set. */
export function createSinks(configs: readonly SinkConfig[]): AuditSink[] {
  return configs.map((cfg) => {
    const sink = createSink(cfg);
    if (cfg.includeArgs !== undefined) sink.includeArgs = cfg.includeArgs;
    return sink;
  });
}

function createSink(cfg: SinkConfig): AuditSink {
  switch (cfg.type) {
    case "console":
      return new ConsoleSink();
    case "file":
      return new FileSink(cfg.path);
    case "webhook":
      warnInsecure("webhook", cfg.url, cfg.allowInsecureTransport);
      return new WebhookSink({
        url: cfg.url,
        headers: resolveSinkHeaders(`webhook:${cfg.url}`, cfg.headers, cfg.headersEnv),
        batchSize: cfg.batchSize,
        timeoutMs: cfg.timeoutMs,
        maxQueue: cfg.maxQueue,
      });
    case "otlp":
      warnInsecure("otlp", cfg.endpoint, cfg.allowInsecureTransport);
      return new OtlpSink({
        endpoint: cfg.endpoint,
        headers: resolveSinkHeaders(`otlp:${cfg.endpoint}`, cfg.headers, cfg.headersEnv),
        batchSize: cfg.batchSize,
        timeoutMs: cfg.timeoutMs,
        maxQueue: cfg.maxQueue,
      });
  }
}
