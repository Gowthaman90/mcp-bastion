/**
 * Audit sinks and a factory that instantiates them from configuration.
 *
 * @packageDocumentation
 */
import type { SinkConfig } from "../../config/index.js";
import type { AuditSink } from "../types.js";
import { ConsoleSink } from "./console.js";
import { FileSink } from "./file.js";
import { WebhookSink } from "./webhook.js";

export { ConsoleSink } from "./console.js";
export { FileSink } from "./file.js";
export { WebhookSink } from "./webhook.js";

/** Instantiate the configured sinks. */
export function createSinks(configs: readonly SinkConfig[]): AuditSink[] {
  return configs.map((cfg) => {
    switch (cfg.type) {
      case "console":
        return new ConsoleSink();
      case "file":
        return new FileSink(cfg.path);
      case "webhook":
        return new WebhookSink({
          url: cfg.url,
          batchSize: cfg.batchSize,
          timeoutMs: cfg.timeoutMs,
        });
    }
  });
}
