/**
 * A sink that writes audit events as JSON lines to stderr.
 *
 * stderr (not stdout) is used deliberately: on the stdio transport, stdout is the
 * JSON-RPC channel and must never carry anything else.
 *
 * @packageDocumentation
 */
import type { AuditEvent, AuditSink } from "../types.js";

export class ConsoleSink implements AuditSink {
  readonly name = "console";

  write(event: AuditEvent): void {
    process.stderr.write(`${JSON.stringify(event)}\n`);
  }

  async flush(): Promise<void> {
    // stderr writes are not buffered by this sink.
  }

  async close(): Promise<void> {
    // Nothing to release.
  }
}
