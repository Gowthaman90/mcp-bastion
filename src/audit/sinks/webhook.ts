/**
 * A sink that POSTs batches of audit events to an HTTP endpoint (e.g. a webhook
 * receiver or an OpenTelemetry Collector's HTTP JSON receiver).
 *
 * Events are buffered and sent in batches; `write` never blocks the caller. Sends
 * are tracked so `flush`/`close` can await in-flight deliveries. A single retry is
 * attempted on failure; persistent failures are logged, not thrown.
 *
 * @packageDocumentation
 */
import { logger } from "../../observability/index.js";
import type { AuditEvent, AuditSink } from "../types.js";

export interface WebhookSinkOptions {
  url: string;
  batchSize: number;
  timeoutMs: number;
}

export class WebhookSink implements AuditSink {
  readonly name: string;
  private buffer: AuditEvent[] = [];
  private readonly pending = new Set<Promise<void>>();

  constructor(private readonly opts: WebhookSinkOptions) {
    this.name = `webhook:${opts.url}`;
  }

  write(event: AuditEvent): void {
    this.buffer.push(event);
    if (this.buffer.length >= this.opts.batchSize) this.dispatch();
  }

  async flush(): Promise<void> {
    this.dispatch();
    await Promise.all([...this.pending]);
  }

  async close(): Promise<void> {
    await this.flush();
  }

  /** Move the current buffer into an in-flight, tracked send. */
  private dispatch(): void {
    if (this.buffer.length === 0) return;
    const batch = this.buffer;
    this.buffer = [];
    const task = this.send(batch).finally(() => this.pending.delete(task));
    this.pending.add(task);
  }

  private async send(events: AuditEvent[], attempt = 0): Promise<void> {
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), this.opts.timeoutMs);
      try {
        const res = await fetch(this.opts.url, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ events }),
          signal: controller.signal,
        });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
      } finally {
        clearTimeout(timer);
      }
    } catch (err) {
      if (attempt === 0) {
        await this.send(events, 1); // one retry
        return;
      }
      logger.warn(
        { sink: this.name, count: events.length, err: (err as Error)?.message ?? String(err) },
        "audit webhook delivery failed",
      );
    }
  }
}
