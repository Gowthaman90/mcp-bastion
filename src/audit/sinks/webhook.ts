/**
 * A sink that POSTs batches of audit events to an HTTP endpoint (e.g. a webhook receiver or an
 * OpenTelemetry Collector's HTTP JSON receiver), as `{ "events": [...] }`.
 *
 * Delivery (bounded queue, retry with backoff, drop-oldest, health counters) is shared with the
 * OTLP sink, see {@link HttpBatchSink}.
 *
 * @packageDocumentation
 */
import type { AuditEvent } from "../types.js";
import { HttpBatchSink } from "./http-batch.js";

export interface WebhookSinkOptions {
  url: string;
  /** Extra request headers (e.g. an authorization token), already resolved. */
  headers?: Record<string, string>;
  batchSize: number;
  timeoutMs: number;
  /** Most events held while the receiver is unreachable. Default 10 000. */
  maxQueue?: number;
}

export class WebhookSink extends HttpBatchSink {
  readonly name: string;

  constructor(opts: WebhookSinkOptions) {
    super({ ...opts, maxQueue: opts.maxQueue ?? 10_000 });
    this.name = `webhook:${opts.url}`;
  }

  protected body(events: AuditEvent[]): unknown {
    return { events };
  }
}
