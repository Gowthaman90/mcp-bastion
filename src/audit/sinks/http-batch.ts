/**
 * Shared delivery for the HTTP audit sinks (webhook, OTLP).
 *
 * Events wait in a bounded queue and are POSTed in batches. A failed batch goes back to the front
 * of the queue and is retried with exponential backoff and jitter, so a receiver outage loses
 * nothing until the queue is full. When it is full, the OLDEST events are dropped and counted, so
 * memory stays bounded; receivers can also spot gaps from each event's `seq`. `write` never blocks
 * the caller. `flush` tries to deliver what is queued now; it does not wait out a backoff.
 *
 * @packageDocumentation
 */
import { logger } from "../../observability/index.js";
import type { AuditEvent, AuditSink, SinkHealth } from "../types.js";

export interface HttpBatchOptions {
  /** Full URL events are POSTed to. */
  url: string;
  /** Extra request headers (e.g. authorization), already resolved. */
  headers?: Record<string, string>;
  batchSize: number;
  timeoutMs: number;
  /** Most events held while the receiver is unreachable; the oldest are dropped beyond it. */
  maxQueue: number;
}

const BASE_DELAY_MS = 500;
const MAX_DELAY_MS = 30_000;

/** Exponential backoff with jitter: 0.5–1.0 × min(30 s, 0.5 s × 2^(attempt−1)). */
export function backoffMs(attempt: number, random: () => number = Math.random): number {
  const ceiling = Math.min(MAX_DELAY_MS, BASE_DELAY_MS * 2 ** Math.max(0, attempt - 1));
  return Math.round(ceiling * (0.5 + random() * 0.5));
}

export abstract class HttpBatchSink implements AuditSink {
  abstract readonly name: string;
  private queue: AuditEvent[] = [];
  private inFlight: Promise<boolean> | undefined;
  private retryTimer: ReturnType<typeof setTimeout> | undefined;
  private consecutiveFailures = 0;
  private delivered = 0;
  private dropped = 0;
  private failedAttempts = 0;
  private lastError: string | undefined;
  private closed = false;

  constructor(protected readonly opts: HttpBatchOptions) {}

  /** The request body for one batch. */
  protected abstract body(events: AuditEvent[]): unknown;

  write(event: AuditEvent): void {
    if (this.closed) {
      this.dropped++;
      return;
    }
    this.queue.push(event);
    this.trim();
    if (this.queue.length >= this.opts.batchSize && !this.inFlight && !this.retryTimer) {
      void this.sendNext();
    }
  }

  async flush(): Promise<void> {
    if (this.inFlight) await this.inFlight;
    this.cancelRetry();
    // Deliver what is queued now; stop at the first failure (the retry timer takes over).
    while (this.queue.length > 0) {
      if (!(await this.sendNext())) break;
    }
  }

  async close(): Promise<void> {
    await this.flush();
    this.closed = true;
    this.cancelRetry();
    if (this.queue.length > 0) {
      this.dropped += this.queue.length;
      logger.warn(
        { sink: this.name, count: this.queue.length, err: this.lastError },
        "audit sink closed with undelivered events",
      );
      this.queue = [];
    }
  }

  health(): SinkHealth {
    return {
      name: this.name,
      healthy: this.consecutiveFailures === 0,
      delivered: this.delivered,
      dropped: this.dropped,
      queued: this.queue.length,
      failedAttempts: this.failedAttempts,
      ...(this.lastError !== undefined ? { lastError: this.lastError } : {}),
    };
  }

  /** Send the next batch; resolves `true` on success. Failed events return to the queue front. */
  private sendNext(): Promise<boolean> {
    if (this.inFlight) return this.inFlight;
    const batch = this.queue.splice(0, this.opts.batchSize);
    if (batch.length === 0) return Promise.resolve(true);
    const task = this.post(batch).then((ok) => {
      this.inFlight = undefined;
      if (ok) {
        this.delivered += batch.length;
        this.consecutiveFailures = 0;
        if (this.queue.length >= this.opts.batchSize && !this.closed) void this.sendNext();
      } else {
        this.queue.unshift(...batch);
        this.trim();
        this.consecutiveFailures++;
        this.failedAttempts++;
        this.scheduleRetry();
      }
      return ok;
    });
    this.inFlight = task;
    return task;
  }

  private async post(events: AuditEvent[]): Promise<boolean> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.opts.timeoutMs);
    try {
      const res = await fetch(this.opts.url, {
        method: "POST",
        headers: { "content-type": "application/json", ...(this.opts.headers ?? {}) },
        body: JSON.stringify(this.body(events)),
        signal: controller.signal,
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return true;
    } catch (err) {
      const message = (err as Error)?.message ?? String(err);
      if (this.consecutiveFailures === 0) {
        logger.warn(
          { sink: this.name, count: events.length, err: message },
          "audit delivery failed; will retry",
        );
      }
      this.lastError = message;
      return false;
    } finally {
      clearTimeout(timer);
    }
  }

  /** Drop the oldest events beyond `maxQueue`. */
  private trim(): void {
    const over = this.queue.length - this.opts.maxQueue;
    if (over > 0) {
      this.queue.splice(0, over);
      this.dropped += over;
    }
  }

  private scheduleRetry(): void {
    if (this.closed || this.retryTimer) return;
    this.retryTimer = setTimeout(() => {
      this.retryTimer = undefined;
      void this.sendNext();
    }, backoffMs(this.consecutiveFailures));
    this.retryTimer.unref?.();
  }

  private cancelRetry(): void {
    if (this.retryTimer) clearTimeout(this.retryTimer);
    this.retryTimer = undefined;
  }
}
