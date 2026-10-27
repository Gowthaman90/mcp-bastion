/**
 * A sink that appends audit events as JSON lines (JSONL) to a file.
 *
 * Writes go through a Node write stream (buffered, non-blocking). `close` ends the
 * stream and waits for the OS flush, which is the durability point relied on by
 * tests and graceful shutdown.
 *
 * Failure handling: the file is opened synchronously at construction, so a bad path
 * fails at startup with a clear error rather than crashing the process later. A
 * write error at runtime (e.g. a full disk) is logged once and the sink stops
 * writing: later events are counted in {@link FileSink.dropped}, never thrown.
 * A new file is created readable and writable by its owner only (`0600`); an
 * existing file keeps its permissions.
 *
 * @packageDocumentation
 */
import { closeSync, createWriteStream, openSync, type WriteStream } from "node:fs";

import { logger } from "../../observability/index.js";
import type { AuditRecord, AuditSink, SinkHealth } from "../types.js";

/** Owner read/write only: audit records can carry sensitive metadata. */
const FILE_MODE = 0o600;

export class FileSink implements AuditSink {
  readonly name: string;
  private readonly stream: WriteStream;
  private failure: string | undefined;
  private droppedCount = 0;
  private written = 0;

  /**
   * @param path File to append to. Its directory must exist and be writable.
   * @throws Error if the file cannot be opened for appending.
   */
  constructor(path: string) {
    this.name = `file:${path}`;
    let fd: number;
    try {
      fd = openSync(path, "a", FILE_MODE);
    } catch (err) {
      throw new Error(
        `audit file sink cannot open "${path}": ${(err as Error)?.message ?? String(err)}`,
        { cause: err },
      );
    }
    closeSync(fd);
    this.stream = createWriteStream(path, { flags: "a", mode: FILE_MODE });
    this.stream.on("error", (err) => {
      if (this.failure !== undefined) return;
      this.failure = err?.message ?? String(err);
      logger.error(
        { sink: this.name, err: this.failure },
        "audit file sink failed: later events to this sink are dropped",
      );
    });
  }

  /** The write error that stopped this sink, if any. */
  get lastError(): string | undefined {
    return this.failure;
  }

  /** Events not written because the sink had failed. */
  get dropped(): number {
    return this.droppedCount;
  }

  write(event: AuditRecord): void {
    if (this.failure !== undefined || this.stream.destroyed) {
      this.droppedCount++;
      return;
    }
    this.stream.write(`${JSON.stringify(event)}\n`);
    this.written++;
  }

  health(): SinkHealth {
    return {
      name: this.name,
      healthy: this.failure === undefined && !this.stream.destroyed,
      delivered: this.written,
      dropped: this.droppedCount,
      queued: 0,
      failedAttempts: this.failure === undefined ? 0 : 1,
      ...(this.failure !== undefined ? { lastError: this.failure } : {}),
    };
  }

  async flush(): Promise<void> {
    // Best-effort: yield until the stream's internal buffer has drained, or it fails.
    if (this.stream.destroyed || this.stream.writableLength === 0) return;
    await new Promise<void>((resolve) => {
      const done = () => {
        this.stream.off("drain", done);
        this.stream.off("close", done);
        resolve();
      };
      this.stream.once("drain", done);
      this.stream.once("close", done);
    });
  }

  async close(): Promise<void> {
    if (this.stream.destroyed) return;
    await new Promise<void>((resolve, reject) => {
      this.stream.end((err?: Error | null) => (err ? reject(err) : resolve()));
    });
  }
}
