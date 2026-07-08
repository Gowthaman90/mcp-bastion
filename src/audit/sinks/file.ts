/**
 * A sink that appends audit events as JSON lines (JSONL) to a file.
 *
 * Writes go through a Node write stream (buffered, non-blocking). `close` ends the
 * stream and waits for the OS flush, which is the durability point relied on by
 * tests and graceful shutdown.
 *
 * @packageDocumentation
 */
import { createWriteStream, type WriteStream } from "node:fs";

import type { AuditEvent, AuditSink } from "../types.js";

export class FileSink implements AuditSink {
  readonly name: string;
  private readonly stream: WriteStream;

  constructor(path: string) {
    this.name = `file:${path}`;
    this.stream = createWriteStream(path, { flags: "a" });
  }

  write(event: AuditEvent): void {
    this.stream.write(`${JSON.stringify(event)}\n`);
  }

  async flush(): Promise<void> {
    // Best-effort: yield until the stream's internal buffer has drained.
    if (this.stream.writableLength === 0) return;
    await new Promise<void>((resolve) => this.stream.once("drain", resolve));
  }

  async close(): Promise<void> {
    await new Promise<void>((resolve, reject) => {
      this.stream.end((err?: Error | null) => (err ? reject(err) : resolve()));
    });
  }
}
