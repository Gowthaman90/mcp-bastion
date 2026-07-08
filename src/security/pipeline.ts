/**
 * A minimal, allocation-light interceptor pipeline.
 *
 * Each interceptor receives the call context and a `next` continuation. Returning
 * `next()` passes control down the chain; returning a result directly
 * short-circuits it. The final handler performs the actual upstream tool call.
 *
 * This is the extensibility backbone for the security checks in v0.2 and the
 * audit sink in v0.3 — new concerns are added as interceptors, not by editing the
 * routing code.
 *
 * @packageDocumentation
 */
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";

import type { Interceptor, NextFn, ToolCallContext } from "./types.js";

/**
 * Run `ctx` through `interceptors` in order, finishing with `final`.
 *
 * @param interceptors Ordered middleware to apply.
 * @param ctx          The tool-call context.
 * @param final        The terminal handler (the real upstream call).
 * @throws Error if an interceptor invokes `next()` more than once.
 */
export function runPipeline(
  interceptors: readonly Interceptor[],
  ctx: ToolCallContext,
  final: NextFn,
): Promise<CallToolResult> {
  let lastCalled = -1;

  const dispatch = (index: number): Promise<CallToolResult> => {
    if (index <= lastCalled) {
      return Promise.reject(new Error("next() called multiple times in a single interceptor"));
    }
    lastCalled = index;
    const interceptor = interceptors[index];
    if (!interceptor) return final();
    return interceptor(ctx, () => dispatch(index + 1));
  };

  return dispatch(0);
}
