/**
 * Small, dependency-free async primitives shared across layers.
 *
 * @packageDocumentation
 */

/**
 * Reject with an error carrying `message` if `promise` does not settle within
 * `timeoutMs`. The timer is always cleared so it never keeps the event loop alive.
 *
 * @param promise   The promise to race against the timeout.
 * @param timeoutMs Maximum time to wait, in milliseconds.
 * @param message   Message for the timeout error.
 * @returns The resolved value of `promise` if it settles in time.
 * @throws Error if the timeout elapses first.
 */
export function withTimeout<T>(
  promise: Promise<T>,
  timeoutMs: number,
  message = "timeout",
): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(message)), timeoutMs);
    promise.then(
      (value) => {
        clearTimeout(timer);
        resolve(value);
      },
      (err) => {
        clearTimeout(timer);
        reject(err);
      },
    );
  });
}
