'use strict';

/**
 * In-memory, TTL-based idempotency store.
 *
 * This is suitable for a single process or low-volume workloads. For multiple
 * replicas or durable exactly-once semantics, replace this with a shared store
 * such as Redis (`SET key value NX EX ttl`) or a database unique constraint
 * keyed on the event identifier.
 */
function createIdempotencyStore({ ttlMs = 86400000 } = {}) {
  const entries = new Map(); // key -> { expiresAt }

  function sweep() {
    const now = Date.now();
    for (const [key, entry] of entries) {
      if (entry.expiresAt <= now) entries.delete(key);
    }
  }

  // Sweep periodically; unref() so the timer never keeps the process alive
  // during graceful shutdown or tests.
  const intervalMs = Math.max(1000, Math.min(ttlMs, 60000));
  const timer = setInterval(sweep, intervalMs);
  if (typeof timer.unref === 'function') timer.unref();

  function has(key) {
    const entry = entries.get(key);
    if (!entry) return false;
    if (entry.expiresAt <= Date.now()) {
      entries.delete(key);
      return false;
    }
    return true;
  }

  function add(key, ttl = ttlMs) {
    entries.set(key, { expiresAt: Date.now() + ttl });
  }

  function stop() {
    clearInterval(timer);
    entries.clear();
  }

  return { has, add, stop, get size() { return entries.size; } };
}

module.exports = { createIdempotencyStore };
