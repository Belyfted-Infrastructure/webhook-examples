'use strict';

const LEVELS = Object.freeze({ error: 0, warn: 1, info: 2, debug: 3 });

function stringify(value) {
  if (typeof value === 'string') return value;
  if (value instanceof Error) return value.message;
  try {
    return JSON.stringify(value);
  } catch {
    return String(value);
  }
}

/**
 * Minimal structured (JSON-lines) logger with configurable severity.
 * It is intentionally dependency-free so logging never leaks to callers.
 */
function createLogger(level = 'info') {
  const threshold = Object.prototype.hasOwnProperty.call(LEVELS, level) ? LEVELS[level] : LEVELS.info;

  function write(levelName, message, meta) {
    if (LEVELS[levelName] > threshold) return;
    const record = {
      level: levelName,
      time: new Date().toISOString(),
      message: stringify(message),
    };
    if (meta !== undefined && meta !== null) {
      record.meta = typeof meta === 'object' ? meta : { value: stringify(meta) };
    }
    const line = JSON.stringify(record);
    if (levelName === 'error' || levelName === 'warn') {
      process.stderr.write(line + '\n');
    } else {
      process.stdout.write(line + '\n');
    }
  }

  return {
    error: (message, meta) => write('error', message, meta),
    warn: (message, meta) => write('warn', message, meta),
    info: (message, meta) => write('info', message, meta),
    debug: (message, meta) => write('debug', message, meta),
  };
}

// Shared default logger. Tests and callers that need a different level can
// build their own instance with createLogger().
module.exports = { createLogger, LEVELS, default: createLogger(process.env.LOG_LEVEL || 'info') };
