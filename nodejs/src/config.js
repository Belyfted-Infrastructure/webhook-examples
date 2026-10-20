'use strict';

const path = require('node:path');
const fs = require('node:fs');
const crypto = require('node:crypto');

require('dotenv').config();

const DEFAULT_PORT = 3000;
const DEFAULT_PUBLIC_KEY_PATH = path.join(__dirname, '..', 'keys', 'public.pem');

/**
 * Parse a TCP port from a string or number. Returns the fallback when the
 * value is undefined/empty, and throws a descriptive error otherwise.
 */
function parsePort(value, fallback = DEFAULT_PORT) {
  if (value === undefined || value === null || String(value).trim() === '') {
    return fallback;
  }
  const port = Number.parseInt(String(value), 10);
  if (!Number.isInteger(port) || String(port) !== String(value).trim() || port < 0 || port > 65535) {
    throw new Error(`Invalid PORT "${value}". Expected an integer between 0 and 65535.`);
  }
  return port;
}

function parsePositiveInt(value, name, fallback) {
  if (value === undefined || value === null || String(value).trim() === '') {
    return fallback;
  }
  const parsed = Number.parseInt(String(value), 10);
  if (!Number.isInteger(parsed) || parsed <= 0) {
    throw new Error(`Invalid ${name} "${value}". Expected a positive integer.`);
  }
  return parsed;
}

function parseBoolean(value, name, fallback) {
  if (value === undefined || value === null || String(value).trim() === '') {
    return fallback;
  }
  if (/^(true|1|yes|on)$/i.test(String(value).trim())) return true;
  if (/^(false|0|no|off)$/i.test(String(value).trim())) return false;
  throw new Error(`Invalid boolean for ${name}: "${value}". Expected true/false.`);
}

/**
 * Load and validate an RSA public key (PEM) from disk.
 *
 * The receiving server must only ever hold the *public* verification key. The
 * sender's private key must never be present on this machine.
 *
 * @param {string} publicKeyPath Absolute path to the PEM file.
 * @returns {crypto.KeyObject} Parsed RSA public key.
 */
function loadPublicKey(publicKeyPath) {
  let pem;
  try {
    pem = fs.readFileSync(publicKeyPath, 'utf8');
  } catch (err) {
    throw new Error(
      `Unable to read the webhook public key at "${publicKeyPath}". ` +
      `Place the provider's RSA public key (PEM) at that path or set WEBHOOK_PUBLIC_KEY_PATH. ` +
      `Details: ${err.message}`
    );
  }

  let key;
  try {
    key = crypto.createPublicKey(pem);
  } catch (err) {
    throw new Error(`The webhook public key at "${publicKeyPath}" is not a valid PEM key. Details: ${err.message}`);
  }

  if (!key || key.type !== 'public' || key.asymmetricKeyType !== 'rsa') {
    throw new Error(
      `The webhook public key at "${publicKeyPath}" must be an RSA public key, ` +
      `but found type "${key ? key.asymmetricKeyType : 'unknown'}".`
    );
  }

  return key;
}

/**
 * Build a validated runtime configuration object from environment variables.
 * Throws with a useful message when a required value or the public key is
 * missing/invalid so the process fails fast at startup.
 *
 * @param {NodeJS.ProcessEnv} [env]
 * @returns {object}
 */
function loadConfig(env = process.env) {
  const publicKeyPath = path.resolve(env.WEBHOOK_PUBLIC_KEY_PATH || DEFAULT_PUBLIC_KEY_PATH);

  return {
    port: parsePort(env.PORT),
    nodeEnv: env.NODE_ENV || 'development',
    publicKeyPath,
    publicKey: loadPublicKey(publicKeyPath),
    signatureHeader: env.WEBHOOK_SIGNATURE_HEADER || 'DigitalSignature',
    maxBodySize: env.WEBHOOK_MAX_BODY_SIZE || '100kb',
    // Event schema field names. These MUST be confirmed against Belyfted's
    // documented webhook payload schema and are configurable to avoid
    // hardcoding an invented schema.
    eventTypeField: env.WEBHOOK_EVENT_TYPE_FIELD || 'type',
    eventIdField: env.WEBHOOK_EVENT_ID_FIELD || 'id',
    logLevel: env.LOG_LEVEL || 'info',
    trustProxy: parseBoolean(env.TRUST_PROXY, 'TRUST_PROXY', false),
    idempotency: {
      enabled: parseBoolean(env.WEBHOOK_IDEMPOTENCY_ENABLED, 'WEBHOOK_IDEMPOTENCY_ENABLED', true),
      ttlMs: parsePositiveInt(env.WEBHOOK_IDEMPOTENCY_TTL_MS, 'WEBHOOK_IDEMPOTENCY_TTL_MS', 86400000),
    },
    // Body-only signatures do NOT provide replay protection. This optional
    // timestamp check only bounds the replay window and must only be enabled
    // once the provider confirms it emits a trustworthy signed timestamp.
    replayProtection: {
      enabled: parseBoolean(env.WEBHOOK_REPLAY_PROTECTION_ENABLED, 'WEBHOOK_REPLAY_PROTECTION_ENABLED', false),
      timestampHeader: env.WEBHOOK_TIMESTAMP_HEADER || 'X-Belyfted-Timestamp',
      toleranceMs: parsePositiveInt(env.WEBHOOK_TIMESTAMP_TOLERANCE_MS, 'WEBHOOK_TIMESTAMP_TOLERANCE_MS', 300000),
    },
  };
}

module.exports = { loadConfig, loadPublicKey };
