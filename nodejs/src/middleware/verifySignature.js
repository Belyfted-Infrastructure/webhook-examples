'use strict';

const crypto = require('node:crypto');

/**
 * Strict Base64 validation. Buffer.from(..., 'base64') silently ignores
 * invalid characters, so we round-trip and compare to reject malformed input.
 */
function isStrictBase64(value) {
  if (typeof value !== 'string') return false;
  const trimmed = value.trim();
  if (trimmed.length === 0) return false;
  if (trimmed.length % 4 === 1) return false;
  return Buffer.from(trimmed, 'base64').toString('base64') === trimmed;
}

/**
 * Build Express middleware that verifies the `DigitalSignature` header against
 * the raw request body bytes using RSA-SHA256 and PKCS#1 v1.5 padding.
 *
 * The body MUST be provided as a Buffer by `express.raw()` upstream. This
 * middleware never parses or re-serializes JSON: it verifies the exact bytes
 * that arrived on the wire.
 *
 * @param {object} deps
 * @param {crypto.KeyObject} deps.publicKey Parsed RSA public key.
 * @param {string} [deps.signatureHeader]
 * @returns {import('express').RequestHandler}
 */
function createVerifySignature({ publicKey, signatureHeader = 'DigitalSignature' }) {
  if (!publicKey) {
    throw new Error('createVerifySignature requires a publicKey.');
  }

  return function verifySignature(req, res, next) {
    // Only application/json bodies are supported for this endpoint.
    if (!req.is('application/json')) {
      return res.status(415).json({
        error: 'Unsupported Media Type',
        message: 'Expected Content-Type: application/json',
      });
    }

    const rawBody = req.body;
    if (!Buffer.isBuffer(rawBody)) {
      return res.status(400).json({
        error: 'Bad Request',
        message: 'Raw request body is unavailable for signature verification.',
      });
    }

    const signatureValue = req.get(signatureHeader);
    if (!signatureValue) {
      return res.status(401).json({
        error: 'Unauthorized',
        message: `Missing "${signatureHeader}" header.`,
      });
    }

    if (!isStrictBase64(signatureValue)) {
      return res.status(401).json({
        error: 'Unauthorized',
        message: 'Malformed digital signature.',
      });
    }

    const signatureBuffer = Buffer.from(signatureValue.trim(), 'base64');

    let valid;
    try {
      valid = crypto.verify(
        'RSA-SHA256',
        rawBody,
        { key: publicKey, padding: crypto.constants.RSA_PKCS1_PADDING },
        signatureBuffer
      );
    } catch {
      valid = false;
    }

    if (!valid) {
      return res.status(401).json({
        error: 'Unauthorized',
        message: 'Invalid digital signature.',
      });
    }

    // Preserve the exact raw bytes for downstream JSON parsing.
    req.rawBody = rawBody;
    next();
  };
}

module.exports = { createVerifySignature, isStrictBase64 };
