'use strict';

const express = require('express');
const { loadConfig } = require('./config');
const logger = require('./logger').default;
const { createVerifySignature } = require('./middleware/verifySignature');
const { createWebhookHandler } = require('./handlers/webhookHandler');
const { notFound, errorHandler } = require('./middleware/errors');

/**
 * Build the Express application.
 *
 * The webhook route is registered BEFORE the global `express.json()` parser so
 * that `express.raw()` receives the exact request body bytes and nothing
 * earlier consumes or transforms the body. Ordinary API routes registered
 * afterward can still parse JSON normally.
 *
 * @param {object} [options]
 * @param {object} [options.config] Runtime config (defaults to loadConfig()).
 * @param {Function} [options.verifySignature] Signature middleware override.
 * @param {Function} [options.webhookHandler] Webhook handler override.
 * @returns {import('express').Express}
 */
function createApp(options = {}) {
  const config = options.config || loadConfig();

  const verifySignature =
    options.verifySignature ||
    createVerifySignature({
      publicKey: config.publicKey,
      signatureHeader: config.signatureHeader,
    });

  const webhookHandler = options.webhookHandler || createWebhookHandler(config);

  const app = express();

  app.disable('x-powered-by');
  if (config.trustProxy) {
    // Trust the first proxy hop (ngrok, nginx, ALB, ...) so HTTPS/TLS is
    // reflected correctly. Terminate TLS at the proxy in production.
    app.set('trust proxy', true);
  }

  app.get('/health', (req, res) => {
    res.status(200).json({ status: 'ok', uptime: process.uptime() });
  });

  // Log every inbound webhook request (before signature verification so even
  // unauthorized/malformed deliveries are observable).
  function logIncomingWebhook(req, res, next) {
    const rawBody = Buffer.isBuffer(req.body) ? req.body.toString('utf8') : undefined;
    logger.info('Incoming webhook request', {
      method: req.method,
      url: req.originalUrl,
      contentType: req.get('Content-Type'),
      contentLength: req.get('Content-Length'),
      signaturePresent: Boolean(req.get(config.signatureHeader)),
      body: rawBody,
    });
    next();
  }

  // Signature-verified webhook endpoint. `express.raw` yields a Buffer.
  app.post(
    '/webhooks/belyfted',
    express.raw({ type: 'application/json', limit: config.maxBodySize }),
    logIncomingWebhook,
    verifySignature,
    webhookHandler
  );

  // JSON parsing for ordinary (non-webhook) API routes.
  app.use(express.json({ limit: config.maxBodySize }));

  app.use(notFound);
  app.use(errorHandler);

  return app;
}

module.exports = { createApp };
