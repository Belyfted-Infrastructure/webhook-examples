'use strict';

const logger = require('../logger').default;
const { EVENT_HANDLERS, isSupportedEventType } = require('./events');
const { createIdempotencyStore } = require('../store/idempotencyStore');

/**
 * Build the webhook request handler.
 *
 * Responsibilities (after signature verification has already succeeded):
 *   1. Decode the raw body as UTF-8.
 *   2. Parse and validate the JSON payload.
 *   3. Extract the event type and identifier using the configured field names.
 *   4. Apply optional timestamp-based replay-window checking (default: off).
 *   5. Enforce idempotency keyed on the event identifier.
 *   6. Route supported events to dedicated handlers and acknowledge.
 *
 * @param {object} config Runtime configuration from src/config.js.
 */
function createWebhookHandler(config) {
  const eventTypeField = config.eventTypeField;
  const eventIdField = config.eventIdField;
  const idempotency = config.idempotency.enabled
    ? createIdempotencyStore({ ttlMs: config.idempotency.ttlMs })
    : null;
  const replay = config.replayProtection;

  function checkTimestamp(req) {
    const header = req.get(replay.timestampHeader);
    if (!header) {
      return { status: 401, body: { error: 'Unauthorized', message: `Missing "${replay.timestampHeader}" header.` } };
    }
    const timestamp = Date.parse(header);
    if (Number.isNaN(timestamp)) {
      return { status: 401, body: { error: 'Unauthorized', message: 'Invalid timestamp header.' } };
    }
    if (Math.abs(Date.now() - timestamp) > replay.toleranceMs) {
      return { status: 401, body: { error: 'Unauthorized', message: 'Event timestamp is outside the allowed tolerance window.' } };
    }
    return null;
  }

  return function webhookHandler(req, res) {
    const rawBody = req.rawBody;

    if (!Buffer.isBuffer(rawBody) || rawBody.length === 0) {
      return res.status(400).json({ error: 'Bad Request', message: 'Empty or missing request body.' });
    }

    // 1-2. Decode and parse the original bytes.
    let payload;
    try {
      payload = JSON.parse(rawBody.toString('utf8'));
    } catch {
      return res.status(400).json({ error: 'Bad Request', message: 'Malformed JSON body.' });
    }

    // 3. Validate the expected structure.
    if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
      return res.status(400).json({ error: 'Bad Request', message: 'Invalid payload: expected a JSON object.' });
    }

    const eventType = payload[eventTypeField];
    if (typeof eventType !== 'string' || eventType.trim() === '') {
      return res.status(400).json({
        error: 'Bad Request',
        message: `Invalid payload: missing or invalid "${eventTypeField}" field.`,
      });
    }

    // Optional replay-window check (NOT cryptographic replay protection).
    if (replay.enabled) {
      const replayError = checkTimestamp(req);
      if (replayError) return res.status(replayError.status).json(replayError.body);
    }

    const eventId =
      typeof payload[eventIdField] === 'string' && payload[eventIdField].trim() !== ''
        ? payload[eventIdField]
        : null;

    if (eventId === null) {
      // A missing identifier disables idempotency for this event; process it
      // anyway but surface the gap for the operator.
      logger.warn('Webhook event is missing its idempotency key', {
        eventType,
        expectedField: eventIdField,
      });
    }

    // 6. Unsupported event types are acknowledged without being processed.
    if (!isSupportedEventType(eventType)) {
      logger.info('Received unsupported webhook event type', { eventType });
      return res.status(202).json({
        received: true,
        processed: false,
        reason: 'unsupported_event_type',
        eventType,
      });
    }

    // Idempotency: skip events we have already processed.
    const idempotencyKey = eventId !== null ? `${eventType}:${eventId}` : null;
    if (idempotency && idempotencyKey) {
      if (idempotency.has(idempotencyKey)) {
        logger.info('Duplicate webhook event ignored', { eventType, eventId });
        return res.status(200).json({
          received: true,
          processed: false,
          reason: 'duplicate_event',
          eventType,
        });
      }
    }

    const event = {
      type: eventType,
      id: eventId,
      data: Object.prototype.hasOwnProperty.call(payload, 'data') ? payload.data : null,
      receivedAt: new Date().toISOString(),
    };

    // Dispatch to the dedicated handler.
    try {
      EVENT_HANDLERS[eventType](event);
    } catch (err) {
      logger.error('Webhook event handler failed', { eventType, eventId, error: err.message });
      return res.status(500).json({ error: 'Internal Server Error', message: 'Failed to process event.' });
    }

    // Mark as seen only after successful processing (at-least-once semantics:
    // the provider may safely redeliver if this acknowledgement is lost).
    if (idempotency && idempotencyKey) {
      idempotency.add(idempotencyKey);
    }

    return res.status(200).json({ received: true, processed: true, eventType });
  };
}

module.exports = { createWebhookHandler };
