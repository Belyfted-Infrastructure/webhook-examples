'use strict';

const logger = require('../logger').default;

/**
 * Event routing registry.
 *
 * IMPORTANT: The event type strings below are PLACEHOLDERS pending
 * confirmation against Belyfted's official webhook documentation. They are not
 * authoritative and must be updated to the provider's actual event names
 * before production use. The webhook handler only routes an event when its
 * type is present in this registry; unknown types receive a distinct
 * "unsupported_event_type" acknowledgement and are never treated as processed.
 */

function logSafe(event) {
  // Log only non-sensitive metadata. Never log the full payload, which may
  // contain PII or credentials.
  logger.info(`Webhook event handled: ${event.type}`, {
    eventType: event.type,
    eventId: event.id,
    receivedAt: event.receivedAt,
  });
}

function handlePaymentCreated(event) {
  logSafe(event);
  // TODO: implement provider-specific business logic here (e.g. persist
  // payment, trigger downstream workflows) using event.data.
}

function handleTransactionCreated(event) {
  logSafe(event);
  // TODO: implement provider-specific business logic here.
}

function handleAccountCreated(event) {
  logSafe(event);
  // TODO: implement provider-specific business logic here.
}

/**
 * Map of supported event type -> handler function. Update keys to match the
 * provider's documented event names.
 */
const EVENT_HANDLERS = Object.freeze({
  'payment-created': handlePaymentCreated,
  'transaction-created': handleTransactionCreated,
  'account-created': handleAccountCreated,
});

const SUPPORTED_EVENT_TYPES = Object.freeze(Object.keys(EVENT_HANDLERS));

function isSupportedEventType(eventType) {
  return Object.prototype.hasOwnProperty.call(EVENT_HANDLERS, eventType);
}

module.exports = { EVENT_HANDLERS, SUPPORTED_EVENT_TYPES, isSupportedEventType };
