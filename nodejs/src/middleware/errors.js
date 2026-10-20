'use strict';

const logger = require('../logger').default;

function notFound(req, res) {
  res.status(404).json({ error: 'Not Found', message: 'Route not found.' });
}

// eslint-disable-next-line no-unused-vars
function errorHandler(err, req, res, next) {
  if (res.headersSent) {
    return next(err);
  }

  const status = err.status || err.statusCode || (err.type === 'entity.too.large' ? 413 : undefined);

  if (status === 413) {
    return res.status(413).json({
      error: 'Payload Too Large',
      message: 'Request body exceeds the configured size limit.',
    });
  }

  // Log full details server-side only; never leak stack traces or
  // cryptographic details to the caller.
  logger.error('Unhandled request error', { message: err.message, stack: err.stack });
  res.status(500).json({
    error: 'Internal Server Error',
    message: 'An unexpected error occurred.',
  });
}

module.exports = { notFound, errorHandler };
