'use strict';

const { loadConfig } = require('./config');
const { createApp } = require('./app');
const logger = require('./logger').default;

function start() {
  let config;
  try {
    config = loadConfig();
  } catch (err) {
    // Fail fast with a useful message; never start with a missing/invalid key
    // or misconfigured environment.
    process.stderr.write(`Startup configuration error: ${err.message}\n`);
    process.exit(1);
  }

  const app = createApp({ config });
  const server = app.listen(config.port, () => {
    logger.info('Server listening', { port: config.port, nodeEnv: config.nodeEnv });
  });

  server.on('error', (err) => {
    logger.error('Server failed to start', { message: err.message });
    process.exit(1);
  });

  let shuttingDown = false;
  function shutdown(signal) {
    if (shuttingDown) return;
    shuttingDown = true;
    logger.info('Shutting down', { signal });

    server.close((err) => {
      if (err) {
        logger.error('Error during graceful shutdown', { message: err.message });
        process.exit(1);
      }
      logger.info('Shutdown complete');
      process.exit(0);
    });

    // Force-exit if connections do not drain in time.
    const forceTimer = setTimeout(() => {
      logger.error('Forced shutdown after timeout');
      process.exit(1);
    }, 10000);
    if (typeof forceTimer.unref === 'function') forceTimer.unref();
  }

  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));
}

if (require.main === module) {
  start();
}

module.exports = { start };
