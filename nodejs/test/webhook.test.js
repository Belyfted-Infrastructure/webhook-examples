'use strict';

// Silence logs during test runs. Must be set before any module that creates
// the shared logger instance is required.
process.env.LOG_LEVEL = 'error';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const { createApp } = require('../src/app');
const { loadPublicKey } = require('../src/config');

// Separate test key pairs generated programmatically; no production or
// committed private keys are used.
const mainKeys = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
const wrongKeys = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });

function sign(privateKey, body) {
  return crypto
    .sign('RSA-SHA256', body, { key: privateKey, padding: crypto.constants.RSA_PKCS1_PADDING })
    .toString('base64');
}

function makeConfig(publicKey, overrides = {}) {
  return {
    port: 0,
    nodeEnv: 'test',
    publicKey,
    publicKeyPath: '<test>',
    signatureHeader: 'DigitalSignature',
    maxBodySize: '10kb',
    eventTypeField: 'type',
    eventIdField: 'id',
    logLevel: 'error',
    trustProxy: false,
    idempotency: { enabled: true, ttlMs: 60000 },
    replayProtection: { enabled: false, timestampHeader: 'X-Belyfted-Timestamp', toleranceMs: 300000 },
    ...overrides,
  };
}

async function startServer(config) {
  const app = createApp({ config });
  const server = app.listen(0);
  await new Promise((resolve, reject) => {
    server.once('listening', resolve);
    server.once('error', reject);
  });
  const address = server.address();
  return { server, baseUrl: `http://127.0.0.1:${address.port}` };
}

function closeServer(server) {
  return new Promise((resolve, reject) => {
    server.close((err) => (err ? reject(err) : resolve()));
  });
}

async function post(baseUrl, body, headers = {}) {
  return fetch(`${baseUrl}/webhooks/belyfted`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...headers },
    body,
  });
}

test('1. accepts a valid signature and valid JSON payload', async () => {
  const { server, baseUrl } = await startServer(makeConfig(mainKeys.publicKey));
  try {
    const body = JSON.stringify({
      id: 'evt_1',
      type: 'payment-created',
      createdAt: new Date().toISOString(),
      data: { amount: 100 },
    });
    const signature = sign(mainKeys.privateKey, Buffer.from(body, 'utf8'));
    const res = await post(baseUrl, body, { DigitalSignature: signature });

    assert.equal(res.status, 200);
    assert.deepEqual(await res.json(), { received: true, processed: true, eventType: 'payment-created' });
  } finally {
    await closeServer(server);
  }
});

test('2. rejects a missing DigitalSignature header', async () => {
  const { server, baseUrl } = await startServer(makeConfig(mainKeys.publicKey));
  try {
    const body = JSON.stringify({ id: 'evt_1', type: 'payment-created' });
    const res = await post(baseUrl, body);
    assert.equal(res.status, 401);
  } finally {
    await closeServer(server);
  }
});

test('3. rejects an invalid Base64 signature', async () => {
  const { server, baseUrl } = await startServer(makeConfig(mainKeys.publicKey));
  try {
    const body = JSON.stringify({ id: 'evt_1', type: 'payment-created' });
    const res = await post(baseUrl, body, { DigitalSignature: 'not-a-base64!!' });
    assert.equal(res.status, 401);
  } finally {
    await closeServer(server);
  }
});

test('4. rejects a signature generated with the wrong private key', async () => {
  const { server, baseUrl } = await startServer(makeConfig(mainKeys.publicKey));
  try {
    const body = JSON.stringify({ id: 'evt_1', type: 'payment-created' });
    const signature = sign(wrongKeys.privateKey, Buffer.from(body, 'utf8'));
    const res = await post(baseUrl, body, { DigitalSignature: signature });
    assert.equal(res.status, 401);
  } finally {
    await closeServer(server);
  }
});

test('5. rejects a body modified after signing (even one byte)', async () => {
  const { server, baseUrl } = await startServer(makeConfig(mainKeys.publicKey));
  try {
    const original = '{"value":123}';
    const signature = sign(mainKeys.privateKey, Buffer.from(original, 'utf8'));
    // Exactly one byte differs: 123 -> 124.
    const tampered = '{"value":124}';
    assert.equal(original.length, tampered.length);
    const res = await post(baseUrl, tampered, { DigitalSignature: signature });
    assert.equal(res.status, 401);
  } finally {
    await closeServer(server);
  }
});

test('6. rejects malformed JSON even with a valid signature', async () => {
  const { server, baseUrl } = await startServer(makeConfig(mainKeys.publicKey));
  try {
    const body = '{not valid json';
    const signature = sign(mainKeys.privateKey, Buffer.from(body, 'utf8'));
    const res = await post(baseUrl, body, { DigitalSignature: signature });
    assert.equal(res.status, 400);
  } finally {
    await closeServer(server);
  }
});

test('7. rejects an empty request body', async () => {
  const { server, baseUrl } = await startServer(makeConfig(mainKeys.publicKey));
  try {
    const signature = sign(mainKeys.privateKey, Buffer.alloc(0));
    const res = await post(baseUrl, '', { DigitalSignature: signature });
    assert.equal(res.status, 400);
  } finally {
    await closeServer(server);
  }
});

test('8. rejects an oversized payload', async () => {
  const { server, baseUrl } = await startServer(makeConfig(mainKeys.publicKey));
  try {
    const body = JSON.stringify({
      id: 'evt_big',
      type: 'payment-created',
      data: { blob: 'x'.repeat(20 * 1024) },
    });
    const signature = sign(mainKeys.privateKey, Buffer.from(body, 'utf8'));
    const res = await post(baseUrl, body, { DigitalSignature: signature });
    assert.equal(res.status, 413);
  } finally {
    await closeServer(server);
  }
});

test('9. rejects unsupported content types', async () => {
  const { server, baseUrl } = await startServer(makeConfig(mainKeys.publicKey));
  try {
    const body = JSON.stringify({ id: 'evt_1', type: 'payment-created' });
    const signature = sign(mainKeys.privateKey, Buffer.from(body, 'utf8'));
    const res = await fetch(`${baseUrl}/webhooks/belyfted`, {
      method: 'POST',
      headers: { 'Content-Type': 'text/plain', DigitalSignature: signature },
      body,
    });
    assert.equal(res.status, 415);
  } finally {
    await closeServer(server);
  }
});

test('10. detects duplicate webhook event delivery', async () => {
  const { server, baseUrl } = await startServer(makeConfig(mainKeys.publicKey));
  try {
    const body = JSON.stringify({ id: 'evt_dup', type: 'payment-created' });
    const signature = sign(mainKeys.privateKey, Buffer.from(body, 'utf8'));

    const first = await post(baseUrl, body, { DigitalSignature: signature });
    assert.equal(first.status, 200);
    assert.deepEqual(await first.json(), { received: true, processed: true, eventType: 'payment-created' });

    const second = await post(baseUrl, body, { DigitalSignature: signature });
    assert.equal(second.status, 200);
    assert.deepEqual(await second.json(), {
      received: true,
      processed: false,
      reason: 'duplicate_event',
      eventType: 'payment-created',
    });
  } finally {
    await closeServer(server);
  }
});

test('11. acknowledges unsupported event types without processing them', async () => {
  const { server, baseUrl } = await startServer(makeConfig(mainKeys.publicKey));
  try {
    const body = JSON.stringify({ id: 'evt_2', type: 'refund-created' });
    const signature = sign(mainKeys.privateKey, Buffer.from(body, 'utf8'));
    const res = await post(baseUrl, body, { DigitalSignature: signature });
    assert.equal(res.status, 202);
    assert.deepEqual(await res.json(), {
      received: true,
      processed: false,
      reason: 'unsupported_event_type',
      eventType: 'refund-created',
    });
  } finally {
    await closeServer(server);
  }
});

test('12. fails fast on public-key loading failures', async () => {
  // Missing file.
  assert.throws(
    () => loadPublicKey(path.join(__dirname, 'does-not-exist.pem')),
    /Unable to read the webhook public key/
  );

  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'belyfted-keys-'));

  // Invalid PEM.
  const badPem = path.join(tmp, 'bad.pem');
  fs.writeFileSync(badPem, 'not a pem file');
  assert.throws(() => loadPublicKey(badPem), /not a valid PEM key/);

  // Valid key but the wrong algorithm (EC instead of RSA).
  const ecPem = path.join(tmp, 'ec.pem');
  const { publicKey: ecPublic } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  fs.writeFileSync(ecPem, ecPublic.export({ type: 'spki', format: 'pem' }));
  assert.throws(() => loadPublicKey(ecPem), /must be an RSA public key/);

  fs.rmSync(tmp, { recursive: true, force: true });
});
