'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { createCsrDer, verifyCsrDer, pemEncode } = require('../scripts/lib/pkcs10');

test('builds a self-verifying PKCS#10 CSR with a PKCS#8 private key', () => {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });

  const csrDer = createCsrDer({
    privateKey,
    publicKey,
    subject: {
      countryName: 'NG',
      stateOrProvinceName: 'FCT',
      localityName: 'Abuja',
      organizationName: 'Test Org',
      commonName: 'example.test',
      emailAddress: 'test@example.com',
    },
  });

  assert.ok(Buffer.isBuffer(csrDer));
  assert.equal(verifyCsrDer(csrDer), true);

  const pem = pemEncode(csrDer, 'CERTIFICATE REQUEST');
  assert.match(pem, /-----BEGIN CERTIFICATE REQUEST-----/);
  assert.match(pem, /-----END CERTIFICATE REQUEST-----/);
});

test('rejects a tampered CSR', () => {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const csrDer = createCsrDer({ privateKey, publicKey, subject: { commonName: 'example.test' } });

  const tampered = Buffer.from(csrDer);
  tampered[tampered.length - 1] ^= 0xff; // flip one byte of the signature

  assert.throws(() => verifyCsrDer(tampered), /signature verification failed|trailing data/);
});
