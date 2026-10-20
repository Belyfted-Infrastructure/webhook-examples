'use strict';

/**
 * Generate a LOCAL DEVELOPMENT RSA key pair and a PKCS#10 CSR.
 *
 * Formats:
 *   - private key: PKCS#8 (PEM)  -> keys/dev-private.pem  (DO NOT COMMIT)
 *   - public key:  SPKI (PEM)    -> keys/public.pem       (verification key)
 *   - CSR:         PKCS#10 (PEM) -> keys/dev.csr
 *
 * This is only for running the server and the example signing script locally.
 * For production you must place the real provider PUBLIC key at keys/public.pem
 * and must NEVER store its private key on this machine.
 *
 * Usage: node scripts/generate-dev-keys.js [--force]
 */

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { createCsrDer, verifyCsrDer, pemEncode } = require('./lib/pkcs10');

const keysDir = path.join(__dirname, '..', 'keys');
const publicPath = path.join(keysDir, 'public.pem');
const privatePath = path.join(keysDir, 'dev-private.pem');
const csrPath = path.join(keysDir, 'dev.csr');

const force = process.argv.includes('--force');

fs.mkdirSync(keysDir, { recursive: true });

const haveKeys = fs.existsSync(publicPath) && fs.existsSync(privatePath);

if (!force && haveKeys) {
  console.log('Development keys already exist; generating the PKCS#10 CSR from the existing private key.');
} else {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  // Public key as SPKI; private key as PKCS#8 (as requested).
  fs.writeFileSync(publicPath, publicKey.export({ type: 'spki', format: 'pem' }));
  fs.writeFileSync(privatePath, privateKey.export({ type: 'pkcs8', format: 'pem' }));
  try {
    fs.chmodSync(privatePath, 0o600); // no-op on Windows, enforced on POSIX
  } catch {
    /* best effort only */
  }
  console.log('Generated local development keys (private key in PKCS#8 format):');
}

// Build and self-verify a PKCS#10 CSR from the current key pair.
const privateKey = crypto.createPrivateKey(fs.readFileSync(privatePath, 'utf8'));
const publicKey = crypto.createPublicKey(privateKey);

const subject = {
  countryName: 'NG',
  stateOrProvinceName: 'FCT',
  localityName: 'Abuja',
  organizationName: 'Acme Development',
  commonName: 'localhost',
  emailAddress: 'jalleto4rel@gmail.com',
};

const csrDer = createCsrDer({ privateKey, publicKey, subject });
verifyCsrDer(csrDer); // throws if the CSR is malformed or the signature is wrong
fs.writeFileSync(csrPath, pemEncode(csrDer, 'CERTIFICATE REQUEST'));

console.log('  public :', publicPath);
console.log('  private:', privatePath, '(PKCS#8, DO NOT COMMIT)');
console.log('  csr    :', csrPath, '(PKCS#10, self-signature verified)');
