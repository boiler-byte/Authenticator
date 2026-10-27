/* Authenticator data and cryptography core. No network access or storage side effects.
 * TOTP: RFC 6238 / RFC 4226; AES-GCM and PBKDF2: native Web Crypto.
 * Encrypted envelope version 1 authenticates all algorithm/KDF metadata as AAD.
 */
(() => {
  'use strict';
  const encoder = new TextEncoder();
  const decoder = new TextDecoder('utf-8', { fatal: true });
  const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const FORMAT = 'authenticator-vault';
  const ITERATIONS = 600000;
  const MAX_ACCOUNTS = 5000;
  const MAX_ENCRYPTED_BYTES = 8 * 1024 * 1024;
  const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);
  const fail = message => { throw new Error(message); };
  function webCrypto() {
    if (!globalThis.crypto?.subtle || !globalThis.crypto?.getRandomValues) {
      fail('Web Crypto ist nicht verfügbar. Öffne die App über HTTPS oder localhost in einem aktuellen Browser.');
    }
    return globalThis.crypto;
  }
  function id() {
    const c = webCrypto();
    return 'acc_' + (c.randomUUID ? c.randomUUID() : Array.from(c.getRandomValues(new Uint8Array(16)), n => n.toString(16).padStart(2, '0')).join(''));
  }
  function normalizeSecret(value) {
    if (typeof value !== 'string' || value.length > 8192) fail('Der Einrichtungsschlüssel muss ein gültiger Base32-Text sein.');
    const compact = value.replace(/[\s-]/g, '').toUpperCase();
    if (!/^[A-Z2-7]+={0,6}$/.test(compact)) fail('Der Einrichtungsschlüssel darf nur A–Z und 2–7 enthalten (Base32).');
    const unpadded = compact.replace(/=+$/, '');
    const remainder = unpadded.length % 8;
    if (![0, 2, 4, 5, 7].includes(remainder)) fail('Die Länge des Base32-Schlüssels ist ungültig.');
    const padding = compact.length - unpadded.length;
    if (padding && (compact.length % 8 !== 0 || padding !== (8 - remainder) % 8)) fail('Die Base32-Auffüllung ist ungültig.');
    const unusedBits = (unpadded.length * 5) % 8;
    if (unusedBits && (B32.indexOf(unpadded.at(-1)) & ((1 << unusedBits) - 1)) !== 0) fail('Der Base32-Schlüssel enthält ungültige Endbits.');
    return unpadded;
  }
  function base32Decode(value) {
    const secret = normalizeSecret(value);
    const result = new Uint8Array(Math.floor(secret.length * 5 / 8));
    let buffer = 0, bits = 0, offset = 0;
    for (const char of secret) {
      buffer = (buffer << 5) | B32.indexOf(char);
      bits += 5;
      if (bits >= 8) {
        bits -= 8;
        result[offset++] = (buffer >>> bits) & 255;
        buffer &= (1 << bits) - 1;
      }
    }
    return result;
  }
  function base32Encode(value) {
    const bytes = value instanceof Uint8Array ? value : new Uint8Array(value);
    let result = '', buffer = 0, bits = 0;
    for (const byte of bytes) {
      buffer = (buffer << 8) | byte;
      bits += 8;
      while (bits >= 5) {
        bits -= 5;
        result += B32[(buffer >>> bits) & 31];
        buffer &= (1 << bits) - 1;
      }
    }
    if (bits) result += B32[(buffer << (5 - bits)) & 31];
    return result;
  }
  function textField(value, label, limit, required = false) {
    if (value === undefined || value === null) value = '';
    if (typeof value !== 'string') fail(label + ' muss ein Text sein.');
    value = value.trim();
    if (required && !value) fail('Bitte ' + label + ' eingeben.');
    if (value.length > limit) fail(label + ' ist zu lang (höchstens ' + limit + ' Zeichen).');
    if (/[\u0000-\u001f\u007f]/.test(value)) fail(label + ' enthält unzulässige Steuerzeichen.');
    return value;
  }
  function integerField(value, fallback, label) {
    if (value === undefined) return fallback;
    if ((typeof value !== 'number' && typeof value !== 'string') || String(value).trim() === '') fail(label + ' ist ungültig.');
    const number = Number(value);
    if (!Number.isSafeInteger(number)) fail(label + ' muss eine ganze Zahl sein.');
    return number;
  }
  function validateAccount(raw, options = {}) {
    if (!object(raw)) fail('Ein Account hat ein ungültiges Format.');
    const type = String(raw.type ?? 'totp').toLowerCase();
    if (type !== 'totp') fail('Es werden nur zeitbasierte TOTP-Accounts unterstützt. HOTP kann nicht importiert werden.');
    const algorithm = String(raw.algorithm ?? 'SHA1').toUpperCase().replace(/-/g, '');
    if (!['SHA1', 'SHA256', 'SHA512'].includes(algorithm)) fail('Unterstützte Algorithmen: SHA1, SHA256 und SHA512.');
    const digits = integerField(raw.digits, 6, 'Die Codelänge');
    if (![6, 8].includes(digits)) fail('Die Codelänge muss 6 oder 8 Stellen betragen.');
    const period = integerField(raw.period, 30, 'Die Gültigkeitsdauer');
    if (period < 5 || period > 3600) fail('Die Gültigkeitsdauer muss zwischen 5 und 3600 Sekunden liegen.');
    const secret = normalizeSecret(raw.secret);
    const bytes = base32Decode(secret);
    if (!bytes.length || bytes.length > 256) fail('Der Einrichtungsschlüssel muss zwischen 1 und 256 Bytes lang sein.');
    bytes.fill(0);
    const accountId = (raw.id === undefined || raw.id === '') && options.generateId !== false ? id() : textField(raw.id, 'Die Account-ID', 100, true);
    return {
      id: accountId,
      issuer: textField(raw.issuer, 'Der Anbieter', 160),
      name: textField(raw.name, 'Den Account-Namen', 320, true),
      secret,
      algorithm,
      digits,
      period,
      type: 'totp',
      group: typeof raw.group === 'string' ? raw.group.trim().slice(0, 64) : ''
    };
  }
  function validateVault(raw) {
    if (!object(raw) || raw.version !== 1 || !Array.isArray(raw.accounts)) fail('Ungültiges JSON-Format. Erwartet wird { version: 1, accounts: […] }.');
    if (raw.accounts.length > MAX_ACCOUNTS) fail('Eine Datei darf höchstens ' + MAX_ACCOUNTS + ' Accounts enthalten.');
    const seen = new Set();
    const accounts = raw.accounts.map((account, index) => {
      let result;
      try { result = validateAccount(account); }
      catch (error) { throw new Error('Account ' + (index + 1) + ': ' + error.message); }
      if (seen.has(result.id)) fail('Die Datei enthält doppelte Account-IDs.');
      seen.add(result.id);
      return result;
    });
    return { version: 1, accounts };
  }
  async function totp(raw, timeMs = Date.now()) {
    const account = validateAccount(raw);
    if (!Number.isFinite(timeMs) || timeMs < 0 || !Number.isSafeInteger(Math.floor(timeMs))) fail('Die Systemzeit ist ungültig.');
    const counter = BigInt(Math.floor(timeMs / 1000 / account.period));
    const message = new Uint8Array(8);
    let value = counter;
    for (let i = 7; i >= 0; i--) { message[i] = Number(value & 255n); value >>= 8n; }
    if (value !== 0n) fail('Die Systemzeit liegt außerhalb des unterstützten Bereichs.');
    const secretBytes = base32Decode(account.secret);
    try {
      const hash = { SHA1: 'SHA-1', SHA256: 'SHA-256', SHA512: 'SHA-512' }[account.algorithm];
      const key = await webCrypto().subtle.importKey('raw', secretBytes, { name: 'HMAC', hash }, false, ['sign']);
      const mac = new Uint8Array(await webCrypto().subtle.sign('HMAC', key, message));
      const offset = mac[mac.length - 1] & 15;
      const binary = ((mac[offset] & 127) * 0x1000000) + (mac[offset + 1] << 16) + (mac[offset + 2] << 8) + mac[offset + 3];
      const result = String(binary % (10 ** account.digits)).padStart(account.digits, '0');
      mac.fill(0);
      return result;
    } finally { secretBytes.fill(0); message.fill(0); }
  }
  function toBase64(bytes) {
    let binary = '';
    for (let offset = 0; offset < bytes.length; offset += 16384) binary += String.fromCharCode(...bytes.subarray(offset, offset + 16384));
    return btoa(binary);
  }
  function fromBase64(value, label, maxBytes) {
    if (typeof value !== 'string' || value.length > Math.ceil(maxBytes / 3) * 4 || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) fail(label + ' ist kein gültiges Base64-Feld.');
    let bytes;
    try { bytes = Uint8Array.from(atob(value), char => char.charCodeAt(0)); }
    catch { fail(label + ' konnte nicht gelesen werden.'); }
    if (bytes.length > maxBytes || toBase64(bytes) !== value) fail(label + ' ist ungültig.');
    return bytes;
  }
  function validateEnvelope(raw) {
    if (!object(raw) || raw.format !== FORMAT || raw.version !== 1) fail('Diese verschlüsselte Datei hat ein unbekanntes Format oder eine nicht unterstützte Version.');
    if (!object(raw.kdf) || raw.kdf.name !== 'PBKDF2' || raw.kdf.hash !== 'SHA-256' || !Number.isInteger(raw.kdf.iterations) || raw.kdf.iterations < 100000 || raw.kdf.iterations > 1000000) fail('Die Schlüsselableitung der verschlüsselten Datei wird nicht unterstützt.');
    if (!object(raw.cipher) || raw.cipher.name !== 'AES-GCM' || raw.cipher.tagLength !== 128) fail('Die Verschlüsselungsmethode der Datei wird nicht unterstützt.');
    if (fromBase64(raw.kdf.salt, 'Das Salt', 16).length !== 16) fail('Die verschlüsselte Datei enthält ein ungültiges Salt.');
    if (fromBase64(raw.cipher.iv, 'Der Initialisierungsvektor', 12).length !== 12) fail('Die verschlüsselte Datei enthält einen ungültigen Initialisierungsvektor.');
    if (fromBase64(raw.ciphertext, 'Die verschlüsselten Daten', MAX_ENCRYPTED_BYTES).length < 16) fail('Die verschlüsselten Daten sind unvollständig.');
    return {
      format: FORMAT,
      version: 1,
      kdf: { name: 'PBKDF2', hash: 'SHA-256', iterations: raw.kdf.iterations, salt: raw.kdf.salt },
      cipher: { name: 'AES-GCM', iv: raw.cipher.iv, tagLength: 128 },
      ciphertext: raw.ciphertext
    };
  }
  function aad(envelope) {
    return encoder.encode(JSON.stringify({ format: envelope.format, version: envelope.version, kdf: envelope.kdf, cipher: envelope.cipher }));
  }
  async function deriveKey(password, kdf) {
    if (typeof password !== 'string' || password.length === 0 || password.length > 4096) fail('Bitte ein gültiges Passwort eingeben (höchstens 4096 Zeichen).');
    const passwordBytes = encoder.encode(password);
    try {
      const c = webCrypto();
      const material = await c.subtle.importKey('raw', passwordBytes, 'PBKDF2', false, ['deriveKey']);
      return await c.subtle.deriveKey({ name: 'PBKDF2', hash: 'SHA-256', iterations: kdf.iterations, salt: fromBase64(kdf.salt, 'Das Salt', 16) }, material, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
    } finally { passwordBytes.fill(0); }
  }
  async function seal(vault, key, kdf) {
    const checked = validateVault(vault);
    const c = webCrypto();
    const iv = c.getRandomValues(new Uint8Array(12));
    const envelope = {
      format: FORMAT, version: 1,
      kdf: { name: 'PBKDF2', hash: 'SHA-256', iterations: kdf.iterations, salt: kdf.salt },
      cipher: { name: 'AES-GCM', iv: toBase64(iv), tagLength: 128 },
      ciphertext: ''
    };
    const plaintext = encoder.encode(JSON.stringify(checked));
    if (plaintext.byteLength + 16 > MAX_ENCRYPTED_BYTES) fail('Der Tresor ist zu groß.');
    try {
      envelope.ciphertext = toBase64(new Uint8Array(await c.subtle.encrypt({ name: 'AES-GCM', iv, tagLength: 128, additionalData: aad(envelope) }, key, plaintext)));
      return envelope;
    } finally { plaintext.fill(0); }
  }
  async function makeEnvelope(vault, password) {
    const kdf = { name: 'PBKDF2', hash: 'SHA-256', iterations: ITERATIONS, salt: toBase64(webCrypto().getRandomValues(new Uint8Array(16))) };
    const key = await deriveKey(password, kdf);
    return { envelope: await seal(vault, key, kdf), key };
  }
  async function unlockEnvelope(raw, password) {
    const envelope = validateEnvelope(raw);
    const key = await deriveKey(password, envelope.kdf);
    let plaintext;
    try {
      plaintext = new Uint8Array(await webCrypto().subtle.decrypt({ name: 'AES-GCM', iv: fromBase64(envelope.cipher.iv, 'Der Initialisierungsvektor', 12), tagLength: 128, additionalData: aad(envelope) }, key, fromBase64(envelope.ciphertext, 'Die verschlüsselten Daten', MAX_ENCRYPTED_BYTES)));
    } catch { fail('Das Passwort ist falsch oder die verschlüsselten Daten wurden verändert.'); }
    try {
      const vault = validateVault(JSON.parse(decoder.decode(plaintext)));
      return { vault, key };
    } catch (error) {
      if (error instanceof SyntaxError || error instanceof TypeError) fail('Die entschlüsselten Daten enthalten keinen gültigen Tresor.');
      throw error;
    } finally { plaintext.fill(0); }
  }
  async function encryptWithKey(vault, key, existingEnvelope) {
    const previous = validateEnvelope(existingEnvelope);
    if (!key || key.type !== 'secret' || key.algorithm?.name !== 'AES-GCM' || key.algorithm?.length !== 256) fail('Der Tresor ist gesperrt. Bitte erneut entsperren.');
    return seal(vault, key, previous.kdf);
  }
  globalThis.AuthCore = Object.freeze({ FORMAT, ITERATIONS, MAX_ACCOUNTS, normalizeSecret, base32Decode, base32Encode, id, validateAccount, validateVault, totp, validateEnvelope, makeEnvelope, unlockEnvelope, encryptWithKey });
})();
