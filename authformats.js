/* Authenticator URI and Google migration import.
 * otpauth: https://github.com/google/google-authenticator/wiki/Key-Uri-Format
 * Migration schema: https://github.com/beemdevelopment/Aegis/blob/master/app/src/main/proto/google_auth.proto
 * Protobuf wire encoding: https://protobuf.dev/programming-guides/encoding/
 * This parser deliberately supports only TOTP. It never converts HOTP to TOTP.
 */
(function (root) {
  'use strict';
  const MAX_URI = 100000;
  const MAX_PAYLOAD = 70000;
  const UTF8 = new TextDecoder('utf-8', {fatal:true});
  const fail = message => { throw new Error(message); };
  function core() {
    if (!root.AuthCore) fail('Der Verschlüsselungskern ist nicht verfügbar.');
    return root.AuthCore;
  }
  function newId() {
    if (root.crypto && root.crypto.randomUUID) return 'acc_' + root.crypto.randomUUID();
    const b = new Uint8Array(16);
    root.crypto.getRandomValues(b);
    return 'acc_' + Array.from(b, x => x.toString(16).padStart(2,'0')).join('');
  }
  function parseURL(text, protocol) {
    if (typeof text !== 'string' || !text.trim()) fail('Bitte einen Einrichtungscode eingeben.');
    text = text.trim();
    if (text.length > MAX_URI) fail('Der Einrichtungscode ist zu groß.');
    let uri;
    try { uri = new URL(text); }
    catch (_) { fail('Der Einrichtungscode ist keine gültige URI.'); }
    if (uri.protocol.toLowerCase() !== protocol || uri.username || uri.password || uri.port || uri.hash) {
      fail('Dieses QR-Format wird nicht unterstützt. Erwartet wird otpauth://totp/ oder otpauth-migration://offline.');
    }
    return uri;
  }
  function getSingle(params, name) {
    const values = params.getAll(name);
    if (values.length > 1) fail('Der Einrichtungscode enthält den Parameter „' + name + '“ mehrfach.');
    return values.length ? values[0] : null;
  }
  function positiveInteger(value, fallback, label) {
    if (value === null) return fallback;
    if (!/^[0-9]+$/.test(value)) fail(label + ' muss eine ganze positive Zahl sein.');
    const result = Number(value);
    if (!Number.isSafeInteger(result) || result < 1) fail(label + ' ist ungültig.');
    return result;
  }
  function parseOtpUri(text) {
    const uri = parseURL(text, 'otpauth:');
    if (uri.hostname.toLowerCase() === 'hotp') fail('HOTP wird nicht unterstützt. Bitte einen zeitbasierten TOTP-Account verwenden.');
    if (uri.hostname.toLowerCase() !== 'totp') fail('Der Einrichtungscode muss einen TOTP-Account enthalten.');
    let label;
    try { label = decodeURIComponent(uri.pathname.replace(/^\//,'')); }
    catch (_) { fail('Die Account-Bezeichnung im Einrichtungscode ist ungültig.'); }
    label = label.trim();
    if (!label) fail('Im Einrichtungscode fehlt die Account-Bezeichnung.');
    const separator = label.indexOf(':');
    const prefix = separator < 0 ? '' : label.slice(0,separator).trim();
    const name = (separator < 0 ? label : label.slice(separator+1)).trim();
    const queryIssuer = getSingle(uri.searchParams, 'issuer');
    const issuer = queryIssuer === null ? prefix : queryIssuer.trim();
    if (prefix && queryIssuer !== null && prefix !== issuer) {
      fail('Die Anbieterangaben im Einrichtungscode widersprechen sich.');
    }
    const secret = getSingle(uri.searchParams, 'secret');
    if (!secret) fail('Im Einrichtungscode fehlt der geheime Schlüssel.');
    const algorithm = (getSingle(uri.searchParams, 'algorithm') || 'SHA1').toUpperCase();
    const digits = positiveInteger(getSingle(uri.searchParams, 'digits'), 6, 'Die Codelänge');
    const period = positiveInteger(getSingle(uri.searchParams, 'period'), 30, 'Das Zeitintervall');
    return core().validateAccount({id:newId(), issuer, name, secret, algorithm, digits, period, type:'totp'});
  }
  function toOtpUri(account) {
    const a = core().validateAccount(account);
    // Colons are separators in the interoperable otpauth label grammar.
    if (a.issuer.includes(':') || a.name.includes(':')) {
      fail('Für einen kompatiblen QR-Export dürfen Anbieter und Account-Name keinen Doppelpunkt enthalten. Bitte den Namen bearbeiten oder JSON exportieren.');
    }
    const label = a.issuer ? encodeURIComponent(a.issuer) + ':' + encodeURIComponent(a.name) : encodeURIComponent(a.name);
    const parts = [
      'secret=' + encodeURIComponent(a.secret),
      'issuer=' + encodeURIComponent(a.issuer),
      'algorithm=' + encodeURIComponent(a.algorithm),
      'digits=' + a.digits,
      'period=' + a.period
    ];
    return 'otpauth://totp/' + label + '?' + parts.join('&');
  }
  class ProtoReader {
    constructor(bytes) { this.bytes = bytes; this.pos = 0; }
    get done() { return this.pos === this.bytes.length; }
    varint() {
      let result = 0n;
      for (let i = 0; i < 10; i++) {
        if (this.pos >= this.bytes.length) fail('Der Google-Export ist abgeschnitten.');
        const byte = this.bytes[this.pos++];
        if (i === 9 && byte > 1) fail('Der Google-Export enthält eine ungültige Ganzzahl.');
        result |= BigInt(byte & 127) << BigInt(i * 7);
        if ((byte & 128) === 0) return result;
      }
      fail('Der Google-Export enthält eine ungültige Ganzzahl.');
    }
    tag() {
      const value = this.varint();
      if (value > 0xffffffffn) fail('Der Google-Export enthält eine ungültige Feldnummer.');
      const field = Number(value >> 3n);
      const wire = Number(value & 7n);
      if (field < 1 || field > 0x1fffffff || wire > 5) fail('Der Google-Export enthält ein ungültiges Datenfeld.');
      return {field, wire};
    }
    data() {
      const length = this.varint();
      if (length > BigInt(this.bytes.length - this.pos)) fail('Der Google-Export ist abgeschnitten.');
      const end = this.pos + Number(length);
      const result = this.bytes.subarray(this.pos,end);
      this.pos = end;
      return result;
    }
    text() {
      try { return UTF8.decode(this.data()); }
      catch (error) { fail('Der Google-Export enthält eine ungültige Textkodierung.'); }
    }
    skip(wire, field, depth = 0) {
      if (depth > 12) fail('Der Google-Export ist zu stark verschachtelt.');
      if (wire === 0) this.varint();
      else if (wire === 1 || wire === 5) {
        this.pos += wire === 1 ? 8 : 4;
        if (this.pos > this.bytes.length) fail('Der Google-Export ist abgeschnitten.');
      } else if (wire === 2) this.data();
      else if (wire === 3) {
        while (!this.done) {
          const tag = this.tag();
          if (tag.wire === 4) {
            if (tag.field !== field) fail('Der Google-Export enthält eine fehlerhafte Datengruppe.');
            return;
          }
          this.skip(tag.wire,tag.field,depth+1);
        }
        fail('Der Google-Export enthält eine unvollständige Datengruppe.');
      } else fail('Der Google-Export enthält eine unerwartete Datengruppe.');
    }
    require(wire, expected) {
      if (wire !== expected) fail('Der Google-Export enthält ein Feld mit falschem Datentyp.');
    }
  }
  function parseParameters(bytes) {
    const reader = new ProtoReader(bytes);
    const p = {secret:new Uint8Array(), name:'', issuer:'', algorithm:0n, digits:0n, type:0n};
    while (!reader.done) {
      const {field, wire} = reader.tag();
      if (field >= 1 && field <= 3) {
        reader.require(wire,2);
        if (field === 1) p.secret = reader.data();
        if (field === 2) p.name = reader.text();
        if (field === 3) p.issuer = reader.text();
      } else if (field >= 4 && field <= 6) {
        reader.require(wire,0);
        p[['algorithm','digits','type'][field-4]] = reader.varint();
      } else reader.skip(wire,field);
    }
    return p;
  }
  function migrationBase64(uri) {
    // Do not apply application/x-www-form-urlencoded '+' -> ' ' conversion:
    // some Google exports contain literal '+' characters in the base64 payload.
    const entries = uri.search.slice(1).split('&');
    const matches = [];
    for (const entry of entries) {
      const split = entry.indexOf('=');
      const key = split < 0 ? entry : entry.slice(0,split);
      let decodedKey;
      try { decodedKey = decodeURIComponent(key); } catch (_) { fail('Der Google-Export enthält ungültige URL-Zeichen.'); }
      if (decodedKey === 'data') {
        if (split < 0) fail('Im Google-Export fehlen die Daten.');
        try { matches.push(decodeURIComponent(entry.slice(split+1))); }
        catch (_) { fail('Die Google-Exportdaten sind ungültig kodiert.'); }
      }
    }
    if (matches.length !== 1 || !matches[0]) fail('Im Google-Export muss genau ein Datenpaket enthalten sein.');
    let value = matches[0].replace(/-/g,'+').replace(/_/g,'/');
    if (value.length > MAX_URI || !/^[A-Za-z0-9+/]*={0,2}$/.test(value) || value.length % 4 === 1) fail('Die Google-Exportdaten sind kein gültiges Base64.');
    const unpadded = value.replace(/=+$/,'');
    if (value.includes('=') && value.length % 4 !== 0) fail('Die Google-Exportdaten enthalten ungültiges Base64-Padding.');
    value = unpadded + '='.repeat((4 - unpadded.length % 4) % 4);
    let binary;
    try { binary = atob(value); } catch (_) { fail('Die Google-Exportdaten sind kein gültiges Base64.'); }
    if (!binary.length || binary.length > MAX_PAYLOAD) fail('Das Google-Datenpaket ist leer oder zu groß.');
    return Uint8Array.from(binary, c => c.charCodeAt(0));
  }
  function parseMigrationUri(text) {
    const uri = parseURL(text,'otpauth-migration:');
    if (uri.hostname.toLowerCase() !== 'offline' || (uri.pathname && uri.pathname !== '/')) fail('Dieser Google-Exporttyp wird nicht unterstützt.');
    const reader = new ProtoReader(migrationBase64(uri));
    const parameters = [];
    let version = 0n, size = 1n, index = 0n, batchId = 0n;
    while (!reader.done) {
      const {field,wire} = reader.tag();
      if (field === 1) {
        reader.require(wire,2);
        if (parameters.length >= 1000) fail('Dieses Google-Datenpaket enthält zu viele Accounts.');
        parameters.push(parseParameters(reader.data()));
      } else if (field >= 2 && field <= 5) {
        reader.require(wire,0);
        const value = reader.varint();
        if (field === 2) version = value;
        if (field === 3) size = value;
        if (field === 4) index = value;
        if (field === 5) batchId = value;
      } else reader.skip(wire,field);
    }
    // Google Authenticator also emits migration version 2 with these same OTP fields.
    // Reference: https://github.com/krissrex/google-authenticator-exporter/issues/26
    // This migration version is independent of our JSON/vault envelope version.
    // Keep the account, enum, protobuf wire-type and batch validation below unchanged.
    if (version !== 0n && version !== 1n && version !== 2n) {
      fail('Die Google-Exportversion ' + version.toString() + ' wird nicht unterstützt. Unterstützt werden die Versionen 0, 1 und 2.');
    }
    if (size === 0n) size = 1n;
    if (size < 1n || size > 1000n || index >= size) fail('Der Google-Export enthält ungültige Angaben zur QR-Serie.');
    if (!parameters.length) fail('Der Google-Export enthält keine Accounts.');
    const accounts = [], skipped = [], warnings = [];
    for (let i = 0; i < parameters.length; i++) {
      const p = parameters[i];
      let issuer = p.issuer.trim();
      let name = p.name.trim();
      if (issuer && name.startsWith(issuer + ':')) name = name.slice(issuer.length+1).trim();
      else if (!issuer && name.includes(':')) {
        const split = name.indexOf(':');
        issuer = name.slice(0,split).trim();
        name = name.slice(split+1).trim();
      }
      const title = name || issuer || 'Account ' + (i + 1);
      if (p.type !== 2n) {
        skipped.push({name:title,reason:p.type === 1n ? 'HOTP wird nicht unterstützt.' : 'Kein unterstützter TOTP-Typ angegeben.'});
        continue;
      }
      const algorithm = {1:'SHA1',2:'SHA256',3:'SHA512'}[p.algorithm.toString()];
      const digits = {1:6,2:8}[p.digits.toString()];
      if (!algorithm || !digits) {
        skipped.push({name:title,reason:!algorithm ? 'Nicht unterstützter Algorithmus (nur SHA1, SHA256, SHA512).' : 'Nicht unterstützte Codelänge (nur 6 oder 8 Stellen).'});
        continue;
      }
      try {
        const account = core().validateAccount({id:newId(), issuer, name, secret:core().base32Encode(p.secret), algorithm, digits, period:30, type:'totp'});
        accounts.push(account);
      } catch (error) {
        skipped.push({name:title,reason:error.message || 'Ungültiger Account.'});
      }
    }
    const batch = {id:BigInt.asIntN(32,batchId).toString(), index:Number(index), size:Number(size)};
    if (batch.size > 1) warnings.push('Teil ' + (batch.index+1) + ' von ' + batch.size + ': Bitte auch die übrigen QR-Codes dieser Google-Exportserie importieren.');
    return {accounts, skipped, batch, warnings};
  }
  function parseQrText(text) {
    if (typeof text !== 'string') fail('Der QR-Code enthält keine Textdaten.');
    const value = text.trim();
    if (/^otpauth-migration:\/\//i.test(value)) return parseMigrationUri(value);
    if (/^otpauth:\/\//i.test(value)) return {accounts:[parseOtpUri(value)],skipped:[],batch:null,warnings:[]};
    fail('Dieser QR-Code enthält keinen TOTP-Einrichtungsschlüssel oder Google-Authenticator-Export.');
  }
  root.AuthFormats = Object.freeze({parseOtpUri,parseMigrationUri,parseQrText,toOtpUri});
})(globalThis);