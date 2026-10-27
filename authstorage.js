/* IndexedDB ciphertext storage with atomic revision checks and cross-tab notices.
 * No account plaintext or password is included in notifications.
 */
(() => {
  'use strict';
  const DB_NAME = 'nexus-authenticator-v1';
  const STORE = 'vault';
  const RECORD_KEY = 'current';
  const PASSWORD_KEY = 'nexus.auth.v1.password';
  const NOTICE_KEY = 'nexus.auth.v1.notice';
  const CHANNEL_NAME = 'nexus.auth.v1.events';
  const source = Date.now().toString(36) + '-' + Math.random().toString(36).slice(2);
  const listeners = new Set();
  const seen = new Set();
  const remoteWipes = new Set();
  let database = null;
  let opening = null;
  let channel = null;
  let generation = 0;
  let localWipePending = false;
  let wipePromise = null;
  function error(message, code = 'STORAGE') {
    const result = new Error(message);
    result.code = code;
    return result;
  }
  function translate(reason, action = 'gespeichert') {
    if (reason?.code === 'CONFLICT' || reason?.code === 'BLOCKED') return reason;
    if (reason?.name === 'QuotaExceededError') return error('Der Browser-Speicher ist voll. Der Tresor konnte nicht ' + action + ' werden. Bitte zuerst ein Backup erstellen.');
    if (reason?.name === 'SecurityError' || reason?.name === 'InvalidStateError') return error('Der Browser blockiert den lokalen Speicher. Erlaube Website-Daten oder verwende ein reguläres Browserfenster.');
    return error('Der lokale Tresor konnte nicht ' + action + ' werden. Bitte Browser-Speicher und Website-Berechtigungen prüfen.');
  }
  function revisionId() {
    if (!globalThis.crypto?.getRandomValues) throw error('Der Browser unterstützt keinen sicheren Zufallsgenerator.');
    return Array.from(globalThis.crypto.getRandomValues(new Uint8Array(16)), byte => byte.toString(16).padStart(2, '0')).join('');
  }
  function rememberSeen(messageId) {
    if (seen.has(messageId)) return false;
    seen.add(messageId);
    if (seen.size > 250) seen.delete(seen.values().next().value);
    return true;
  }
  function closeDatabase() {
    generation++;
    if (database) database.close();
    database = null;
    // An open request already in flight cannot be cancelled. Its generation check
    // closes the returned connection before it could keep deletion blocked.
  }
  function receive(message) {
    if (!message || typeof message !== 'object' || message.source === source || typeof message.source !== 'string' || typeof message.id !== 'string' || message.id.length > 160) return;
    if (!['changed', 'privacy', 'wipe-start', 'wipe', 'wipe-abort'].includes(message.type)) return;
    // Start and completion are distinct lifecycle events. Deduplicate before
    // side effects so a delayed duplicate cannot close a newly reopened database.
    if (!rememberSeen(message.type + ':' + message.id)) return;
    if (message.type === 'wipe-start') {
      remoteWipes.add(message.id);
      closeDatabase();
    } else if (message.type === 'wipe' || message.type === 'wipe-abort') {
      remoteWipes.delete(message.id);
      closeDatabase();
    }
    const clean = message.type === 'changed'
      ? { type: 'changed', revision: typeof message.revision === 'string' ? message.revision.slice(0, 100) : null }
      : message.type === 'privacy'
        ? { type: 'privacy', remembered: message.remembered === true }
        : { type: 'wipe', phase: message.type === 'wipe-start' ? 'start' : message.type === 'wipe-abort' ? 'aborted' : 'complete' };
    for (const callback of listeners) {
      try { callback(clean); }
      catch (reason) { console.error('Authenticator storage notification failed:', reason?.name || 'Error'); }
    }
  }
  function notice(type, fields = {}, messageId = source + '-' + Date.now().toString(36) + '-' + Math.random().toString(36).slice(2)) {
    const message = { type, id: messageId, source, ...fields };
    try { channel?.postMessage(message); } catch { /* Atomic CAS still prevents overwrites. */ }
    try { globalThis.localStorage.setItem(NOTICE_KEY, JSON.stringify(message)); } catch { /* BroadcastChannel or CAS remains available. */ }
    return messageId;
  }
  try {
    if ('BroadcastChannel' in globalThis) {
      channel = new BroadcastChannel(CHANNEL_NAME);
      channel.addEventListener('message', event => receive(event.data));
    }
  } catch { channel = null; }
  globalThis.addEventListener?.('storage', event => {
    if (event.key !== NOTICE_KEY || !event.newValue || event.newValue.length > 2048) return;
    try { receive(JSON.parse(event.newValue)); } catch { /* Ignore unrelated or malformed messages. */ }
  });
  globalThis.addEventListener?.('pagehide', () => closeDatabase());
  function checkWipe() {
    if (localWipePending || remoteWipes.size) throw error('Der Tresor wird gerade zurückgesetzt. Bitte anschließend die Seite neu laden.', 'CONFLICT');
  }
  async function openDatabase() {
    checkWipe();
    if (database) return database;
    if (opening) return opening;
    if (!globalThis.indexedDB) throw error('IndexedDB ist in diesem Browser nicht verfügbar. Bitte Website-Daten erlauben oder einen aktuellen Browser verwenden.');
    const requestedGeneration = generation;
    opening = new Promise((resolve, reject) => {
      let request;
      let finished = false;
      const rejectOpen = reason => { if (!finished) { finished = true; reject(reason); } };
      try { request = globalThis.indexedDB.open(DB_NAME, 1); }
      catch (reason) { rejectOpen(translate(reason, 'geöffnet')); return; }
      request.onupgradeneeded = () => {
        const db = request.result;
        if (!db.objectStoreNames.contains(STORE)) db.createObjectStore(STORE);
      };
      request.onerror = () => rejectOpen(translate(request.error, 'geöffnet'));
      request.onblocked = () => rejectOpen(error('Ein anderer Tab blockiert den Tresor. Schließe weitere Tabs dieser App und lade die Seite neu.', 'BLOCKED'));
      request.onsuccess = () => {
        const db = request.result;
        if (finished) { db.close(); return; }
        if (requestedGeneration !== generation || localWipePending || remoteWipes.size) {
          db.close();
          rejectOpen(error('Der Tresor wurde zwischenzeitlich geändert. Bitte die Seite neu laden.', 'CONFLICT'));
          return;
        }
        database = db;
        db.onversionchange = () => {
          closeDatabase();
        };
        db.onclose = () => { if (database === db) database = null; };
        finished = true;
        resolve(db);
      };
    });
    try { return await opening; }
    finally { opening = null; }
  }
  function checkedRecord(value) {
    if (value === undefined) return null;
    if (!value || typeof value !== 'object' || typeof value.revision !== 'string' || !/^[a-f0-9]{32}$/.test(value.revision) || !value.envelope) throw error('Der gespeicherte Tresor hat ein ungültiges Format. Stelle ein Backup wieder her oder setze die App zurück.');
    const envelope = globalThis.AuthCore.validateEnvelope(value.envelope);
    return { envelope, revision: value.revision };
  }
  async function read() {
    const db = await openDatabase();
    checkWipe();
    return new Promise((resolve, reject) => {
      let transaction;
      let result = null;
      let failure = null;
      try {
        transaction = db.transaction(STORE, 'readonly');
        const request = transaction.objectStore(STORE).get(RECORD_KEY);
        request.onsuccess = () => {
          try { result = checkedRecord(request.result); }
          catch (reason) { failure = reason; transaction.abort(); }
        };
        transaction.oncomplete = () => resolve(result);
        transaction.onabort = () => reject(failure || translate(transaction.error, 'gelesen'));
        transaction.onerror = () => { /* onabort delivers the transaction's final failure. */ };
      } catch (reason) { reject(translate(reason, 'gelesen')); }
    });
  }
  async function save(rawEnvelope, expectedRevision) {
    if (expectedRevision !== null && (typeof expectedRevision !== 'string' || !/^[a-f0-9]{32}$/.test(expectedRevision))) throw error('Die Tresor-Version ist ungültig. Bitte erneut entsperren.', 'CONFLICT');
    // Keep IndexedDB ciphertext-only even if the caller accidentally supplies a vault.
    const envelope = globalThis.AuthCore.validateEnvelope(rawEnvelope);
    const db = await openDatabase();
    checkWipe();
    const record = { envelope, revision: revisionId() };
    return new Promise((resolve, reject) => {
      let transaction;
      let failure = null;
      try {
        transaction = db.transaction(STORE, 'readwrite');
        const store = transaction.objectStore(STORE);
        const request = store.get(RECORD_KEY);
        request.onsuccess = () => {
          const storedRevision = request.result === undefined ? null : request.result?.revision;
          if (storedRevision !== expectedRevision) {
            failure = error('Der Tresor wurde in einem anderen Tab geändert. Entsperre ihn erneut, damit keine Änderungen überschrieben werden.', 'CONFLICT');
            transaction.abort();
            return;
          }
          store.put(record, RECORD_KEY);
        };
        transaction.oncomplete = () => {
          notice('changed', { revision: record.revision });
          resolve(record);
        };
        transaction.onabort = () => reject(failure || translate(transaction.error));
        transaction.onerror = () => { /* onabort preserves CONFLICT and final transaction errors. */ };
      } catch (reason) { reject(translate(reason)); }
    });
  }
  function getRemembered() {
    try {
      const password = globalThis.localStorage.getItem(PASSWORD_KEY);
      if (password === null || password === '') return null;
      if (password.length > 4096) throw error('Das gespeicherte Passwort ist ungültig. Bitte die automatische Entsperrung deaktivieren.');
      return password;
    } catch (reason) {
      if (reason?.code === 'STORAGE') throw reason;
      throw error('Der Browser blockiert localStorage. Ein gespeichertes Passwort kann nicht gelesen werden.');
    }
  }
  function setRemembered(password) {
    if (typeof password !== 'string' || !password || password.length > 4096) throw error('Das Passwort kann nicht gespeichert werden.');
    try { globalThis.localStorage.setItem(PASSWORD_KEY, password); }
    catch { throw error('Der Browser blockiert localStorage. Das Passwort wurde nicht gespeichert; automatische Entsperrung ist nicht verfügbar.'); }
    notice('privacy', { remembered: true });
  }
  function clearRemembered() {
    try { globalThis.localStorage.removeItem(PASSWORD_KEY); }
    catch { throw error('Das gespeicherte Passwort konnte nicht entfernt werden. Bitte Website-Daten in den Browser-Einstellungen löschen.'); }
    notice('privacy', { remembered: false });
  }
  async function wipe() {
    if (wipePromise) return wipePromise;
    if (localWipePending) throw error('Die Löschung wartet noch auf einen anderen Tab. Schließe alle weiteren Tabs dieser App und lade die Seite anschließend neu.', 'BLOCKED');
    localWipePending = true;
    closeDatabase();
    const operation = notice('wipe-start');
    wipePromise = new Promise((resolve, reject) => {
      let request;
      let blockedTimer = null;
      const done = () => { if (blockedTimer) clearTimeout(blockedTimer); };
      try { request = globalThis.indexedDB.deleteDatabase(DB_NAME); }
      catch (reason) {
        localWipePending = false;
        notice('wipe-abort', {}, operation);
        reject(translate(reason, 'gelöscht'));
        return;
      }
      request.onblocked = () => {
        if (!blockedTimer) blockedTimer = setTimeout(() => {
          // A deleteDatabase request cannot be cancelled. Keep local writes blocked;
          // the request may finish after another tab releases its connection.
          reject(error('Die Löschung wartet auf einen anderen Tab und ist noch nicht bestätigt. Schließe alle weiteren Tabs dieser App. Lade die Seite danach neu; die Löschung kann dann abgeschlossen sein.', 'BLOCKED'));
        }, 2000);
      };
      request.onerror = () => {
        done();
        localWipePending = false;
        notice('wipe-abort', {}, operation);
        reject(translate(request.error, 'gelöscht'));
      };
      request.onsuccess = () => {
        done();
        localWipePending = false;
        let passwordError = null;
        try { globalThis.localStorage.removeItem(PASSWORD_KEY); }
        catch { passwordError = error('Der Tresor wurde gelöscht, aber das gespeicherte Passwort konnte nicht entfernt werden. Bitte Website-Daten in den Browser-Einstellungen löschen.'); }
        notice('wipe', {}, operation);
        // The app owns this metadata key; removing it leaves no stale notice behind.
        try { globalThis.localStorage.removeItem(NOTICE_KEY); } catch { /* No password is in the notice. */ }
        if (passwordError) reject(passwordError); else resolve();
      };
    });
    try { return await wipePromise; }
    finally { wipePromise = null; }
  }
  function onChange(callback) {
    if (typeof callback !== 'function') throw new TypeError('onChange erwartet eine Funktion.');
    listeners.add(callback);
    return () => listeners.delete(callback);
  }
  globalThis.AuthStorage = Object.freeze({ DB_NAME, PASSWORD_KEY, NOTICE_KEY, read, save, wipe, getRemembered, setRemembered, clearRemembered, onChange });
})();