/* Local import interface. Native BarcodeDetector only; no decoder service or network. */
(function(root) {
  'use strict';
  const MAX_JSON = 8 * 1024 * 1024;
  const MAX_IMAGE = 15 * 1024 * 1024;
  const MAX_PIXELS = 32000000;
  let sequence = 0;
  let active = null;
  const $ = id => document.getElementById(id);
  const N = () => root.Nexus;
  const esc = value => N().escape(String(value ?? ''));
  const ico = name => N().icon(name);
  const fingerprint = account => N().accountFingerprint ? N().accountFingerprint(account) : JSON.stringify([account.secret,account.algorithm,account.digits,account.period,account.type]);
  const live = state => active === state && !state.closed && N().isUnlocked();
  const notice = (message, warning = false) => '<div class="notice' + (warning ? ' warning' : '') + '">' + ico(warning ? 'alert' : 'check') + '<div>' + esc(message) + '</div></div>';
  const currentError = message => { const element = $('importError'); if (element) N().showError(element,message || ''); };
  const errorMessage = error => N().formatError(error);
  function cameraAccessError(error) {
    if (error?.name === 'NotAllowedError' || error?.name === 'PermissionDeniedError') return 'Der Kamerazugriff wurde nicht erlaubt. Erlaube ihn in den Website-Einstellungen oder lade ein QR-Bild hoch.';
    if (error?.name === 'NotFoundError' || error?.name === 'DevicesNotFoundError') return 'Es wurde keine Kamera gefunden. Du kannst stattdessen ein QR-Bild hochladen.';
    if (error?.name === 'NotReadableError' || error?.name === 'TrackStartError') return 'Die Kamera ist gerade nicht verfügbar. Schließe andere Kamera-Apps und versuche es erneut.';
    return N().formatError(error);
  }
  function cleanup(state) {
    if (state.closed) return;
    state.closed = true;
    stopCamera(state);
    state.abort.abort();
    window.removeEventListener('paste',state.onPaste);
    document.removeEventListener('visibilitychange',state.onVisibility);
    state.queue.length = 0;
    state.skipped.length = 0;
    state.pendingEncrypted = null;
    state.detector = null;
    state.batches.clear();
    state.pages.clear();
    state.extras.clear();
    if (active === state) active = null;
  }
  function setWorking(state,working,button,label) {
    state.working = working;
    if (!live(state)) return;
    $('importShell')?.setAttribute('aria-busy',String(working));
    $('importShell')?.querySelectorAll('[data-import-tab],.import-upload-input').forEach(node => {node.disabled = working;});
    const drop = $('importDropzone');
    if (drop) { drop.setAttribute('aria-disabled',String(working)); drop.tabIndex = working ? -1 : 0; }
    if (button) N().setBusy(button,working,label);
  }
  function tabsMarkup(tab) {
    return '<div class="tabs" role="tablist" aria-label="Importquelle">' + [
      ['camera','camera','Kamera'],['image','image','QR-Bild'],['json','file','JSON-Datei']
    ].map(([id,icon,label]) => '<button class="tab' + (tab===id?' active':'') + '" id="importTab-' + id + '" type="button" role="tab" aria-selected="' + (tab===id) + '" aria-controls="importContent" data-import-tab="' + id + '">' + ico(icon) + esc(label) + '</button>').join('') + '</div>';
  }
  function open(initial = 'image') {
    if (!N()?.isUnlocked()) return;
    if (active) cleanup(active);
    const state = {
      token:++sequence, closed:false, abort:new AbortController(), tab:['camera','image','json'].includes(initial)?initial:'image',
      stage:'input', queue:[], skipped:[], repeated:0, batches:new Map(), pages:new Set(), extras:new Set(),
      partialConfirmed:false, listLimit:100, working:false, cameraRun:0, stream:null, video:null, timer:null,
      detector:null, detectorPromise:null, pendingEncrypted:null, playbackPending:false, cameraScanning:false, onCameraPlaying:null
    };
    active = state;
    const style = '<style>.import-summary{display:flex;align-items:center;gap:9px;flex-wrap:wrap;margin:0 0 14px;font-size:11px;color:var(--muted)}.import-summary strong{font-size:16px;font-weight:550;color:var(--accent)}.import-series{margin:13px 0;font-size:11px;color:var(--muted);line-height:1.7}.import-series p{margin:3px 0}.import-mini{font-size:10px;color:var(--muted);margin:10px 0;line-height:1.7}.import-upload-input{position:absolute;width:1px!important;height:1px!important;opacity:0;overflow:hidden;padding:0!important;min-height:0!important;clip:rect(0,0,0,0)}.import-key-form{margin-top:17px}.import-key-form .field{margin-bottom:9px}.import-partial{display:flex;gap:10px;font-size:11px;line-height:1.7;color:#edc8b4;margin:14px 0}.import-warning-list{font-size:11px;line-height:1.7;color:var(--muted);padding-left:18px;overflow-wrap:anywhere;max-height:150px;overflow:auto}.import-toolbar{display:flex;gap:8px;flex-wrap:wrap}.import-source-hint{font-size:10px;line-height:1.7;color:var(--muted);margin:13px 0}.import-draft{display:flex;align-items:center;justify-content:space-between;gap:10px;border-top:1px solid var(--line);padding-top:15px;margin-top:18px;font-size:11px;color:var(--muted)}.import-row .tag{white-space:nowrap;flex-shrink:0}.import-row.is-duplicate{opacity:.7}.import-row .import-account{overflow-wrap:anywhere}.import-drop{transition:background .15s,border-color .15s}.import-camera-controls .btn{flex:1}.import-drop:focus-visible{outline:2px solid var(--accent);outline-offset:3px}.import-drop[aria-disabled="true"]{opacity:.55;cursor:wait}.import-selection{font-size:11px;color:var(--muted);overflow-wrap:anywhere;margin:0 0 15px}.import-preview-title{font-size:15px;letter-spacing:-.2px;font-weight:550;margin:0 0 10px}.import-loading{font-size:11px;line-height:1.7;color:var(--accent);margin-top:12px}</style>';
    N().showModal('Accounts importieren','Lokal einlesen. Prüfen. Verschlüsselt speichern.',style + '<div id="importShell">' + tabsMarkup(state.tab) + '<div id="importContent" role="tabpanel"></div><div id="importError" class="inline-error" role="alert" hidden></div><div id="importDraft"></div><div class="dialog-actions" id="importActions"></div></div>',{wide:true,onClose:()=>cleanup(state)});
    if (!live(state)) return;
    $('importShell').addEventListener('click',event => {
      const tab = event.target.closest('[data-import-tab]');
      if (tab && !state.working) selectTab(state,tab.dataset.importTab);
    });
    $('importShell').addEventListener('keydown',event => {
      if (!event.target.matches('[data-import-tab]') || !['ArrowLeft','ArrowRight','Home','End'].includes(event.key) || state.working) return;
      event.preventDefault();
      const order = ['camera','image','json'];
      let index = order.indexOf(state.tab);
      if (event.key === 'Home') index = 0;
      else if (event.key === 'End') index = 2;
      else index = (index + (event.key === 'ArrowRight' ? 1 : 2)) % 3;
      selectTab(state,order[index]); $('importTab-'+order[index])?.focus();
    });
    state.onPaste = event => {
      if (!live(state) || state.working || state.stage === 'password') return;
      const images = Array.from(event.clipboardData?.items || []).filter(item => item.kind==='file' && item.type.startsWith('image/')).map(item => item.getAsFile()).filter(Boolean);
      if (images.length) {
        event.preventDefault(); selectTab(state,'image'); processFiles(state,images,'image'); return;
      }
      const text = event.clipboardData?.getData('text/plain')?.trim();
      const target = event.target;
      if (target instanceof Element && target.closest('input,textarea,[contenteditable=true]')) return;
      if (text && /^otpauth(?:-migration)?:\/\//i.test(text)) {
        event.preventDefault(); processText(state,text);
      }
    };
    state.onVisibility = () => {
      if (document.hidden && live(state)) {
        stopCamera(state);
        const status = $('importCameraStatus');
        if (status) status.textContent = 'Kamera pausiert. Zum Fortsetzen erneut starten.';
      }
    };
    window.addEventListener('paste',state.onPaste);
    document.addEventListener('visibilitychange',state.onVisibility);
    renderInput(state);
  }
  function updateTabSelection(state) {
    $('importShell')?.querySelectorAll('[data-import-tab]').forEach(button => {
      const selected = button.dataset.importTab === state.tab;
      button.classList.toggle('active',selected);
      button.setAttribute('aria-selected',String(selected));
      button.setAttribute('tabindex',selected?'0':'-1');
    });
    $('importContent')?.setAttribute('aria-labelledby','importTab-'+state.tab);
  }
  function selectTab(state,tab) {
    if (!live(state) || state.working) return;
    stopCamera(state);
    state.pendingEncrypted = null;
    state.tab = tab;
    state.stage = 'input';
    currentError('');
    renderInput(state);
  }
  function uriForm() {
    return '<div class="divider-label">ODER EINRICHTUNGS-URI EINFÜGEN</div><form id="importUriForm" class="import-key-form"><div class="field"><label for="importUri">otpauth://totp/ oder otpauth-migration://</label><textarea id="importUri" rows="2" maxlength="100000" autocomplete="off" spellcheck="false" placeholder="otpauth://totp/…" required></textarea></div><button class="btn" type="submit">' + ico('key') + 'URI einlesen</button></form>';
  }
  function renderInput(state) {
    if (!live(state)) return;
    state.stage = 'input';
    updateTabSelection(state);
    const nativeAvailable = typeof root.BarcodeDetector === 'function';
    let html = '';
    if (state.tab === 'camera') {
      html = '<div class="scan-preview"><video id="importVideo" muted playsinline autoplay aria-label="Kamerabild zum QR-Scannen"></video><div class="scan-placeholder" id="importCameraPlaceholder">' + ico('scan') + '<span>QR-Code in den Rahmen halten</span></div><div class="scan-guides" id="importScanGuides" hidden></div></div><div class="camera-state" id="importCameraStatus" role="status">Die Kamera startet erst nach deinem Klick.</div><div class="import-toolbar import-camera-controls"><button class="btn primary" id="importStartCamera" type="button">' + ico('camera') + 'Kamera starten</button><button class="btn" id="importStopCamera" type="button" hidden>' + ico('x') + 'Kamera stoppen</button></div>';
      if (!nativeAvailable) html += '<div style="margin-top:15px">' + notice('Dieser Browser bietet keine native QR-Erkennung. Füge eine Einrichtungs-URI ein oder importiere eine JSON-Datei.',true) + '</div>';
      html += uriForm();
    } else if (state.tab === 'image') {
      html = '<input id="importImageFiles" class="import-upload-input" aria-label="QR-Bilder auswählen" tabindex="-1" type="file" accept="image/png,image/jpeg,image/webp,image/gif,image/bmp,image/avif,.png,.jpg,.jpeg,.webp,.gif,.bmp,.avif" multiple><div class="dropzone import-drop" id="importDropzone" tabindex="0" role="button" aria-controls="importImageFiles" aria-disabled="false">' + ico('image') + '<strong>Deinen QR-Code hier ablegen</strong><p>Bild auswählen, hineinziehen oder mit Strg/⌘ + V einfügen.<br>PNG, JPG, WebP, GIF, BMP oder AVIF · bis 15 MB pro Bild</p><span class="small-link">Bild auswählen</span></div><p class="import-source-hint">Unterstützt TOTP-Einrichtungscodes und Google-Authenticator-Exporte. Bei mehreren Google-QR-Codes kannst du alle Bilder gemeinsam auswählen.</p>';
      if (!nativeAvailable) html += notice('Für das Lesen von QR-Bildern fehlt diesem Browser die native Barcode Detection API. URI- und JSON-Import funktionieren weiterhin.',true);
      html += uriForm();
    } else {
      html = '<input id="importJsonFiles" class="import-upload-input" aria-label="JSON-Datei auswählen" tabindex="-1" type="file" accept="application/json,.json"><div class="dropzone import-drop" id="importDropzone" tabindex="0" role="button" aria-controls="importJsonFiles" aria-disabled="false">' + ico('file') + '<strong>Dein Backup importieren</strong><p>export.json oder export.enc.json auswählen oder hier ablegen.<br>Eine JSON-Datei · bis 8 MB</p><span class="small-link">Datei auswählen</span></div><p class="import-source-hint">Eine verschlüsselte Datei benötigt ihr eigenes Export-Passwort. Vorhandene Accounts bleiben erhalten; identische Schlüssel werden übersprungen.</p>' + notice('JSON-Import unterstützt das Datenformat dieser App: Version 1 mit einer Accounts-Liste, unverschlüsselt oder als verschlüsselter App-Export.');
    }
    $('importContent').innerHTML = html;
    const uri = $('importUriForm');
    uri?.addEventListener('submit',event => {event.preventDefault(); if (!state.working) processText(state,$('importUri').value);});
    $('importStartCamera')?.addEventListener('click',()=>startCamera(state));
    $('importStopCamera')?.addEventListener('click',()=>stopCamera(state,'Kamera gestoppt.'));
    const input = $(state.tab==='image'?'importImageFiles':'importJsonFiles');
    if (input) input.addEventListener('change',()=>{if (!state.working && input.files?.length) processFiles(state,Array.from(input.files),state.tab);input.value='';});
    const drop = $('importDropzone');
    const chooseFile = event => {
      event.preventDefault();
      if (live(state) && !state.working && input && !input.disabled) input.click();
    };
    drop?.addEventListener('keydown',event=>{if (event.key==='Enter'||event.key===' ') {event.preventDefault();if(!event.repeat)chooseFile(event);}});
    drop?.addEventListener('click',chooseFile);
    ['dragenter','dragover'].forEach(type=>drop?.addEventListener(type,event=>{event.preventDefault();if(!state.working) drop.classList.add('dragover');}));
    drop?.addEventListener('dragleave',event=>{if(!drop.contains(event.relatedTarget)) drop.classList.remove('dragover');});
    drop?.addEventListener('drop',event=>{event.preventDefault();drop.classList.remove('dragover');if(!state.working)processFiles(state,Array.from(event.dataTransfer?.files||[]),state.tab);});
    renderDraft(state);
    $('importActions').innerHTML = '<button class="btn" id="importCancel" type="button">Abbrechen</button>';
    $('importCancel').addEventListener('click',()=>N().closeModal());
  }
  function renderDraft(state) {
    if (!live(state)) return;
    if (!state.queue.length && !state.skipped.length) { $('importDraft').innerHTML=''; return; }
    $('importDraft').innerHTML = '<div class="import-draft"><span>' + state.queue.length + ' Account' + (state.queue.length===1?'':'s') + ' eingelesen</span><button class="btn subtle" id="importReview" type="button">Vorschau öffnen ' + ico('check') + '</button></div>';
    $('importReview').addEventListener('click',()=>{if(!state.working){stopCamera(state);renderPreview(state);}});
  }
  function incompleteSeries(state) {
    return Array.from(state.batches.values()).filter(batch=>batch.indices.size<batch.size);
  }
  function addResult(state,result) {
    if (!live(state)) return false;
    const batch = result.batch;
    let pageKey = null;
    if (batch) {
      pageKey = batch.id + ':' + batch.size + ':' + batch.index;
      // Legacy single-page exports can omit batch_id. Avoid confusing two such exports.
      if (batch.id==='0' && batch.size===1) pageKey += ':' + result.accounts.map(fingerprint).join('|');
      if (state.pages.has(pageKey)) throw new Error('Dieser Teil des Google-Exports wurde bereits eingelesen. Bitte den nächsten QR-Code verwenden.');
      const previous = state.batches.get(batch.id);
      if (batch.size>1 && previous && previous.size!==batch.size) throw new Error('Diese QR-Serie enthält widersprüchliche Angaben. Bitte eine neue Google-Exportserie erzeugen.');
    }
    const existing = new Set(state.queue.map(fingerprint));
    const unique=[];
    let duplicates=0;
    for(const account of result.accounts) {
      const key=fingerprint(account);
      if(existing.has(key)) duplicates++;
      else {existing.add(key);unique.push(account);}
    }
    if(state.queue.length+unique.length>root.AuthCore.MAX_ACCOUNTS) throw new Error('Es können höchstens ' + root.AuthCore.MAX_ACCOUNTS + ' Accounts auf einmal importiert werden.');
    state.queue.push(...unique);
    state.repeated+=duplicates;
    state.skipped.push(...(result.skipped||[]));
    if(state.skipped.length>5000) state.skipped.length=5000;
    if(pageKey) state.pages.add(pageKey);
    if(batch?.size>1) {
      const series=state.batches.get(batch.id)||{id:batch.id,size:batch.size,indices:new Set()};
      series.indices.add(batch.index);
      state.batches.set(batch.id,series);
      state.partialConfirmed=false;
    }
    // Batch warnings are generated from current completion state, rather than retained as stale text.
    if (!batch?.size || batch.size<=1) for(const warning of result.warnings||[]) state.extras.add(warning);
    return true;
  }
  function processText(state,text) {
    if(!live(state)||state.working) return;
    currentError('');
    try {
      const result=root.AuthFormats.parseQrText(text);
      addResult(state,result);
      const input=$('importUri');if(input)input.value='';
      stopCamera(state);
      renderPreview(state);
    } catch(error) {currentError(errorMessage(error));}
  }
  function renderPreview(state) {
    if(!live(state))return;
    stopCamera(state);
    state.stage='preview';
    state.pendingEncrypted=null;
    currentError('');
    updateTabSelection(state);
    const stored=new Set(N().getAccounts().map(fingerprint));
    const duplicateAccounts=state.queue.filter(account=>stored.has(fingerprint(account))).length;
    const fresh=state.queue.length-duplicateAccounts;
    const duplicates=duplicateAccounts+state.repeated;
    const incomplete=incompleteSeries(state);
    let html='<h3 class="import-preview-title" id="importPreviewTitle" tabindex="-1">Bereit für deinen Tresor</h3><div class="import-summary"><span><strong>' + fresh + '</strong> neue Accounts</span><span>· ' + duplicates + ' doppelt</span><span>· ' + state.skipped.length + ' nicht unterstützt</span></div>';
    if(!state.queue.length) html+=notice('Es wurden keine unterstützten TOTP-Accounts gefunden. Die Details stehen weiter unten.',true);
    if(state.batches.size) {
      html+='<div class="import-series">';
      for(const batch of state.batches.values()) {
        const complete=batch.indices.size===batch.size;
        html+='<p>' + (complete?'✓ ':'') + esc('Google-QR-Serie: ' + batch.indices.size + ' von ' + batch.size + ' Teilen eingelesen') + '</p>';
        if(!complete) {
          const missing=Array.from({length:batch.size},(_,index)=>index).filter(index=>!batch.indices.has(index)).map(index=>index+1);
          html+='<p>' + esc('Fehlend: ' + missing.slice(0,20).join(', ') + (missing.length>20?' …':'')) + '</p>';
        }
      }
      html+='</div>';
    }
    if(incomplete.length) html+=notice('Die Google-Exportserie ist noch unvollständig. Lies die übrigen QR-Codes ein oder bestätige ausdrücklich, dass nur die bisher erkannten Accounts importiert werden sollen.',true) + '<label class="import-partial"><input type="checkbox" id="importAllowPartial"' + (state.partialConfirmed?' checked':'') + '><span>Nur die bisher erkannten Accounts importieren.</span></label>';
    if(state.queue.length) {
      html+='<div class="import-list" aria-label="Vorschau der eingelesenen Accounts">' + state.queue.slice(0,state.listLimit).map(account=>{
        const duplicate=stored.has(fingerprint(account));
        return '<div class="import-row' + (duplicate?' is-duplicate':'') + '">' + ico(duplicate?'check':'key') + '<div class="import-account"><strong>' + esc(account.issuer||'TOTP-Account') + '</strong><small>' + esc(account.name) + '</small></div><span class="tag">' + (duplicate?'Vorhanden':esc(account.algorithm+' · '+account.digits+' Stellen')) + '</span></div>';
      }).join('') + '</div>';
      if(state.queue.length>state.listLimit) html+='<button class="btn subtle" id="importShowMore" type="button">Weitere Accounts anzeigen (' + (state.queue.length-state.listLimit) + ')</button>';
    }
    if(state.skipped.length) html+='<details><summary>' + state.skipped.length + ' Accounts werden übersprungen</summary><ul class="import-warning-list">' + state.skipped.map(item=>'<li><strong>' + esc(item.name) + ':</strong> ' + esc(item.reason) + '</li>').join('') + '</ul></details>';
    for(const warning of state.extras)html+='<p class="import-mini">' + esc(warning) + '</p>';
    html+='<p class="import-mini">Einrichtungsschlüssel bleiben in diesem Browser. Erst „Importieren“ speichert die Accounts verschlüsselt in deinem Tresor.</p>';
    $('importContent').innerHTML=html;
    $('importDraft').innerHTML='';
    $('importActions').innerHTML='<button class="btn left" id="importMore" type="button">' + ico('plus') + 'Weitere einlesen</button><button class="btn primary" id="importCommit" type="button"' + (!fresh||(incomplete.length&&!state.partialConfirmed)?' disabled':'') + '>' + ico('import') + fresh + ' Account' + (fresh===1?'':'s') + ' importieren</button>';
    $('importMore').addEventListener('click',()=>{if(!state.working){renderInput(state);currentError('');}});
    $('importAllowPartial')?.addEventListener('change',event=>{state.partialConfirmed=event.target.checked;$('importCommit').disabled=!fresh||!state.partialConfirmed;});
    $('importShowMore')?.addEventListener('click',()=>{state.listLimit+=100;renderPreview(state);});
    $('importCommit').addEventListener('click',()=>commit(state));
    $('importPreviewTitle').focus({preventScroll:false});
  }
  async function commit(state) {
    if(!live(state)||state.working||(incompleteSeries(state).length&&!state.partialConfirmed))return;
    const button=$('importCommit');
    setWorking(state,true,button,'Importieren …');
    $('importMore').disabled=true;
    currentError('');
    try {
      const result=await N().addImported(state.queue.slice());
      if(!live(state))return;
      const repeated=state.repeated;
      N().closeModal();
      const duplicates=result.duplicates+repeated;
      N().toast(result.added + ' Account' + (result.added===1?'':'s') + ' importiert.' + (duplicates?' '+duplicates+' doppelte übersprungen.':''));
    }catch(error){
      if(live(state)){currentError(errorMessage(error));setWorking(state,false,button);$('importMore').disabled=false;}
    }
  }
  async function getDetector(state) {
    if(state.detector)return state.detector;
    if(state.detectorPromise)return state.detectorPromise;
    state.detectorPromise=(async()=>{
      if(typeof root.BarcodeDetector!=='function')throw new Error('Dieser Browser unterstützt die native Barcode Detection API nicht. Nutze den URI- oder JSON-Import oder einen Browser mit nativer QR-Erkennung.');
      if(typeof root.BarcodeDetector.getSupportedFormats==='function'){
        const formats=await root.BarcodeDetector.getSupportedFormats();
        if(!formats.includes('qr_code'))throw new Error('Die native Barcode Detection API dieses Browsers unterstützt keine QR-Codes. Nutze den URI- oder JSON-Import.');
      }
      const detector=new root.BarcodeDetector({formats:['qr_code']});
      if(live(state))state.detector=detector;
      return detector;
    })();
    try{return await state.detectorPromise;}finally{state.detectorPromise=null;}
  }
  function cameraLive(state,run) {
    return live(state)&&run===state.cameraRun&&state.tab==='camera'&&state.stage==='input'&&!document.hidden;
  }
  function stopCamera(state,status='') {
    state.cameraRun++;
    state.playbackPending=false;state.cameraScanning=false;
    clearTimeout(state.timer);state.timer=null;
    if(state.stream){for(const track of state.stream.getTracks())track.stop();state.stream=null;}
    if(state.video){
      if(state.onCameraPlaying)state.video.removeEventListener?.('playing',state.onCameraPlaying);
      state.video.pause();state.video.srcObject=null;state.video.controls=false;state.video=null;
    }
    state.onCameraPlaying=null;
    if(!live(state))return;
    const start=$('importStartCamera'),stop=$('importStopCamera');
    if(start){start.hidden=false;N().setBusy(start,false);start.innerHTML=ico('camera')+'Kamera starten';}
    if(stop)stop.hidden=true;
    const placeholder=$('importCameraPlaceholder'),guides=$('importScanGuides');
    if(placeholder)placeholder.hidden=false;if(guides)guides.hidden=true;
    if(status&&$('importCameraStatus'))$('importCameraStatus').textContent=status;
  }
  function cameraPlaying(state,run) {
    if(!cameraLive(state,run)||!state.stream||!state.video||state.cameraScanning)return;
    const video=state.video,detector=state.detector;
    state.cameraScanning=true;
    const button=$('importStartCamera');
    N().setBusy(button,false);button.hidden=true;
    video.controls=false;
    $('importStopCamera').hidden=false;$('importCameraPlaceholder').hidden=true;$('importScanGuides').hidden=false;
    $('importCameraStatus').textContent='Kamera aktiv. TOTP- oder Google-QR-Code in den Rahmen halten.';
    currentError('');
    let detectorErrors=0,lastMessage='';
    const scan=async()=>{
      if(!cameraLive(state,run))return;
      try{
        if(video.readyState>=2&&video.videoWidth>0){
          const results=await detector.detect(video);
          if(!cameraLive(state,run))return;
          detectorErrors=0;
          let accepted=0;
          for(const item of results){
            if(!item.rawValue)continue;
            try{addResult(state,root.AuthFormats.parseQrText(item.rawValue));accepted++;}
            catch(error){const message=errorMessage(error);if(message!==lastMessage){lastMessage=message;$('importCameraStatus').textContent=message;}}
          }
          if(accepted){stopCamera(state);renderPreview(state);return;}
        }
      }catch(error){
        detectorErrors++;
        if(detectorErrors>=3){stopCamera(state,'QR-Erkennung angehalten.');currentError('Die native QR-Erkennung konnte das Kamerabild nicht lesen. Versuche ein QR-Bild oder den URI-Import.');return;}
      }
      if(cameraLive(state,run))state.timer=setTimeout(scan,250);
    };
    scan();
  }
  function playbackFailed(state,run,error) {
    if(!cameraLive(state,run))return;
    state.playbackPending=false;
    if(error?.name==='NotAllowedError') {
      // Camera capture is already authorized. Keep its stream for a direct user-
      // gesture retry; a playback policy rejection is not a camera denial.
      const button=$('importStartCamera');
      N().setBusy(button,false);button.hidden=false;button.innerHTML=ico('camera')+'Kameravorschau starten';
      state.video.controls=true;
      $('importStopCamera').hidden=false;$('importCameraPlaceholder').hidden=true;$('importScanGuides').hidden=true;
      $('importCameraStatus').textContent='Kamera erlaubt · Wiedergabe durch den Browser blockiert.';
      currentError('Die Kamera ist freigegeben, aber der Browser blockiert die Wiedergabe des Kamerabilds (Autoplay). Klicke auf „Kameravorschau starten“ oder auf Wiedergabe im Kamerabild. Falls die Vorschau weiter blockiert bleibt, erlaube Autoplay für diese Website in den Browser-Einstellungen.');
      return;
    }
    stopCamera(state,'Kameravorschau nicht verfügbar.');
    currentError('Die Kamera wurde freigegeben, aber die Vorschau konnte nicht gestartet werden. '+errorMessage(error));
  }
  function playCamera(state,run) {
    if(!cameraLive(state,run)||!state.stream||!state.video||state.playbackPending)return;
    state.playbackPending=true;
    N().setBusy($('importStartCamera'),true,'Vorschau startet …');
    currentError('');
    let playback;
    // Keep this call synchronous, before any await, so clicking the retry button
    // supplies the browser's transient user activation to HTMLMediaElement.play.
    try { playback=state.video.play(); }
    catch(error){playbackFailed(state,run,error);return;}
    Promise.resolve(playback).then(()=>{
      if(!cameraLive(state,run))return;
      state.playbackPending=false;cameraPlaying(state,run);
    },error=>playbackFailed(state,run,error));
  }
  async function startCamera(state) {
    if(!live(state)||state.working||state.tab!=='camera'||state.stage!=='input')return;
    if(state.stream){playCamera(state,state.cameraRun);return;}
    stopCamera(state);
    const run=state.cameraRun;
    const button=$('importStartCamera');
    N().setBusy(button,true,'Kamera startet …');
    currentError('');
    try{
      if(!root.isSecureContext)throw new Error('Kamerazugriff benötigt HTTPS oder localhost. Öffne die App über eine sichere Adresse.');
      await getDetector(state);
      if(!cameraLive(state,run))return;
      if(!navigator.mediaDevices?.getUserMedia)throw new Error('In diesem Browser ist kein Kamerazugriff verfügbar. Lade ein QR-Bild hoch oder füge eine URI ein.');
      let stream;
      try {
        stream=await navigator.mediaDevices.getUserMedia({video:{facingMode:{ideal:'environment'},width:{ideal:1280},height:{ideal:720}},audio:false});
      } catch(error) {
        if(cameraLive(state,run)){stopCamera(state,'Kamera nicht verfügbar.');currentError(cameraAccessError(error));}
        return;
      }
      if(!cameraLive(state,run)){for(const track of stream.getTracks())track.stop();return;}
      const video=$('importVideo');
      state.video=video;state.stream=stream;
      video.muted=true;video.defaultMuted=true;video.playsInline=true;
      video.setAttribute('muted','');video.setAttribute('playsinline','');
      state.onCameraPlaying=()=>cameraPlaying(state,run);
      video.addEventListener('playing',state.onCameraPlaying);
      video.srcObject=stream;
      $('importStopCamera').hidden=false;
      playCamera(state,run);
    }catch(error){if(cameraLive(state,run)){stopCamera(state,'Kamera nicht verfügbar.');currentError(errorMessage(error));}}
    finally{if(cameraLive(state,run)&&!state.stream)N().setBusy(button,false);}
  }
  function loadImage(state,file) {
    return new Promise((resolve,reject)=>{
      const url=URL.createObjectURL(file),img=new Image();
      let settled=false;
      const finish=(error)=>{
        if(settled)return;settled=true;
        clearTimeout(timeout);URL.revokeObjectURL(url);
        img.onload=null;img.onerror=null;
        state.abort.signal.removeEventListener('abort',onAbort);
        if(error){img.src='';reject(error);}else resolve(img);
      };
      const onAbort=()=>finish(new DOMException('Import geschlossen','AbortError'));
      const timeout=setTimeout(()=>finish(new Error('Das Bild konnte nicht rechtzeitig gelesen werden. Bitte ein kleineres PNG- oder JPG-Bild verwenden.')),15000);
      state.abort.signal.addEventListener('abort',onAbort,{once:true});
      img.onload=()=>{
        const width=img.naturalWidth,height=img.naturalHeight;
        if(!Number.isFinite(width)||!Number.isFinite(height)||width<1||height<1||width>16000||height>16000||width*height>MAX_PIXELS)finish(new Error('Das QR-Bild ist zu groß. Bitte auf höchstens 32 Megapixel und 16.000 Pixel pro Seite verkleinern.'));
        else finish();
      };
      img.onerror=()=>finish(new Error('Dieses Bildformat konnte nicht gelesen werden. Bitte einen QR-Code als PNG, JPG oder WebP verwenden.'));
      img.src=url;
      if(state.abort.signal.aborted)onAbort();
    });
  }
  async function readImage(state,file,detector) {
    if(file.size>MAX_IMAGE)throw new Error('Das QR-Bild überschreitet 15 MB. Bitte ein kleineres Bild verwenden.');
    if(file.size===0)throw new Error('Die Bilddatei ist leer.');
    if(file.type==='image/svg+xml'||/\.svgz?$/i.test(file.name)||(!/^image\/(png|jpeg|webp|gif|bmp|avif|x-ms-bmp)$/i.test(file.type)&&!(/\.(png|jpe?g|webp|gif|bmp|avif)$/i.test(file.name)&&!file.type)))throw new Error('Bitte ein QR-Bild als PNG, JPG, WebP, GIF, BMP oder AVIF auswählen.');
    const img=await loadImage(state,file);
    const canvas=document.createElement('canvas');
    try{
      if(!live(state))return [];
      const width=img.naturalWidth,height=img.naturalHeight;
      let results=[];
      for(const max of [2048,4096]){
        const scale=Math.min(1,max/Math.max(width,height));
        canvas.width=Math.max(1,Math.round(width*scale));canvas.height=Math.max(1,Math.round(height*scale));
        const context=canvas.getContext('2d',{willReadFrequently:true});
        if(!context)throw new Error('Dieses Bild konnte nicht für die QR-Erkennung vorbereitet werden.');
        context.fillStyle='#fff';context.fillRect(0,0,canvas.width,canvas.height);context.drawImage(img,0,0,canvas.width,canvas.height);
        results=await detector.detect(canvas);
        if(!live(state))return [];
        if(results.length||Math.max(width,height)<=2048)break;
      }
      if(!results.length)throw new Error('In diesem Bild wurde kein QR-Code erkannt. Bitte einen scharfen, vollständigen QR-Code mit hellem Rand verwenden.');
      return results;
    }finally{img.src='';canvas.width=canvas.height=0;}
  }
  async function readJSON(state,file) {
    if(file.size>MAX_JSON)throw new Error('Die JSON-Datei überschreitet 8 MB.');
    if(!file.size)throw new Error('Die JSON-Datei ist leer.');
    let parsed;
    try{parsed=JSON.parse((await file.text()).replace(/^\uFEFF/,''));}
    catch(_){throw new Error('Diese Datei enthält kein gültiges JSON. Bitte eine unveränderte export.json oder export.enc.json auswählen.');}
    if(!live(state))return null;
    if(parsed&&typeof parsed==='object'&&parsed.format===root.AuthCore.FORMAT){
      return {encrypted:root.AuthCore.validateEnvelope(parsed),name:file.name};
    }
    return {vault:root.AuthCore.validateVault(parsed)};
  }
  async function processFiles(state,files,source) {
    if(!live(state)||state.working||!files.length)return;
    currentError('');
    stopCamera(state);
    if(files.length>100){currentError('Bitte höchstens 100 Bilder auf einmal auswählen.');return;}
    if(source==='json'&&files.length!==1){currentError('Bitte jeweils eine JSON-Datei importieren.');return;}
    const errors=[];
    let accepted=0;
    setWorking(state,true);
    const loading=document.createElement('p');loading.className='import-loading';loading.setAttribute('role','status');loading.textContent='Datei wird lokal eingelesen …';$('importContent').append(loading);
    try{
      if(source==='json'){
        const result=await readJSON(state,files[0]);
        if(!live(state)||!result)return;
        if(result.encrypted){state.pendingEncrypted=result;setWorking(state,false);renderPassword(state);return;}
        addResult(state,{accounts:result.vault.accounts,skipped:[],batch:null,warnings:[]});accepted++;
      }else{
        const detector=await getDetector(state);
        if(!live(state))return;
        for(let i=0;i<files.length;i++){
          if(!live(state))return;
          loading.textContent='Bild '+(i+1)+' von '+files.length+' wird lokal gelesen …';
          try{
            const codes=await readImage(state,files[i],detector);
            if(!live(state))return;
            let imageAccepted=0,lastError='';
            for(const code of codes){
              try{addResult(state,root.AuthFormats.parseQrText(code.rawValue));imageAccepted++;accepted++;}
              catch(error){lastError=errorMessage(error);}
            }
            if(!imageAccepted)errors.push((files.length>1?files[i].name+': ':'')+(lastError||'Kein unterstützter TOTP-Code gefunden.'));
            else if(lastError)errors.push((files.length>1?files[i].name+': ':'')+lastError);
          }catch(error){if(error?.name!=='AbortError')errors.push((files.length>1?files[i].name+': ':'')+errorMessage(error));}
        }
      }
      if(live(state)){
        setWorking(state,false);
        if(accepted)renderPreview(state);
        if(errors.length)currentError(errors.join('\n'));
      }
    }catch(error){if(live(state))currentError(errorMessage(error));}
    finally{if(live(state)){setWorking(state,false);loading.remove();}}
  }
  function renderPassword(state) {
    if(!live(state)||!state.pendingEncrypted)return;
    state.stage='password';
    const filename=state.pendingEncrypted.name;
    $('importContent').innerHTML='<h3 class="import-preview-title">Verschlüsseltes Backup</h3><p class="import-selection">' + esc(filename) + '</p>' + notice('Gib das Passwort ein, das beim Export dieser Datei gewählt wurde. Dein Tresor-Passwort wird dadurch nicht geändert.') + '<form id="importDecryptForm" style="margin-top:20px"><div class="field"><label for="importFilePassword">Passwort der Export-Datei</label><input id="importFilePassword" type="password" autocomplete="off" maxlength="1024" required placeholder="Export-Passwort"></div><button id="importDecrypt" class="btn primary full" type="submit">' + ico('key') + 'Backup entschlüsseln</button></form>';
    $('importActions').innerHTML='<button class="btn" id="importOtherFile" type="button">Andere Datei wählen</button>';
    $('importOtherFile').addEventListener('click',()=>{if(!state.working)selectTab(state,'json');});
    renderDraft(state);
    $('importDecryptForm').addEventListener('submit',async event=>{
      event.preventDefault();
      if(!live(state)||state.working)return;
      const button=$('importDecrypt'),passwordInput=$('importFilePassword');
      const envelope=state.pendingEncrypted.encrypted;
      let password=passwordInput.value;
      setWorking(state,true,button,'Entschlüsseln …');$('importOtherFile').disabled=true;passwordInput.disabled=true;currentError('');
      try{
        const result=await root.AuthCore.unlockEnvelope(envelope,password);
        if(!live(state))return;
        addResult(state,{accounts:result.vault.accounts,skipped:[],batch:null,warnings:[]});
        passwordInput.value='';password='';
        state.pendingEncrypted=null;
        setWorking(state,false);renderPreview(state);
      }catch(error){if(live(state)){currentError(errorMessage(error));passwordInput.value='';}}
      finally{
        password='';
        if(live(state)&&state.stage==='password'){setWorking(state,false,button);passwordInput.disabled=false;$('importOtherFile').disabled=false;passwordInput.focus();}
      }
    });
    $('importFilePassword').focus();
  }
  root.ImportUI=Object.freeze({open});
})(globalThis);
