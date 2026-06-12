/**
 * Demo TURN — serverless edition
 *
 * No backend. Two browsers connect directly over a WebRTC DataChannel.
 * The only handshake is a one-time manual copy-paste of short codes.
 * Files are AES-GCM encrypted, chunked, padded with dummy chunks and
 * shuffled locally before being sent — the data never passes through any
 * server (TURN is only used to relay the already-encrypted stream when a
 * direct connection is impossible).
 */

'use strict';

// ═══════════════════════ CONFIG ═════════════════════════════
// Many free servers that back each other up — the browser tries them all and
// picks whichever works.
//
// STUN  = free, plentiful, no signup, but ONLY helps find a direct path; it
//         does NOT relay data. More of them = higher chance of connecting.
// TURN  = relays data when a direct connection fails. Free TURN is rare.
//         No-signup free TURN is basically only freestun.net.
const ICE_SERVERS = [
    // ── STUN (free, no signup) ───────────────────────────────
    { urls: 'stun:stun.l.google.com:19302' },
    { urls: 'stun:stun1.l.google.com:19302' },
    { urls: 'stun:stun2.l.google.com:19302' },
    { urls: 'stun:stun3.l.google.com:19302' },
    { urls: 'stun:stun4.l.google.com:19302' },
    { urls: 'stun:stun.cloudflare.com:3478' },
    { urls: 'stun:stun.relay.metered.ca:80' },
    { urls: 'stun:stun.freestun.net:3478' },
    // Hourly-refreshed list of live STUN servers (add more if needed):
    //   https://github.com/pradt2/always-online-stun

    // ── TURN (free, NO signup) ───────────────────────────────
    // freestun.net — shared 'free'/'free' credentials. Best-effort, may be slow.
    { urls: 'turn:freestun.net:3478', username: 'free', credential: 'free' },
    { urls: 'turns:freestun.net:5350', username: 'free', credential: 'free' }, // TLS, better at traversing firewalls

    // ── TURN (free but requires a free signup for credentials) ──
    // Sign up once, paste the credentials here for a more reliable relay.
    // Each source backs up the others — fill in whichever you have.
    //
    // 1) ExpressTURN — free 1000 GB/month. https://www.expressturn.com/
    // { urls: 'turn:relay1.expressturn.com:3478', username: 'YOUR_USER', credential: 'YOUR_PASS' },
    //
    // 2) Metered Open Relay — free tier. https://www.metered.ca/tools/openrelay/
    // { urls: 'turn:standard.relay.metered.ca:80',  username: 'YOUR_USER', credential: 'YOUR_PASS' },
    // { urls: 'turn:standard.relay.metered.ca:443', username: 'YOUR_USER', credential: 'YOUR_PASS' },
    // { urls: 'turns:standard.relay.metered.ca:443?transport=tcp', username: 'YOUR_USER', credential: 'YOUR_PASS' },
];

const CHUNK = 16 * 1024;          // 16 KB plaintext — safe DataChannel message size
const DUMMY_RATIO = 0.25;         // anti-tracking: extra fake chunks
const BUF_HIGH = 8 * 1024 * 1024; // backpressure: pause when send buffer > 8 MB
const BUF_LOW = 1 * 1024 * 1024;  // resume when drained below 1 MB
const ICE_TIMEOUT = 8000;         // ms to wait for ICE gathering before encoding
const FAIL_GRACE = 6000;          // ms to wait on 'disconnected' before declaring failure

// ═══════════════════════ STATE ══════════════════════════════
let pc = null, dc = null;
let isInitiator = false;
let wasConnected = false, failed = false, failTimer = null;
let diag = { host: 0, srflx: 0, relay: 0, prflx: 0, errors: [] };
let dirHandle = null;
let myFolderReady = false, peerFolderReady = false;
let syncReady = false, cryptoReady = false, isTransferring = false;
let myECDHKey = null, sharedAESKey = null, ecdhDerived = false;

const uploads = new Map();
const downloads = new Map();

// ═══════════════════════ DOM HELPERS ════════════════════════
const $ = id => document.getElementById(id);
function showPage(id) { document.querySelectorAll('.page').forEach(p => p.classList.remove('active')); $(id).classList.add('active'); }
function setConn(state, text) { const p = $('conn-pill'); p.className = `conn-pill ${state}`; $('conn-text').textContent = text; }

function toast(msg, type = 'info', dur = 3500) {
    const el = document.createElement('div');
    el.className = `toast ${type}`;
    el.textContent = msg;
    $('toasts').appendChild(el);
    setTimeout(() => el.remove(), dur);
}
function fmtSize(b) {
    if (b < 1024) return b + ' B';
    if (b < 1048576) return (b / 1024).toFixed(1) + ' KB';
    if (b < 1073741824) return (b / 1048576).toFixed(1) + ' MB';
    return (b / 1073741824).toFixed(2) + ' GB';
}

// ═══════════════════════ CODE ENCODING ══════════════════════
// Compact, robust short codes. We strip the SDP down to the few variable
// fields, gzip them, and base64url the result. The full SDP is rebuilt from
// a fixed DataChannel template on the other side.
function b64urlEncode(bytes) {
    let s = '';
    for (const b of bytes) s += String.fromCharCode(b);
    return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function b64urlDecode(str) {
    str = str.replace(/-/g, '+').replace(/_/g, '/');
    const bin = atob(str);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
}
async function gzip(str) {
    if (!('CompressionStream' in window)) return 'r' + b64urlEncode(new TextEncoder().encode(str));
    const cs = new CompressionStream('gzip');
    const w = cs.writable.getWriter(); w.write(new TextEncoder().encode(str)); w.close();
    const buf = await new Response(cs.readable).arrayBuffer();
    return 'g' + b64urlEncode(new Uint8Array(buf));
}
async function gunzip(code) {
    const tag = code[0], body = code.slice(1);
    const bytes = b64urlDecode(body);
    if (tag === 'r') return new TextDecoder().decode(bytes);
    const ds = new DecompressionStream('gzip');
    const w = ds.writable.getWriter(); w.write(bytes); w.close();
    const buf = await new Response(ds.readable).arrayBuffer();
    return new TextDecoder().decode(buf);
}

const CAND_TYPES = ['host', 'srflx', 'relay', 'prflx'];
const CAND_PRIO = [2122260223, 1686052607, 41885439, 1862270975];

function packSDP(desc) {
    const sdp = desc.sdp;
    const grab = re => (sdp.match(re) || [])[1] || '';
    // Reduce each candidate to [type, ip, port]. Drop the long foundation/
    // priority/raddr fields (rebuilt by the receiver) and drop non-relay TCP
    // candidates → much shorter code.
    const seen = new Set();
    const c = [];
    for (const m of sdp.matchAll(/a=candidate:\S+ \d+ (\S+) \d+ (\S+) (\d+) typ (\S+)/g)) {
        const transport = m[1].toLowerCase(), ip = m[2], port = +m[3], type = m[4];
        if (transport !== 'udp' && type !== 'relay') continue; // drop non-relay tcp
        const key = type + '|' + ip + '|' + port;
        if (seen.has(key)) continue;
        seen.add(key);
        c.push([Math.max(0, CAND_TYPES.indexOf(type)), ip, port]);
    }
    return {
        t: desc.type === 'offer' ? 'o' : 'a',
        u: grab(/a=ice-ufrag:(\S+)/),
        p: grab(/a=ice-pwd:(\S+)/),
        f: grab(/a=fingerprint:sha-256 (\S+)/),
        c,
    };
}
function unpackSDP(o) {
    const type = o.t === 'o' ? 'offer' : 'answer';
    const setup = o.t === 'o' ? 'actpass' : 'active';
    const cands = (o.c || []).map(([tc, ip, port], i) => {
        let line = `candidate:${i + 1} 1 udp ${CAND_PRIO[tc] || 1} ${ip} ${port} typ ${CAND_TYPES[tc] || 'host'}`;
        if (tc > 0) line += ' raddr 0.0.0.0 rport 0'; // srflx/relay need a rel-addr
        return 'a=' + line;
    });
    const lines = [
        'v=0',
        'o=- 0 0 IN IP4 0.0.0.0',
        's=-',
        't=0 0',
        'a=group:BUNDLE 0',
        'm=application 9 UDP/DTLS/SCTP webrtc-datachannel',
        'c=IN IP4 0.0.0.0',
        'a=mid:0',
        'a=sctp-port:5000',
        'a=max-message-size:262144',
        'a=ice-ufrag:' + o.u,
        'a=ice-pwd:' + o.p,
        'a=fingerprint:sha-256 ' + o.f,
        'a=setup:' + setup,
        ...cands,
    ];
    return { type, sdp: lines.join('\r\n') + '\r\n' };
}
function warnIfNoRelay() {
    console.log('[ICE] gathered for code →', candSummary());
    if (diag.relay === 0)
        toast('⚠️ No TURN relay gathered — connecting across different networks may fail', 'warn', 6000);
}
async function encodeDesc(desc) { return gzip(JSON.stringify(packSDP(desc))); }
async function decodeDesc(code) { return unpackSDP(JSON.parse(await gunzip(code.trim()))); }

// ═══════════════════════ WEBRTC ═════════════════════════════
function candSummary() { return `host=${diag.host} srflx=${diag.srflx} relay=${diag.relay} prflx=${diag.prflx}`; }

function newPeer(initiator) {
    isInitiator = initiator;
    wasConnected = false; failed = false; clearTimeout(failTimer);
    diag = { host: 0, srflx: 0, relay: 0, prflx: 0, errors: [] };
    pc = new RTCPeerConnection({ iceServers: ICE_SERVERS });

    // ── Diagnostics: which candidate types we manage to gather ──
    pc.onicecandidate = e => {
        if (!e.candidate) { console.log('[ICE] gathering complete →', candSummary()); return; }
        const t = (e.candidate.candidate.match(/ typ (\S+)/) || [])[1] || 'unknown';
        if (t in diag) diag[t]++;
        console.log(`[ICE] candidate (${t}): ${e.candidate.candidate}`);
    };
    // ── Diagnostics: STUN/TURN server errors (e.g. 401 = bad TURN creds) ──
    pc.onicecandidateerror = e => {
        diag.errors.push({ url: e.url, code: e.errorCode, text: e.errorText });
        console.warn(`[ICE] candidate error: code=${e.errorCode} "${e.errorText}" @ ${e.url}`);
    };
    pc.oniceconnectionstatechange = () => console.log('[ICE] iceConnectionState =', pc.iceConnectionState);
    pc.onicegatheringstatechange = () => console.log('[ICE] iceGatheringState =', pc.iceGatheringState);
    pc.onconnectionstatechange = () => handleConnState(pc.connectionState);

    if (initiator) setupDC(pc.createDataChannel('file', { ordered: true }));
    else pc.ondatachannel = e => setupDC(e.channel);
    return pc;
}

function setupDC(channel) {
    dc = channel;
    dc.binaryType = 'arraybuffer';
    dc.onopen = onConnected;
    dc.onclose = () => surfaceFailure('closed');
    dc.onmessage = e => {
        if (typeof e.data === 'string') handleControl(JSON.parse(e.data));
        else handleBinary(e.data);
    };
}

// ── Connection state machine: tolerate transient drops, surface real failures ──
function handleConnState(s) {
    console.log('[PC]', s, '|', candSummary());
    if (s === 'connected') {
        wasConnected = true; failed = false; clearTimeout(failTimer);
        setConn('ok', 'Connected');
    } else if (s === 'disconnected') {
        // Transient — WebRTC often self-heals. Wait before declaring failure.
        setConn('warn', 'Connection lost — trying to recover...');
        clearTimeout(failTimer);
        failTimer = setTimeout(() => {
            if (pc && pc.connectionState !== 'connected') surfaceFailure('disconnected');
        }, FAIL_GRACE);
    } else if (s === 'failed') {
        surfaceFailure('failed');
    } else if (s === 'closed') {
        surfaceFailure('closed');
    }
}

// ── Turn a raw failure into a human-readable cause ──
function diagnose() {
    const authErr = diag.errors.find(e => e.code === 401 || e.code === 403);
    if (authErr)
        return `A TURN server rejected the credentials (HTTP ${authErr.code}). The free TURN is likely down or its credentials changed — add a working TURN server in ICE_SERVERS.`;
    if (diag.srflx === 0 && diag.relay === 0)
        return 'Could not reach any STUN or TURN server. Check the internet connection / firewall on both devices.';
    if (diag.relay === 0)
        return 'Direct connection failed and no TURN relay was available — likely a strict/symmetric NAT while the free TURN server was unreachable. Add a working TURN server (e.g. ExpressTURN) in ICE_SERVERS.';
    return 'Direct connection failed and even the TURN relay did not work — the relay may be overloaded or blocked. Try a different TURN server, then try again.';
}

function surfaceFailure(reason) {
    if (failed) return;
    failed = true;
    clearTimeout(failTimer);

    const peerClosed = reason === 'closed' && wasConnected;
    setConn('err', peerClosed ? 'Disconnected' : 'Connection failed');

    if (peerClosed) {
        $('disc-title').textContent = '⚠️ Disconnected';
        $('disc-msg').textContent = 'The other device disconnected.';
        $('disc-diag').hidden = true;
    } else {
        $('disc-title').textContent = '❌ Connection failed';
        $('disc-msg').textContent = diagnose();
        const tech = `Reason: ${reason}\n`
            + `ICE state: ${pc?.iceConnectionState}\n`
            + `Candidates gathered: ${candSummary()}\n`
            + (diag.errors.length
                ? 'STUN/TURN errors:\n' + diag.errors.map(e => `  • [${e.code}] ${e.text || ''} @ ${e.url}`).join('\n')
                : 'No STUN/TURN errors reported.');
        const dg = $('disc-diag');
        dg.textContent = tech;
        dg.hidden = false;
        console.warn('[PC] failure diagnostics:\n' + tech);
    }
    $('disc-ov').hidden = false;
}

function waitIce(pc) {
    return new Promise(resolve => {
        if (pc.iceGatheringState === 'complete') return resolve();
        const done = () => { clearTimeout(t); pc.removeEventListener('icegatheringstatechange', check); resolve(); };
        const check = () => { if (pc.iceGatheringState === 'complete') done(); };
        const t = setTimeout(done, ICE_TIMEOUT);
        pc.addEventListener('icegatheringstatechange', check);
    });
}

function sendCtrl(obj) { if (dc?.readyState === 'open') dc.send(JSON.stringify(obj)); }

function onConnected() {
    console.log('[DC] open');
    showPage('page-room');
    setConn('ok', 'Connected');
    toast('🔗 Connected! Setting up encryption...', 'success');
    initECDH();
}

// ═══════════════════════ CONNECT UI FLOW ════════════════════
async function startCreate() {
    $('choose').hidden = true;
    $('create-flow').hidden = false;
    setConn('warn', 'Generating code...');
    try {
        newPeer(true);
        const offer = await pc.createOffer();
        await pc.setLocalDescription(offer);
        await waitIce(pc);
        $('my-offer').value = await encodeDesc(pc.localDescription);
        warnIfNoRelay();
        setConn('warn', 'Waiting for reply code...');
    } catch (e) { toast('Error creating code: ' + e.message, 'error', 6000); }
}

async function finishCreate() {
    const code = $('their-answer').value.trim();
    if (!code) return toast('Paste the reply code first!', 'error');
    try {
        await pc.setRemoteDescription(await decodeDesc(code));
        $('btn-finish').disabled = true;
        $('btn-finish').textContent = 'Connecting...';
        setConn('warn', 'Connecting...');
    } catch (e) { toast('Invalid reply code', 'error'); console.error(e); }
}

function startJoin() {
    $('choose').hidden = true;
    $('join-flow').hidden = false;
}

async function makeAnswer() {
    const code = $('their-offer').value.trim();
    if (!code) return toast('Paste the code from Device A first!', 'error');
    setConn('warn', 'Generating reply code...');
    try {
        newPeer(false);
        await pc.setRemoteDescription(await decodeDesc(code));
        const ans = await pc.createAnswer();
        await pc.setLocalDescription(ans);
        await waitIce(pc);
        $('my-answer').value = await encodeDesc(pc.localDescription);
        warnIfNoRelay();
        $('answer-out').hidden = false;
        $('btn-answer').disabled = true;
        setConn('warn', 'Waiting for connection...');
    } catch (e) { toast('Invalid code', 'error'); console.error(e); }
}

// ═══════════════════════ ECDH ═══════════════════════════════
async function initECDH() {
    $('crypto-msg').textContent = 'Generating ECDH key...';
    if (!window.crypto?.subtle) {
        $('crypto-msg').textContent = '❌ HTTPS is required for encryption';
        return toast('crypto.subtle unavailable — HTTPS required!', 'error', 8000);
    }
    try {
        myECDHKey = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveKey']);
        const raw = await crypto.subtle.exportKey('raw', myECDHKey.publicKey);
        const pubB64 = btoa(String.fromCharCode(...new Uint8Array(raw)));
        sendCtrl({ type: 'ecdh', pubkey: pubB64 });
        $('crypto-msg').textContent = 'Public key sent, waiting for peer...';
    } catch (e) { $('crypto-msg').textContent = '❌ Key generation error: ' + e.message; }
}

async function deriveSharedKey(peerPub64) {
    if (ecdhDerived) return;
    ecdhDerived = true;
    try {
        const raw = Uint8Array.from(atob(peerPub64), c => c.charCodeAt(0));
        const pub = await crypto.subtle.importKey('raw', raw, { name: 'ECDH', namedCurve: 'P-256' }, false, []);
        sharedAESKey = await crypto.subtle.deriveKey(
            { name: 'ECDH', public: pub }, myECDHKey.privateKey,
            { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
        cryptoReady = true;
        $('crypto-msg').textContent = '🔒 AES-GCM 256-bit — secure channel ready';
        $('enc-badge').style.display = 'inline';
        checkSync();
    } catch (e) { ecdhDerived = false; $('crypto-msg').textContent = '❌ deriveKey error: ' + e.message; }
}

// ═══════════════════════ CRYPTO HELPERS ═════════════════════
async function encryptChunk(plain) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, sharedAESKey, plain);
    const out = new Uint8Array(12 + ct.byteLength);
    out.set(iv); out.set(new Uint8Array(ct), 12);
    return out;
}
async function decryptChunk(raw) {
    const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: raw.slice(0, 12) }, sharedAESKey, raw.slice(12));
    return new Uint8Array(pt);
}
function buildFrame(dummy, idx, enc) {
    const b = new ArrayBuffer(5 + enc.byteLength), v = new DataView(b);
    v.setUint8(0, dummy ? 1 : 0); v.setUint32(1, idx, false);
    new Uint8Array(b, 5).set(enc);
    return b;
}
function parseFrame(b) {
    const v = new DataView(b);
    return { isDummy: (v.getUint8(0) & 1) === 1, idx: v.getUint32(1, false), payload: new Uint8Array(b, 5) };
}

// ═══════════════════════ FOLDER ═════════════════════════════
async function pickFolder() {
    if (!window.showDirectoryPicker) return toast('Requires Chrome or Edge!', 'error');
    try {
        dirHandle = await window.showDirectoryPicker({ mode: 'readwrite' });
        $('folder-name-lbl').textContent = `📁 ${dirHandle.name}`;
        $('folder-ok').hidden = false;
        $('my-pc').classList.add('rdy');
        $('my-folder-lbl').textContent = '✅ Ready';
        $('pick-btn').disabled = true;
        myFolderReady = true;
        sendCtrl({ type: 'folder_ready' });
        toast('📁 Folder selected. Waiting for peer...', 'info');
        checkSync();
    } catch (e) {
        if (e.name !== 'AbortError') toast('Error: ' + e.message, 'error');
    }
}

function checkSync() {
    if (peerFolderReady) { $('peer-pc').classList.add('rdy'); $('peer-folder-lbl').textContent = '✅ Ready'; }
    if (myFolderReady && peerFolderReady && !syncReady) {
        syncReady = true;
        $('sync-sec').hidden = false;
    }
    if (syncReady && cryptoReady) unlockDrop();
}

// ═══════════════════════ DROP ZONE ══════════════════════════
function unlockDrop() {
    if (!syncReady || !cryptoReady || isTransferring) return;
    $('drop-zone').classList.remove('locked');
    $('drop-label').innerHTML = '<strong>Click to choose a .zip file</strong>';
}
function lockDrop(reason) {
    $('drop-zone').classList.add('locked');
    $('drop-label').innerHTML = `<strong>${reason}</strong>`;
}
function pickFile() {
    if (!syncReady || !cryptoReady || isTransferring) return;
    $('file-input').value = '';
    $('file-input').click();
}
function onDragOver(e) { e.preventDefault(); $('drop-zone').classList.add('drag-over'); }
function onDragLeave() { $('drop-zone').classList.remove('drag-over'); }
function onDrop(e) {
    e.preventDefault(); $('drop-zone').classList.remove('drag-over');
    if (!syncReady || !cryptoReady || isTransferring) return;
    const f = e.dataTransfer.files[0];
    if (f?.name.toLowerCase().endsWith('.zip')) sendFile(f);
    else toast('Only .zip files allowed!', 'error');
}

// ═══════════════════════ FILE UPLOAD ════════════════════════
function drainBuffer() {
    return new Promise(resolve => {
        dc.bufferedAmountLowThreshold = BUF_LOW;
        const h = () => { dc.removeEventListener('bufferedamountlow', h); resolve(); };
        dc.addEventListener('bufferedamountlow', h);
    });
}

async function sendFile(file) {
    if (!syncReady || !cryptoReady) return toast('Not ready yet!', 'error');
    if (isTransferring) return toast('Transferring...', 'error');
    if (!file.name.toLowerCase().endsWith('.zip')) return toast('Only .zip!', 'error');

    isTransferring = true; lockDrop('Transferring...');

    // Save a local copy into our own folder too.
    if (dirHandle) {
        try {
            const fh = await dirHandle.getFileHandle(file.name, { create: true });
            const w = await fh.createWritable();
            await w.write(file); await w.close();
        } catch (e) { toast('Error saving to folder: ' + e.message, 'error'); isTransferring = false; unlockDrop(); return; }
    }

    const bytes = new Uint8Array(await file.arrayBuffer());
    const nReal = Math.ceil(bytes.length / CHUNK);
    const nDummy = Math.ceil(nReal * DUMMY_RATIO);
    const itemId = 'u' + Date.now();
    addTfItem(itemId, file.name, file.size, 'upload');
    uploads.set(file.name, { itemId });
    sendCtrl({ type: 'file_start', fileName: file.name, fileSize: file.size, totalReal: nReal });

    // Build all frames: real (encrypted) + dummy (random), then shuffle.
    const frames = [];
    for (let i = 0; i < nReal; i++) {
        const slice = bytes.slice(i * CHUNK, (i + 1) * CHUNK);
        frames.push({ dummy: false, idx: i, data: await encryptChunk(slice) });
    }
    const dsz = frames.length ? frames[frames.length - 1].data.byteLength : CHUNK;
    for (let d = 0; d < nDummy; d++)
        frames.push({ dummy: true, idx: nReal + d, data: crypto.getRandomValues(new Uint8Array(dsz)) });
    for (let i = frames.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [frames[i], frames[j]] = [frames[j], frames[i]];
    }

    let sent = 0;
    for (const f of frames) {
        if (dc.bufferedAmount > BUF_HIGH) await drainBuffer();
        dc.send(buildFrame(f.dummy, f.idx, f.data));
        if (!f.dummy) { sent++; updProg(itemId, Math.round(sent / nReal * 100), false); }
    }
    sendCtrl({ type: 'file_end', fileName: file.name, fileSize: file.size });
}
function markSent(name) { const i = uploads.get(name); if (i) updProg(i.itemId, 100, true); }

// ═══════════════════════ FILE DOWNLOAD ══════════════════════
function startDownload(m) {
    const id = 'd' + Date.now();
    downloads.set(m.fileName, { itemId: id, fileSize: m.fileSize, totalReal: m.totalReal, received: 0, chunks: new Map() });
    addTfItem(id, m.fileName, m.fileSize, 'download');
}
async function handleBinary(buf) {
    const { isDummy, idx, payload } = parseFrame(buf);
    if (isDummy) return;
    for (const [, info] of downloads) {
        if (info.received < info.totalReal) {
            try {
                info.chunks.set(idx, await decryptChunk(payload));
                info.received++;
                updProg(info.itemId, Math.round(info.received / info.totalReal * 100), false);
            } catch (e) { toast('Decryption error!', 'error'); console.error(e); }
            break;
        }
    }
}
async function finalizeDownload(m) {
    const info = downloads.get(m.fileName);
    if (!info || !dirHandle) return;
    const ordered = [];
    for (let i = 0; i < info.totalReal; i++) {
        const c = info.chunks.get(i);
        if (!c) return toast(`Missing chunk ${i}!`, 'error');
        ordered.push(c);
    }
    try {
        const blob = new Blob(ordered, { type: 'application/zip' });
        const fh = await dirHandle.getFileHandle(m.fileName, { create: true });
        const w = await fh.createWritable();
        await w.write(blob); await w.close();
        updProg(info.itemId, 100, true);
        toast(`✅ Received: ${m.fileName}`, 'success');
        downloads.delete(m.fileName);
        sendCtrl({ type: 'file_ack', fileName: m.fileName });
    } catch (e) { toast('Error saving: ' + e.message, 'error'); console.error(e); }
}

// ═══════════════════════ CONTROL MESSAGES ═══════════════════
function handleControl(msg) {
    switch (msg.type) {
        case 'ecdh': deriveSharedKey(msg.pubkey); break;
        case 'folder_ready':
            peerFolderReady = true;
            toast('📁 Peer selected a folder', 'info');
            checkSync();
            break;
        case 'file_start': startDownload(msg); break;
        case 'file_end': finalizeDownload(msg); isTransferring = false; unlockDrop(); break;
        case 'file_ack': markSent(msg.fileName); isTransferring = false; unlockDrop(); break;
    }
}

// ═══════════════════════ TRANSFER UI ════════════════════════
function esc(s) { return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;'); }
function addTfItem(id, name, size, dir) {
    const el = document.createElement('div');
    el.className = 'tf-item'; el.id = id;
    el.innerHTML = `
        <div class="tf-hdr">
          <div class="tf-name" title="${esc(name)}">${dir === 'upload' ? '⬆' : '⬇'} ${esc(name)}</div>
          <div class="tf-size">${fmtSize(size)}</div>
        </div>
        <div class="pbar"><div class="pfill" id="${id}-b" style="width:0%"></div></div>
        <div class="tf-meta"><span id="${id}-p">0%</span><span id="${id}-s">Transferring...</span></div>`;
    $('tf-list').prepend(el);
}
function updProg(id, pct, done) {
    const b = $(`${id}-b`); if (!b) return;
    b.style.width = pct + '%'; $(`${id}-p`).textContent = pct + '%';
    if (done) { b.classList.add('done'); $(`${id}-s`).textContent = '✅ Done'; }
}

// ═══════════════════════ WIRE UP EVENTS ═════════════════════
$('btn-create').addEventListener('click', startCreate);
$('btn-join').addEventListener('click', startJoin);
$('btn-finish').addEventListener('click', finishCreate);
$('btn-answer').addEventListener('click', makeAnswer);
$('pick-btn').addEventListener('click', pickFolder);
$('leave-btn').addEventListener('click', () => location.reload());
$('disc-btn').addEventListener('click', () => location.reload());
$('file-input').addEventListener('change', e => { const f = e.target.files[0]; if (f) sendFile(f); });

const dz = $('drop-zone');
dz.addEventListener('click', pickFile);
dz.addEventListener('dragover', onDragOver);
dz.addEventListener('dragleave', onDragLeave);
dz.addEventListener('drop', onDrop);

document.querySelectorAll('.copy-btn').forEach(btn => {
    btn.addEventListener('click', async () => {
        const ta = $(btn.dataset.copy);
        if (!ta.value) return toast('No code yet!', 'error');
        try { await navigator.clipboard.writeText(ta.value); toast('📋 Copied', 'success', 2000); }
        catch { ta.select(); document.execCommand('copy'); toast('📋 Copied', 'success', 2000); }
    });
});
