'use strict';
/*
 * Old iPhone Web Gateway
 * ----------------------
 * Run this on your PC:      node server.js
 * On the iPhone (iOS 1-6):  open Safari and go to  http://<your-PC-IP>:8106
 *
 * No proxy settings on the phone. Microsoft Edge (running hidden on the PC)
 * loads the modern website, and the phone gets either:
 *   - Live mode:   the real page streamed like a video; swipe to scroll, tap to click (default)
 *   - Modern mode: the real modern page drawn by Edge, sent as pictures you scroll and tap
 *   - Lite mode:   light, simple HTML that old Safari can show (fastest)
 *
 * Sound: tap the note button in the Live top bar (works on iOS 1 - iOS 17).
 * Shake = on/off after the first tap, screen face down = mute. Rotate and the live view follows.
 */
const http = require('http');
const os = require('os');
const fs = require('fs');
const path = require('path');
const zlib = require('zlib');
const dgram = require('dgram');
const crypto = require('crypto');
const puppeteer = require('puppeteer-core');

let sharp = null;
try { sharp = require('sharp'); } catch (e) { console.warn('[!] "sharp" is not installed - images will not be converted for old Safari.'); }

const PORT = Number(process.env.PORT) || 8106;
const VW = 360;          // width of the hidden Edge window (CSS px)
const VH = 900;          // height of the hidden Edge window
const PHONE_W = 320;     // width of the iPhone screen (CSS px)
const TILES = 8;         // the page is sent as pieces of VH height; this many at first
const SEARCH = process.env.SEARCH || 'https://html.duckduckgo.com/html/?q=';
const IDLE_MS = 30 * 60 * 1000;

/* =================================================================
   REMOTE ACCESS (away from home: mobile data / hotspot / other Wi-Fi)
   - UPnP opens this port in the router by itself, like yt_anywhere.js
   ================================================================= */
const WANT_REMOTE = !(process.env.REMOTE === '0' || String(process.env.REMOTE || '').toLowerCase() === 'false');

// DuckDNS (optional): keeps a name like yourname.duckdns.org pointed at your home IP even when it changes.
const DUCKDNS_DOMAIN = process.env.DUCKDNS_DOMAIN || '';
const DUCKDNS_TOKEN = process.env.DUCKDNS_TOKEN || '';

function isPrivateIp(ip) {
  ip = String(ip || '').replace(/^::ffff:/, '');
  if (/^(127\.|10\.|192\.168\.|169\.254\.|::1$|fe80:|f[cd])/.test(ip)) return true;
  if (/^172\.(1[6-9]|2\d|3[01])\./.test(ip)) return true;
  if (/^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\./.test(ip)) return true; // CGNAT: treat as not-internet
  return false;
}

/* ---- UPnP: open this port in the router automatically (so mobile data can reach this PC) ---- */
const upnp = {
  state: 'off', control: null, opened: [], externalIp: '', permanent: false,
  discover(lanIp) {
    return new Promise(resolve => {
      const sock = dgram.createSocket({ type: 'udp4', reuseAddr: true });
      const places = new Set(); let done = false;
      const fin = () => { if (done) return; done = true; try { sock.close(); } catch (e) {} resolve([...places]); };
      sock.on('error', fin);
      sock.on('message', msg => { const m = /^location:\s*(\S+)/im.exec(msg.toString()); if (m) places.add(m[1]); });
      sock.bind(0, lanIp, () => {
        for (const st of ['urn:schemas-upnp-org:device:InternetGatewayDevice:1', 'urn:schemas-upnp-org:device:InternetGatewayDevice:2',
          'urn:schemas-upnp-org:service:WANIPConnection:1', 'urn:schemas-upnp-org:service:WANPPPConnection:1']) {
          const q = `M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: "ssdp:discover"\r\nMX: 2\r\nST: ${st}\r\n\r\n`;
          try { sock.send(Buffer.from(q), 1900, '239.255.255.250'); } catch (e) {}
        }
      });
      setTimeout(fin, 3500);
    });
  },
  async findControl(place) {
    const r = await fetch(place, { signal: AbortSignal.timeout(5000) });
    const xml = await r.text();
    const base = (/<URLBase>\s*([^<\s]+)\s*<\/URLBase>/i.exec(xml) || [])[1] || place;
    for (const block of xml.match(/<service>[\s\S]*?<\/service>/gi) || []) {
      const type = ((/<serviceType>([^<]+)</i.exec(block) || [])[1] || '').trim();
      const ctrl = ((/<controlURL>([^<]+)</i.exec(block) || [])[1] || '').trim();
      if (ctrl && /:WAN(IP|PPP)Connection:/i.test(type)) return { type, url: new URL(ctrl, base).href };
    }
    return null;
  },
  async soap(action, args) {
    const inner = Object.entries(args).map(([k, v]) => `<${k}>${v}</${k}>`).join('');
    const xml = '<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" ' +
      's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body>' +
      `<u:${action} xmlns:u="${this.control.type}">${inner}</u:${action}></s:Body></s:Envelope>`;
    const r = await fetch(this.control.url, { method: 'POST', body: xml, signal: AbortSignal.timeout(6000),
      headers: { 'Content-Type': 'text/xml; charset="utf-8"', SOAPAction: `"${this.control.type}#${action}"` } });
    return { ok: r.ok, text: await r.text() };
  },
  map(port, lanIp, lease) {
    return this.soap('AddPortMapping', { NewRemoteHost: '', NewExternalPort: port, NewProtocol: 'TCP',
      NewInternalPort: port, NewInternalClient: lanIp, NewEnabled: 1, NewPortMappingDescription: 'OldWeb gateway', NewLeaseDuration: lease });
  },
  async open(lanIp, port) {
    try {
      const places = await this.discover(lanIp);
      for (const p of places) { try { this.control = await this.findControl(p); } catch (e) { this.control = null; } if (this.control) break; }
      if (!this.control) { this.state = 'no UPnP (turn on UPnP in the router, or forward the port by hand)'; return; }
      let r = await this.map(port, lanIp, 7200);
      if (!r.ok && /\b725\b|OnlyPermanentLeasesSupported/i.test(r.text)) { this.permanent = true; r = await this.map(port, lanIp, 0); }
      if (r.ok) this.opened.push(port);
      try { const g = await this.soap('GetExternalIPAddress', {}); this.externalIp = (/<NewExternalIPAddress>([^<]*)</i.exec(g.text) || [])[1] || ''; } catch (e) {}
      if (this.opened.length) {
        this.state = `port ${port} open -> ${lanIp}` + (this.externalIp ? ` (internet IP ${this.externalIp})` : '');
        if (isPrivateIp(this.externalIp)) this.state += '  !! this looks like CGNAT - mobile data may NOT reach you';
        if (!this.permanent) setInterval(() => this.map(port, lanIp, 7200).catch(() => {}), 60 * 60 * 1000).unref();
      } else this.state = 'router refused to open the port';
    } catch (e) { this.state = 'error: ' + e.message; }
  },
  async close() { for (const port of this.opened) { try { await this.soap('DeletePortMapping', { NewRemoteHost: '', NewExternalPort: port, NewProtocol: 'TCP' }); } catch (e) {} } },
};

async function duckdnsUpdate() {
  if (!DUCKDNS_DOMAIN || !DUCKDNS_TOKEN) return;
  try {
    const r = await fetch(`https://www.duckdns.org/update?domains=${DUCKDNS_DOMAIN}&token=${DUCKDNS_TOKEN}&ip=`, { signal: AbortSignal.timeout(8000) });
    const t = (await r.text()).trim();
    console.log(`  DuckDNS ${DUCKDNS_DOMAIN}.duckdns.org update: ${t}`);
  } catch (e) { console.log('  DuckDNS update failed: ' + e.message); }
}

/* ---- your home internet address (the .deb learns it at home and uses it on mobile data) ---- */
let extIp = '';
async function refreshExtIp() {
  if (!WANT_REMOTE) return;
  try {
    if (upnp.control) {
      const g = await upnp.soap('GetExternalIPAddress', {});
      const v = (/<NewExternalIPAddress>([^<]*)</i.exec(g.text) || [])[1] || '';
      if (v && !isPrivateIp(v)) { extIp = v; return; }
    }
  } catch (e) {}
  try {
    const r = await fetch('https://api.ipify.org', { signal: AbortSignal.timeout(6000) });
    const v = (await r.text()).trim();
    if (/^\d+\.\d+\.\d+\.\d+$/.test(v)) extIp = v;
  } catch (e) {}
}

/* ---- oldweb.local: the iPhone finds this PC by name on any Wi-Fi / hotspot (mDNS / Bonjour) ---- */
const MDNS_NAME = (process.env.MDNS_NAME || 'oldweb').toLowerCase() + '.local';
const ip4 = (s) => s.split('.').reduce((n, o) => ((n << 8) | (+o & 255)) >>> 0, 0);
function lanAddrs() {
  const out = [];
  for (const list of Object.values(os.networkInterfaces())) for (const a of list || []) if (a.family === 'IPv4' && !a.internal) out.push(a);
  return out;
}
function startMdns() {
  const sock = dgram.createSocket({ type: 'udp4', reuseAddr: true });
  const joined = new Set(), sendQ = [];
  let sending = false, ok = false;
  const pump = () => { // one send at a time, each out of the right network card
    if (sending || !sendQ.length) return;
    sending = true;
    const [buf, port, addr, iface] = sendQ.shift();
    try { if (iface) sock.setMulticastInterface(iface); } catch (e) {}
    sock.send(buf, port, addr, () => { sending = false; pump(); });
  };
  const queue = (...a) => { sendQ.push(a); pump(); };
  const nameBuf = Buffer.concat(MDNS_NAME.split('.').map((l) => Buffer.concat([Buffer.from([l.length]), Buffer.from(l)])).concat([Buffer.from([0])]));
  function reply(ip, id, legacy) {
    const h = Buffer.alloc(12);
    h.writeUInt16BE(id, 0); h.writeUInt16BE(0x8400, 2); h.writeUInt16BE(legacy ? 1 : 0, 4); h.writeUInt16BE(1, 6);
    const rr = Buffer.alloc(10);
    rr.writeUInt16BE(1, 0); rr.writeUInt16BE(legacy ? 1 : 0x8001, 2); rr.writeUInt32BE(legacy ? 10 : 120, 4); rr.writeUInt16BE(4, 8);
    return Buffer.concat([h, legacy ? Buffer.concat([nameBuf, Buffer.from([0, 1, 0, 1])]) : Buffer.alloc(0), nameBuf, rr, Buffer.from(ip.split('.').map(Number))]);
  }
  function readName(b, off) {
    const labels = []; let end = -1, guard = 0;
    while (guard++ < 40) {
      const len = b[off];
      if (len === undefined) return null;
      if (len === 0) { off++; break; }
      if ((len & 0xc0) === 0xc0) { if (end < 0) end = off + 2; off = ((len & 0x3f) << 8) | b[off + 1]; continue; }
      labels.push(b.toString('latin1', off + 1, off + 1 + len)); off += 1 + len;
    }
    return { name: labels.join('.').toLowerCase(), end: end < 0 ? off : end };
  }
  sock.on('message', (msg, rinfo) => {
    try {
      if (msg.length < 12 || (msg.readUInt16BE(2) & 0x8000)) return; // not a question
      let off = 12, want = false, qu = false;
      for (let i = 0, n = msg.readUInt16BE(4); i < n; i++) {
        const nm = readName(msg, off); if (!nm) return;
        off = nm.end;
        const type = msg.readUInt16BE(off), cls = msg.readUInt16BE(off + 2); off += 4;
        if (nm.name === MDNS_NAME && (type === 1 || type === 255)) { want = true; if (cls & 0x8000) qu = true; }
      }
      if (!want) return;
      const addrs = lanAddrs();
      const a = addrs.find((x) => ((ip4(x.address) & ip4(x.netmask)) >>> 0) === ((ip4(rinfo.address) & ip4(x.netmask)) >>> 0)) || addrs[0];
      if (!a) return;
      if (rinfo.port !== 5353) return queue(reply(a.address, msg.readUInt16BE(0), true), rinfo.port, rinfo.address, null);
      if (qu) queue(reply(a.address, 0, false), 5353, rinfo.address, null);
      queue(reply(a.address, 0, false), 5353, '224.0.0.251', a.address);
    } catch (e) {}
  });
  const join = () => { // also after Wi-Fi / hotspot changes
    for (const a of lanAddrs()) {
      if (joined.has(a.address)) continue;
      try { sock.addMembership('224.0.0.251', a.address); joined.add(a.address); queue(reply(a.address, 0, false), 5353, '224.0.0.251', a.address); } catch (e) {}
    }
  };
  sock.on('error', (e) => { if (!ok) console.log('  ' + MDNS_NAME + ': not available (' + e.code + ') - use the IP address instead.'); try { sock.close(); } catch (x) {} });
  sock.bind(5353, () => {
    ok = true;
    try { sock.setMulticastTTL(255); sock.setMulticastLoopback(true); } catch (e) {}
    join();
    setInterval(join, 20000).unref();
  });
}

/* =================================================================
   PASSWORD for access from the internet (mobile data / other Wi-Fi)
   - phones on your own Wi-Fi / hotspot never need it
   - kept in owpass.txt next to this file (shown in the window)
   ================================================================= */
function readOrMake(file, make, ok) {
  let v = '';
  try { v = fs.readFileSync(path.join(__dirname, file), 'utf8').trim(); } catch (e) {}
  if (!ok.test(v)) { v = make(); try { fs.writeFileSync(path.join(__dirname, file), v + '\n'); } catch (e) {} }
  return v;
}
const PASS = readOrMake('owpass.txt', () => crypto.randomBytes(4).toString('hex'), /^[A-Za-z0-9_-]{4,64}$/);
const SERVER_ID = readOrMake('owid.txt', () => crypto.randomBytes(6).toString('hex'), /^[a-f0-9]{12}$/);
const badTries = new Map(); // ip -> { n, t }
const passOk = (v) => { const a = Buffer.from(String(v || '')), b = Buffer.from(PASS); return a.length === b.length && crypto.timingSafeEqual(a, b); };
const COOKIE_END = 'Expires=Thu, 31 Dec 2037 23:59:59 GMT; Path=/';

function loginPage(msg) {
  return '<!DOCTYPE html>\n<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">' +
    '<meta name="apple-mobile-web-app-capable" content="yes"><title>OldWeb</title>' +
    '<style>body{font:17px Helvetica,Arial,sans-serif;margin:0;background:#1d2733;color:#fff;text-align:center}' +
    'div{padding:40px 16px}input{font-size:20px;padding:6px;width:180px}</style></head><body><div>' +
    '<h2>OldWeb</h2><p>' + (msg || 'You are away from home. Type the password shown in the window on your PC (owpass.txt).') + '</p>' +
    '<form action="/oldweb/login" method="get"><input type="password" name="pw" autocorrect="off" autocapitalize="off"> ' +
    '<input type="submit" value="OK"></form></div></body></html>';
}

const BOOKMARKS = [
  ['DuckDuckGo', 'https://html.duckduckgo.com/html/'],
  ['Google', 'https://www.google.com/'],
  ['Wikipedia', 'https://en.m.wikipedia.org/'],
  ['YouTube', 'https://m.youtube.com/'],
  ['Reddit (old)', 'https://old.reddit.com/'],
  ['BBC News', 'https://www.bbc.com/news'],
  ['Hacker News', 'https://news.ycombinator.com/'],
  ['GitHub', 'https://github.com/'],
];

/* ------------------------------------------------------------------ Edge */

function findEdge() {
  if (process.env.EDGE_PATH) return process.env.EDGE_PATH;
  const list = [];
  if (process.platform === 'win32') {
    for (const v of ['PROGRAMFILES(X86)', 'PROGRAMFILES', 'LOCALAPPDATA']) {
      if (process.env[v]) list.push(path.join(process.env[v], 'Microsoft', 'Edge', 'Application', 'msedge.exe'));
    }
  } else if (process.platform === 'darwin') {
    list.push('/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge');
  } else {
    list.push('/usr/bin/microsoft-edge', '/usr/bin/microsoft-edge-stable', '/opt/microsoft/msedge/msedge');
  }
  for (const p of list) if (fs.existsSync(p)) return p;
  throw new Error('Microsoft Edge was not found. Set EDGE_PATH to the full path of msedge.exe');
}
const EDGE = findEdge();
for (const f of fs.readdirSync(__dirname)) { // clean spare profiles from earlier runs
  if (f.startsWith('edge-profile-spare-')) { try { fs.rmSync(path.join(__dirname, f), { recursive: true, force: true }); } catch (e) {} }
}

let browserP = null;
let UA = null;
function getBrowser() {
  if (!browserP) {
    const extra = process.env.EDGE_ARGS ? process.env.EDGE_ARGS.split(' ').filter(Boolean) : [];
    const launch = (dir) => puppeteer.launch({
      executablePath: EDGE,
      headless: process.env.SHOW_EDGE ? false : true,
      userDataDir: dir,
      defaultViewport: null,
      args: ['--no-first-run', '--no-default-browser-check', '--mute-audio',
        '--autoplay-policy=no-user-gesture-required', // page sound is caught even before a "real" click
        '--use-fake-ui-for-media-stream',             // camera / microphone: allowed without a button (PC webcam)
        '--disable-features=Translate', '--force-device-scale-factor=1.5',
        '--disable-blink-features=AutomationControlled', '--disable-smooth-scrolling'].concat(extra),
    });
    const dir = path.join(__dirname, 'edge-profile');
    // Clear stale lock files so your SAME profile (your logins/cookies) is reused after a
    // crash or hard close - this is what was quietly losing your data on restart.
    for (const lf of ['SingletonLock', 'SingletonSocket', 'SingletonCookie', 'lockfile']) {
      try { fs.rmSync(path.join(dir, lf), { force: true }); } catch (e) {}
    }
    browserP = launch(dir).catch((e) => {
      // Still busy (a hidden Edge is really running): use a PERSISTENT spare (not wiped next time),
      // so even in this case your logins are kept instead of thrown away.
      console.warn('Main Edge profile is busy (' + e.message.split('\n')[0] + '), using edge-profile-2 (also saved).');
      return launch(dir + '-2');
    }).then(async (b) => {
      // camera + microphone allowed for every site (no "Allow" button that the phone can't see)
      try {
        const bs = await b.target().createCDPSession();
        await bs.send('Browser.grantPermissions', { permissions: ['videoCapture', 'audioCapture'] });
      } catch (e) {}
      const v = await b.version();
      const m = /(\d+)\.\d+\.\d+\.\d+/.exec(v);
      const maj = m ? m[1] : '130';
      UA = 'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/' + maj +
        '.0.0.0 Mobile Safari/537.36 EdgA/' + maj + '.0.0.0';
      b.on('disconnected', () => {
        browserP = null;
        for (const s of sessions.values()) s.page = null;
      });
      console.log('Edge ready: ' + v);
      return b;
    }).catch((e) => { browserP = null; throw e; });
  }
  return browserP;
}

/* -------------------------------------------------------------- sessions */
// One hidden Edge tab per phone (by IP address), so no cookies are needed on the phone.

// The phone also gets a small cookie (ows) so its tab stays the same when its IP changes
// (home Wi-Fi -> mobile data, or a carrier that changes your IP). Without the cookie: by IP.
const sessions = new Map();
const clientIp = (req) => String(req.socket.remoteAddress || '').replace(/^::ffff:/, '');
function cookie(req, name) {
  const m = new RegExp('(?:^|;\\s*)' + name + '=([^;]*)').exec(req.headers.cookie || '');
  return m ? m[1] : '';
}
function sessionKey(req) {
  const c = cookie(req, 'ows');
  return /^[a-f0-9]{16}$/.test(c) ? 'c:' + c : clientIp(req);
}
function getSession(req) {
  const ip = clientIp(req), key = sessionKey(req);
  let s = sessions.get(key);
  if (!s) { // new cookie / no cookie (first visit, or iOS forgot it): keep this phone's tab from the same IP
    let best = null, bestK = null;
    for (const [k, v] of sessions) if (v.ip === ip && (!best || v.last > best.last)) { best = v; bestK = k; }
    if (best) { sessions.delete(bestK); s = best; sessions.set(key, s); }
  }
  if (!s) {
    s = { ip, page: null, prefs: { mode: 'live', css: 0, img: 1, hd: null }, q: Promise.resolve(),
      blocked: false, aud: null, frame: null, fid: 0, sentId: 0, waiters: [], live: null, casting: false, cap: null, capP: null, capT: 0, maxTiles: TILES, popup: null };
    sessions.set(key, s);
  }
  s.ip = ip;
  s.last = Date.now();
  return s;
}
setInterval(() => {
  for (const [k, s] of sessions) {
    if (s.casting && s.cdp && Date.now() - (s.lastPull || 0) > 30000) { // phone stopped watching: save PC power
      s.casting = false; s.cdp.send('Page.stopScreencast').catch(() => {});
    }
    if (Date.now() - s.last > IDLE_MS) { if (s.page) s.page.close().catch(() => {}); sessions.delete(k); }
  }
}, 15000).unref();

// run tasks for one phone one at a time (no clashes between taps)
function withLock(s, fn) {
  const run = s.q.then(fn, fn);
  s.q = run.catch(() => {});
  return run;
}

function viewport(s) {
  return { width: VW, height: VH, deviceScaleFactor: 1, isMobile: true, hasTouch: true };
}

// set up one Edge tab (the main page, or a login window it opens)
async function setupPage(s, page) {
  await page.setBypassCSP(true).catch(() => {});
  await page.setUserAgent(UA).catch(() => {});
  await page.setViewport(viewport(s)).catch(() => {});
  page.on('dialog', (d) => d.accept().catch(() => {}));
  await page.exposeFunction('__ioAudio', (b64) => onAudio(s, page, b64)).catch(() => {});
  await page.exposeFunction('__ioBankID', (u) => onBankID(s, u)).catch(() => {});
  const HOOKS = '(' + AUDIO_HOOK.toString() + ')();(' + BANKID_HOOK.toString() + ')()';
  await page.evaluateOnNewDocument(HOOKS).catch(() => {});
  page.evaluate(HOOKS).catch(() => {});
  page.on('popup', (p) => onPopup(s, page, p));
  page.on('framenavigated', (fr) => {
    if (fr !== page.mainFrame()) fr.evaluate(HOOKS).catch(() => {});
  });
  const cdp = await page.createCDPSession();
  await cdp.send('Fetch.enable', {
    patterns: ['Image', 'Font', 'Media'].map((t) => ({ urlPattern: '*', resourceType: t, requestStage: 'Request' }))
      .concat([{ urlPattern: '*', resourceType: 'Media', requestStage: 'Response' },        // sound from other sites
        { urlPattern: '*://app.bankid.com/*', resourceType: 'Document', requestStage: 'Request' }]), // BankID "open app" link
  }).catch(() => {});
  cdp.on('Fetch.requestPaused', (e) => {
    let p;
    if (e.responseStatusCode != null || e.responseErrorReason) p = corsFix(cdp, e);
    else if (e.resourceType === 'Document') { // the site wants to open the BankID app
      onBankID(s, e.request.url);
      p = cdp.send('Fetch.failRequest', { requestId: e.requestId, errorReason: 'Aborted' });
    } else if (s.prefs.mode === 'text') { // In Text mode Edge skips images/fonts/video = much faster
      p = cdp.send('Fetch.failRequest', { requestId: e.requestId, errorReason: 'BlockedByClient' });
    } else p = cdp.send('Fetch.continueRequest', { requestId: e.requestId });
    p.catch(() => {});
  });
  // script opens bankid:///... (location.href = ...)
  await cdp.send('Page.enable').catch(() => {});
  cdp.on('Page.frameRequestedNavigation', (e) => { if (isBankIdUrl(e.url)) onBankID(s, e.url); });
  // Live mode: Edge sends a new picture every time the page changes (like a video)
  cdp.on('Page.screencastFrame', (e) => {
    cdp.send('Page.screencastFrameAck', { sessionId: e.sessionId }).catch(() => {});
    if (s.page !== page) return;
    const tNow = Date.now();
    // keep the picture as text; it is only turned into bytes if the phone really takes it (saves PC CPU)
    s.frame = { id: ++s.fid, b64: e.data, buf: null, moving: tNow - (s.lastFrameAt || 0) < 300 };
    s.lastFrameAt = tNow;
    if (e.metadata && e.metadata.pageScaleFactor) s.scale = e.metadata.pageScaleFactor;
    const w = s.waiters; s.waiters = [];
    w.forEach((f) => f());
  });
  page.__io = { cdp };
  return cdp;
}

// show another tab on the phone (a login window, or back to the main page)
async function switchTo(s, page) {
  if (s.casting && s.cdp) await s.cdp.send('Page.stopScreencast').catch(() => {});
  s.casting = false;
  s.page = page;
  s.cdp = page.__io.cdp;
  s.frame = null;
  s.sentId = s.fid;
  if (s.prefs.mode === 'live' && s.live) await startLive(s, s.live.w, s.live.h).catch(() => {});
}

// a page opened a new window (often "Sign in with ..."): keep it as a real window so the login can
// report back to the site, show it on the phone, and go back to the site when it closes
function onPopup(s, opener, p) {
  if (s.prefs.mode !== 'live') { s.popup = p; return; }
  (async () => {
    await setupPage(s, p);
    if (p.isClosed()) return;
    s.stack = s.stack || [];
    s.stack.push(opener);
    p.once('close', () => {
      if (s.page !== p) { s.stack = s.stack.filter((x) => x !== p); return; }
      let back = null;
      while (s.stack.length && !back) { const x = s.stack.pop(); if (!x.isClosed()) back = x; }
      if (back) switchTo(s, back).catch(() => {});
    });
    await switchTo(s, p);
  })().catch(() => {});
}

async function ensurePage(s) {
  if (s.page && !s.page.isClosed()) return s.page;
  while (s.stack && s.stack.length) { // the shown window was closed: go back to the one below
    const x = s.stack.pop();
    if (!x.isClosed()) { await switchTo(s, x); return x; }
  }
  const b = await getBrowser();
  const page = await b.newPage();
  const cdp = await setupPage(s, page);
  s.cdp = cdp;
  s.casting = false;
  s.page = page;
  return page;
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const settle = (page, ms) => page.waitForNetworkIdle({ idleTime: 300, timeout: ms }).catch(() => {});

async function navigate(s, url) {
  const page = await ensurePage(s);
  s.blocked = s.prefs.mode === 'text';
  try {
    await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 20000 });
  } catch (e) {
    if (!/timeout/i.test(e.message)) throw e;
  }
  await settle(page, s.prefs.mode === 'text' ? 1500 : 2500);
  s.maxTiles = TILES; s.lastTile = 0;
  if (s.prefs.mode === 'shot') await warm(s, page);
}

// Scroll through the page once so pictures that load "when you scroll to them" are ready.
async function warm(s, page) {
  await page.evaluate(async (tiles, VW, VH) => {
    const max = Math.min(document.documentElement.scrollHeight, tiles * VH * innerWidth / VW);
    for (let y = innerHeight; y < max; y += innerHeight) { window.scrollTo(0, y); await new Promise((r) => setTimeout(r, 50)); }
    window.scrollTo(0, 0);
  }, s.maxTiles, VW, VH).catch(() => {});
  await settle(page, 900);
}

// Do something on the page (tap, key...) and wait if it starts loading a new page.
async function act(s, fn) {
  const page = await ensurePage(s);
  s.popup = null;
  let started = false;
  const onReq = (r) => { try { if (r.isNavigationRequest() && r.frame() === page.mainFrame()) started = true; } catch (e) {} };
  page.on('request', onReq);
  const nav = page.waitForNavigation({ waitUntil: 'domcontentloaded', timeout: 10000 }).catch(() => null);
  try {
    await fn(page);
    await sleep(350);
    if (started) { await nav; await settle(page, 2000); s.maxTiles = TILES; if (s.prefs.mode === 'shot') await warm(s, page); }
    else { await settle(page, 600); }
  } finally {
    page.off('request', onReq);
  }
  if (s.popup) { // link opened a new window: open it in our tab instead
    const p = s.popup; s.popup = null;
    let u = p.url();
    if (!u || u === 'about:blank') { await p.waitForNavigation({ timeout: 5000 }).catch(() => {}); u = p.url(); }
    await p.close().catch(() => {});
    if (/^https?:/i.test(u)) { await navigate(s, u); started = true; }
  }
  s.blocked = s.prefs.mode === 'text';
  return started;
}

/* ------------------------------ Modern mode: the real page as tappable pictures */
// Edge draws the whole page; we cut it into pieces (old iPhones can't show one huge picture).
async function capture(s) {
  const page = await ensurePage(s);
  const outW = VW * (s.prefs.hd ? 2 : 1);
  const info = await page.evaluate(() => {
    window.scrollTo(0, 0);
    const d = document.documentElement, b = document.body;
    return { w: innerWidth, h: Math.max(d.scrollHeight, b ? b.scrollHeight : 0, innerHeight), url: location.href, title: document.title };
  });
  const lw = Math.min(info.w, 1600);                       // page width in Edge (360 for mobile sites)
  const maxH = Math.round(s.maxTiles * VH * lw / VW);
  const h = Math.max(1, Math.min(info.h, maxH));
  const shot = await page.screenshot({ type: 'jpeg', quality: 92, optimizeForSpeed: true, captureBeyondViewport: true,
    clip: { x: 0, y: 0, width: lw, height: h, scale: outW / lw } });
  const raw = await sharp(shot).raw().toBuffer({ resolveWithObject: true });
  const W = raw.info.width, H = raw.info.height;
  const tileH = Math.round(VH * W / VW);
  const n = Math.max(1, Math.ceil(H / tileH));
  const q = s.prefs.hd ? 60 : 72;
  const tiles = await Promise.all(Array.from({ length: n }, (_, i) => {
    const th = Math.min(tileH, H - i * tileH);
    return sharp(raw.data, { raw: raw.info }).extract({ left: 0, top: i * tileH, width: W, height: th })
      .jpeg({ quality: q, progressive: false }).toBuffer().then((buf) => ({ buf, dispH: Math.round(th * PHONE_W / W) }));
  }));
  return { tiles, lw, tileDisp: Math.round(tileH * PHONE_W / W), more: info.h > maxH, url: info.url, title: info.title };
}

/* ------------------------------------------------- Sound: Edge -> phone */
// Inside every page: copy the sound of playing <video>/<audio> AND of the page's own Web Audio
// (games, web apps, sound effects) and hand it to Node as 16-bit stereo at 44100 Hz.
const AUDIO_HOOK = function () {
  if (window.__ioHooked) return;
  window.__ioHooked = true;
  var inBox = window !== window.top; // a video inside a box from another site (DuckDuckGo, embeds)
  // the main page passes sound from boxes on to the server
  if (!inBox) window.addEventListener('message', function (e) {
    if (e.data && typeof e.data.__ioA === 'string' && window.__ioAudio) window.__ioAudio(e.data.__ioA);
  });
  function sendSound(b64) {
    if (!inBox) { if (window.__ioAudio) window.__ioAudio(b64); }
    else { try { window.top.postMessage({ __ioA: b64 }, '*'); } catch (e) {} }
  }
  var AC = window.AudioContext || window.webkitAudioContext;
  if (!AC || !window.AudioNode) return;
  var RATE = 44100, N = 2048;
  var ctx = null, mix, proc, seen = [], els = [];
  var ring = [], ringOff = 0, ringN = 0, lastWA = 0; // sound from the page's own Web Audio, already at 44100
  var origConnect = AudioNode.prototype.connect, origDisc = AudioNode.prototype.disconnect;
  function mediaPlaying() {
    for (var i = 0; i < els.length; i++) if (!els[i].paused && !els[i].muted && els[i].volume > 0) return true;
    return false;
  }
  function setup() {
    if (ctx) return true;
    try { ctx = new AC({ sampleRate: RATE }); } catch (e) { return false; }
    mix = ctx.createGain();
    proc = ctx.createScriptProcessor(N, 2, 2);
    origConnect.call(mix, proc); origConnect.call(proc, ctx.destination);
    proc.onaudioprocess = function (e) {
      if (!inBox && !window.__ioAudio) return;
      var media = mediaPlaying(), wa = ringN > 0;
      if (!media && !wa) return;
      var L = e.inputBuffer.getChannelData(0), R = e.inputBuffer.getChannelData(1), n = L.length;
      var out = new Int16Array(n * 2), i, l, r, k = 0;
      // game / Web Audio sound waiting in the ring
      var gl = null, gr = null;
      if (wa) {
        gl = new Float32Array(n); gr = new Float32Array(n);
        while (k < n && ring.length) {
          var c = ring[0], take = Math.min(c[0].length - ringOff, n - k);
          gl.set(c[0].subarray(ringOff, ringOff + take), k); gr.set(c[1].subarray(ringOff, ringOff + take), k);
          k += take; ringN -= take; ringOff += take;
          if (ringOff >= c[0].length) { ring.shift(); ringOff = 0; }
        }
      }
      for (i = 0; i < n; i++) {
        l = media ? L[i] : 0; r = media ? R[i] : 0;
        if (gl) { l += gl[i]; r += gr[i]; }
        out[2 * i] = l <= -1 ? -32768 : l >= 1 ? 32767 : l * 32767;
        out[2 * i + 1] = r <= -1 ? -32768 : r >= 1 ? 32767 : r * 32767;
      }
      var b = new Uint8Array(out.buffer), s = '';
      for (var j = 0; j < b.length; j += 8192) s += String.fromCharCode.apply(null, b.subarray(j, j + 8192));
      sendSound(btoa(s));
    };
    return true;
  }
  function wake() { if (ctx && ctx.state === 'suspended') ctx.resume(); }
  // a listening point inside one of the page's own AudioContexts
  function tap(c) {
    if (c === ctx) return null;
    if (c.__ioTap) return c.__ioTap;
    if (!setup()) return null;
    var g = c.createGain(), p = c.createScriptProcessor(N, 2, 2);
    origConnect.call(g, p); origConnect.call(p, c.destination);
    var ratio = c.sampleRate / RATE;
    p.onaudioprocess = function (e) {
      var ib = e.inputBuffer, L = ib.getChannelData(0), R = ib.numberOfChannels > 1 ? ib.getChannelData(1) : L, n = L.length;
      var peak = 0, i, v;
      for (i = 0; i < n; i += 4) { v = L[i] < 0 ? -L[i] : L[i]; if (v > peak) peak = v; v = R[i] < 0 ? -R[i] : R[i]; if (v > peak) peak = v; }
      if (peak < 0.0005) return; // silence: send nothing (saves data)
      lastWA = Date.now(); wake();
      var oL, oR;
      if (ratio === 1) { oL = new Float32Array(L); oR = new Float32Array(R); }
      else {
        var m = Math.max(1, Math.round(n / ratio)); oL = new Float32Array(m); oR = new Float32Array(m);
        for (i = 0; i < m; i++) {
          var x = i * ratio, i0 = x | 0, f = x - i0, i1 = i0 + 1 < n ? i0 + 1 : i0;
          oL[i] = L[i0] + (L[i1] - L[i0]) * f; oR[i] = R[i0] + (R[i1] - R[i0]) * f;
        }
      }
      ring.push([oL, oR]); ringN += oL.length;
      while (ringN > RATE * 0.4 && ring.length > 1) { ringN -= ring[0][0].length - ringOff; ring.shift(); ringOff = 0; }
    };
    c.__ioTap = g;
    return g;
  }
  // every time the page sends sound to its speakers, we listen too
  AudioNode.prototype.connect = function (dest) {
    var r = origConnect.apply(this, arguments);
    try {
      if (dest && window.AudioDestinationNode && dest instanceof AudioDestinationNode && this.context !== ctx) {
        var t = tap(this.context);
        if (t) origConnect.call(this, t, arguments[1] | 0);
      }
    } catch (e) {}
    return r;
  };
  AudioNode.prototype.disconnect = function (dest) {
    var r = origDisc.apply(this, arguments);
    try { if (dest && window.AudioDestinationNode && dest instanceof AudioDestinationNode && this.context.__ioTap) origDisc.call(this, this.context.__ioTap); } catch (e) {}
    return r;
  };
  /* Video/sound from ANOTHER site (Instagram, Facebook, many news sites play straight from their
     CDN): Edge only lets us copy that sound if the video is loaded "CORS-clean". So we ask for it
     that way (crossorigin=anonymous) and Edge adds the permission header itself (see corsFix).
     If a video still fails like that, it is played the normal way again (picture keeps working). */
  var HM = window.HTMLMediaElement && HTMLMediaElement.prototype;
  function foreign(u) {
    try { var x = new URL(u, location.href); return (x.protocol === 'http:' || x.protocol === 'https:') && x.origin !== location.origin; }
    catch (e) { return false; }
  }
  function prep(el, u) {
    if (!el || el.__ioNoCors || el.hasAttribute('crossorigin')) return false;
    if (!u || !foreign(u)) return false;
    el.setAttribute('crossorigin', 'anonymous'); el.__ioForced = true;
    return true;
  }
  function isMedia(n) { return n && (n.tagName === 'VIDEO' || n.tagName === 'AUDIO'); }
  if (HM) {
    var sd = Object.getOwnPropertyDescriptor(HM, 'src');
    if (sd && sd.set) Object.defineProperty(HM, 'src', { configurable: true, enumerable: sd.enumerable, get: sd.get,
      set: function (v) { try { prep(this, String(v)); } catch (e) {} sd.set.call(this, v); } });
    var srcd = window.HTMLSourceElement && Object.getOwnPropertyDescriptor(HTMLSourceElement.prototype, 'src');
    if (srcd && srcd.set) Object.defineProperty(HTMLSourceElement.prototype, 'src', { configurable: true, enumerable: srcd.enumerable, get: srcd.get,
      set: function (v) { try { if (isMedia(this.parentNode)) prep(this.parentNode, String(v)); } catch (e) {} srcd.set.call(this, v); } });
    var origPlay = HM.play;
    HM.play = function () { this.__ioWant = true; return origPlay.apply(this, arguments); };
  }
  var origSetAttr = Element.prototype.setAttribute;
  Element.prototype.setAttribute = function (n, v) {
    try {
      if (String(n).toLowerCase() === 'src') {
        if (isMedia(this)) prep(this, String(v));
        else if (this.tagName === 'SOURCE' && isMedia(this.parentNode)) prep(this.parentNode, String(v));
      }
    } catch (e) {}
    return origSetAttr.apply(this, arguments);
  };
  function scan(n) { // videos written straight into the page's HTML
    if (!n || n.nodeType !== 1) return;
    if (isMedia(n)) { var so = n.querySelector('source[src]'); prep(n, n.getAttribute('src') ? n.src : so ? so.src : ''); return; }
    if (n.tagName === 'SOURCE') { if (isMedia(n.parentNode)) prep(n.parentNode, n.src); return; }
    if (n.firstElementChild && n.querySelectorAll) { var l = n.querySelectorAll('video,audio'); for (var i = 0; i < l.length; i++) scan(l[i]); }
  }
  try {
    new MutationObserver(function (recs) {
      for (var i = 0; i < recs.length; i++) for (var j = 0; j < recs[i].addedNodes.length; j++) scan(recs[i].addedNodes[j]);
    }).observe(document, { childList: true, subtree: true });
  } catch (e) {}
  function replay(el, t, go) { // load again (other way of loading), same spot, keep playing
    el.load();
    if (t) { var seek = function () { el.removeEventListener('loadedmetadata', seek); try { el.currentTime = t; } catch (e) {} }; el.addEventListener('loadedmetadata', seek); }
    if (go) { var pr = origPlay ? origPlay.call(el) : el.play(); if (pr && pr.catch) pr.catch(function () {}); }
  }
  document.addEventListener('error', function (e) {
    var el = e.target;
    if (el && el.tagName === 'SOURCE') el = el.parentNode;
    if (!isMedia(el) || !el.__ioForced || el.__ioNoCors) return;
    el.__ioNoCors = true; el.removeAttribute('crossorigin');
    replay(el, el.currentTime || 0, el.__ioWant || el.autoplay);
  }, true);

  function attach(el) {
    if (seen.indexOf(el) >= 0) return;
    // already playing from another site without CORS: its sound would be silent -> load it again CORS-clean
    if (!el.__ioForced && !el.__ioNoCors && !el.hasAttribute('crossorigin') && prep(el, el.currentSrc)) {
      replay(el, el.currentTime || 0, true);
      return; // comes back here on the next "play"
    }
    seen.push(el);
    if (!setup()) return;
    try { ctx.createMediaElementSource(el).connect(mix); els.push(el); } catch (e) {}
    wake();
  }
  document.addEventListener('play', function (e) {
    var t = e.target;
    if (t && (t.tagName === 'VIDEO' || t.tagName === 'AUDIO')) attach(t);
  }, true);
  document.addEventListener('touchend', wake, true);
  document.addEventListener('click', wake, true);
};

// Edge side of "CORS-clean": give video/sound from other sites the header that allows copying its sound
function corsFix(cdp, e) {
  const h = (e.request && e.request.headers) || {};
  const origin = h.Origin || h.origin;
  if (!origin || e.responseErrorReason || !e.responseHeaders) return cdp.send('Fetch.continueRequest', { requestId: e.requestId });
  const headers = e.responseHeaders.filter((x) => !/^access-control-allow-(origin|credentials)$/i.test(x.name));
  headers.push({ name: 'Access-Control-Allow-Origin', value: origin }, { name: 'Access-Control-Allow-Credentials', value: 'true' });
  return cdp.send('Fetch.continueResponse', { requestId: e.requestId, responseCode: e.responseStatusCode, responseHeaders: headers })
    .catch(() => cdp.send('Fetch.continueRequest', { requestId: e.requestId }));
}

/* ------------------------------------------------------------------ BankID */
// Kivra, Klarna, banks... "Open BankID on this device" tries to start the BankID app. In the hidden
// Edge that goes nowhere, so we catch it and ask the phone what to do: open BankID on the PC (BankID
// program for Windows), or use the QR code ("BankID on another device") with a phone that has BankID.
// (The BankID app needs iOS 16+, so on older iPhones it cannot open there.)
const isBankIdUrl = (u) => /^bankid:/i.test(String(u || '')) || /^https?:\/\/app\.bankid\.com\//i.test(String(u || ''));
function onBankID(s, url) {
  url = String(url || '');
  if (!isBankIdUrl(url)) { // another app (swish:, mailto:, tel:...): tell the phone
    if (!/^[a-z][a-z0-9+.-]*:/i.test(url) || /^(https?|about|blob|data|javascript):/i.test(url)) return;
    if (s.applink && s.applink.url === url && Date.now() - s.applink.t < 5000) return;
    s.applink = { url: url.slice(0, 1500), t: Date.now() };
    return;
  }
  const m = /[?&]autostarttoken=([A-Za-z0-9-]{6,80})/i.exec(String(url));
  const token = m ? m[1] : '';
  if (s.bankid && s.bankid.token === token && Date.now() - s.bankid.t < 60000) return; // same one twice
  s.bankid = { token, t: Date.now(), done: false };
  console.log('  BankID asked for (' + (token ? 'token ' + token.slice(0, 8) + '...' : 'no token') + ') - the phone will show the choices.');
}
function bankIdOnPc(token) {
  if (!/^[A-Za-z0-9-]{6,80}$/.test(token)) return 'no BankID token';
  const url = 'bankid:///?autostarttoken=' + token + '&redirect=null';
  const { spawn } = require('child_process');
  const [cmd, args] = process.platform === 'win32' ? ['rundll32.exe', ['url.dll,FileProtocolHandler', url]]
    : process.platform === 'darwin' ? ['open', [url]] : ['xdg-open', [url]];
  try { spawn(cmd, args, { detached: true, stdio: 'ignore', windowsHide: true }).on('error', () => {}).unref(); return 'ok'; }
  catch (e) { return e.message; }
}
// Inside every page: links that open an APP (bankid:, swish:, mailto:, tel:...). In the hidden Edge
// such a link opens an invisible "Open app?" question and the tab stops reacting to taps for good.
// So they are stopped here, and the phone is told instead.
const BANKID_HOOK = function () {
  if (window.__ioBidHooked) return;
  window.__ioBidHooked = true;
  function isBid(u) { u = String(u || ''); return /^bankid:/i.test(u) || /^https?:\/\/app\.bankid\.com\//i.test(u); }
  function isApp(u) {
    var m = /^([a-z][a-z0-9+.-]*):/i.exec(String(u || ''));
    return !!m && !/^(https?|about|blob|data|javascript|chrome|edge|file|ws|wss)$/i.test(m[1]);
  }
  function stop(u) { return isBid(u) || isApp(u); }
  function report(u) {
    if (window.__ioBankID) window.__ioBankID(String(u));
    else { try { window.top.postMessage({ __ioB: String(u) }, '*'); } catch (e) {} }
  }
  if (window === window.top) window.addEventListener('message', function (e) {
    if (e.data && typeof e.data.__ioB === 'string' && window.__ioBankID) window.__ioBankID(e.data.__ioB);
  });
  // location.href = 'bankid:...', links, forms (Navigation API, Edge 102+)
  if (window.navigation && navigation.addEventListener) navigation.addEventListener('navigate', function (e) {
    var u = e.destination && e.destination.url;
    if (stop(u)) { if (e.cancelable) e.preventDefault(); report(u); }
  });
  document.addEventListener('click', function (e) {
    var a = e.target && e.target.closest ? e.target.closest('a[href]') : null;
    if (a && stop(a.href)) { e.preventDefault(); report(a.href); }
  }, true);
  var wo = window.open;
  window.open = function (u) { if (stop(u)) { report(u); return null; } return wo.apply(this, arguments); };
  // hidden boxes (iframes) pointed at an app
  var fd = window.HTMLIFrameElement && Object.getOwnPropertyDescriptor(HTMLIFrameElement.prototype, 'src');
  if (fd && fd.set) Object.defineProperty(HTMLIFrameElement.prototype, 'src', { configurable: true, enumerable: fd.enumerable, get: fd.get,
    set: function (v) { if (stop(v)) { report(v); return; } fd.set.call(this, v); } });
  var sa = Element.prototype.setAttribute;
  Element.prototype.setAttribute = function (n, v) {
    if (this.tagName === 'IFRAME' && String(n).toLowerCase() === 'src' && stop(v)) { report(v); return; }
    return sa.apply(this, arguments);
  };
  try {
    new MutationObserver(function (recs) {
      for (var i = 0; i < recs.length; i++) for (var j = 0; j < recs[i].addedNodes.length; j++) {
        var n = recs[i].addedNodes[j];
        if (n && n.tagName === 'IFRAME' && stop(n.getAttribute('src'))) { report(n.getAttribute('src')); n.removeAttribute('src'); }
      }
    }).observe(document, { childList: true, subtree: true });
  } catch (e) {}
};

let MP3 = null; // MP3 encoder (loaded on first use)
const RATE = 44100;

// u-law: 8-bit sound (half the data of 16-bit, sounds like a good phone call / AM radio+)
function linToMu(v) {
  let sign = 0;
  if (v < 0) { v = -v; sign = 0x80; }
  if (v > 32635) v = 32635;
  v += 0x84;
  let exp = 7;
  for (let m = 0x4000; (v & m) === 0 && exp > 0; m >>= 1) exp--;
  return ~(sign | (exp << 4) | ((v >> (exp + 3)) & 0x0f)) & 0xff;
}
const MU_ENC = new Uint8Array(65536);
for (let i = 0; i < 65536; i++) MU_ENC[i] = linToMu(i - 32768);

// a short silent sound: playing it on iOS 7+ makes Web Audio ignore the silent switch
const SILENCE_WAV = (() => {
  const n = 22050, b = Buffer.alloc(44 + n, 128); // 0.5 s, 8-bit, 44100 Hz mono
  b.write('RIFF', 0); b.writeUInt32LE(36 + n, 4); b.write('WAVEfmt ', 8); b.writeUInt32LE(16, 16);
  b.writeUInt16LE(1, 20); b.writeUInt16LE(1, 22); b.writeUInt32LE(44100, 24); b.writeUInt32LE(44100, 28);
  b.writeUInt16LE(1, 32); b.writeUInt16LE(8, 34); b.write('data', 36); b.writeUInt32LE(n, 40);
  return b;
})();

function onAudio(s, page, b64) {
  if (s.page !== page) return;

  // Low-delay path (iOS 6+ Web Audio) - only if the phone is pulling it.
  // Kept as 22050 Hz 16-bit stereo; turned into u-law when sent.
  const p = s.pcm;
  if (p && Date.now() - p.lastPull < 8000) {
    const src = Buffer.from(b64, 'base64');
    const d = new Int16Array(src.buffer, src.byteOffset, src.length >> 1);
    const n = d.length >> 2;
    const out = new Int16Array(n * 2);
    for (let i = 0; i < n; i++) {
      out[2 * i] = (d[4 * i] + d[4 * i + 2]) >> 1;
      out[2 * i + 1] = (d[4 * i + 1] + d[4 * i + 3]) >> 1;
    }
    p.chunks.push({ seq: ++p.seq, pcm: out });
    if (p.chunks.length > 30) p.chunks.shift();
    const w = p.waiters; p.waiters = []; w.forEach((f) => f());
    return;
  }

  // MP3 stream path - only if someone is listening.
  const a = s.aud;
  if (!a || !a.listeners.size) return;
  const buf = Buffer.from(b64, 'base64');
  a.q.push(new Int16Array(buf.buffer, buf.byteOffset, buf.length >> 1));
  a.qLen += buf.length >> 2;
  while (a.qLen > RATE * 0.3 && a.q.length > 1) { a.qLen -= a.q[0].length >> 1; a.q.shift(); }
}

// pieces of sound for the phone, as u-law (stereo at home, mono on mobile data = less data)
function pcmBody(list, mono) {
  let n = 0;
  for (const c of list) n += c.pcm.length >> 1;
  const out = Buffer.alloc(mono ? n : n * 2);
  let o = 0;
  for (const c of list) {
    const d = c.pcm, m = d.length >> 1;
    if (mono) for (let i = 0; i < m; i++) out[o++] = MU_ENC[((d[2 * i] + d[2 * i + 1]) >> 1) + 32768];
    else for (let i = 0; i < d.length; i++) out[o++] = MU_ENC[d[i] + 32768];
  }
  return out;
}

// every 100 ms: take the sound that arrived (or silence) and send it as MP3 to the phone
function audioTick(s) {
  const a = s.aud;
  if (!a || !a.listeners.size) return;
  const now = Date.now();
  let frames = Math.round((now - a.t) * RATE / 1000);
  a.t = now;
  if (frames <= 0) return;
  if (frames > RATE) frames = RATE;
  const L = new Int16Array(frames), R = new Int16Array(frames);
  let i = 0;
  while (i < frames && a.q.length) {
    const c = a.q[0], start = a.off, avail = (c.length >> 1) - start, take = Math.min(avail, frames - i);
    for (let j = 0; j < take; j++) { L[i + j] = c[2 * (start + j)]; R[i + j] = c[2 * (start + j) + 1]; }
    i += take; a.qLen -= take;
    if (take === avail) { a.q.shift(); a.off = 0; } else a.off += take;
  }
  const mp3 = a.enc.encodeBuffer(L, R);
  if (mp3.length) {
    const out = Buffer.from(mp3.buffer, mp3.byteOffset, mp3.length);
    for (const res of a.listeners) res.write(out);
  }
}

async function addListener(s, req, res) {
  if (!MP3) MP3 = (await import('@breezystack/lamejs')).Mp3Encoder;
  if (!s.aud) s.aud = { listeners: new Set(), q: [], qLen: 0, off: 0, t: Date.now(), enc: null, timer: null };
  const a = s.aud;
  res.writeHead(200, { 'Content-Type': 'audio/mpeg', 'Cache-Control': 'no-cache, no-store', 'Accept-Ranges': 'none',
    'icy-name': 'Edge sound', Connection: 'keep-alive' });
  if (req.method === 'HEAD') return res.end();
  if (!a.timer) {
    a.enc = new MP3(2, RATE, 112);
    a.t = Date.now() - 400; a.q = []; a.qLen = 0; a.off = 0;
    a.timer = setInterval(() => audioTick(s), 100);
  }
  a.listeners.add(res);
  audioTick(s);
  const bye = () => {
    a.listeners.delete(res);
    if (!a.listeners.size && a.timer) { clearInterval(a.timer); a.timer = null; }
  };
  req.on('close', bye);
  res.on('error', bye);
}

/* ------------------------------------------ Live mode: streamed like a video */

async function startLive(s, w, h, dpr) {
  if (dpr) s.dpr = dpr;
  const page = await ensurePage(s);
  w = Math.min(Math.max(w | 0, 200), 1400); h = Math.min(Math.max(h | 0, 150), 1400);
  const k = VW / PHONE_W; // phone 320 px wide -> Edge 360 px wide
  s.live = { w, h, vw: Math.round(w * k), vh: Math.round(h * k) };
  // picture sharpness: HD = 2x, SD = 1x, Auto = 1x in LIVE mode (fastest; less lag on old phones).
  // (Still-picture modes can go sharper; live needs small frames so old Safari keeps up.)
  const m = s.prefs.hd === 1 ? 2 : s.prefs.hd === 0 ? 1 : 1;
  // same size as now and already streaming: keep going (restarting the stream = a pause on the phone)
  if (s.casting && s.liveScale === m && s.liveKey === s.live.vw + 'x' + s.live.vh && s.page === page) {
    if (s.frame) s.sentId = s.frame.id - 1; // the phone may have a blank screen: give it the current picture again
    return;
  }
  s.liveKey = s.live.vw + 'x' + s.live.vh;
  const vp = page.viewport() || {};
  if (vp.width !== s.live.vw || vp.height !== s.live.vh || vp.deviceScaleFactor !== m) {
    await page.setViewport({ width: s.live.vw, height: s.live.vh, deviceScaleFactor: m, isMobile: true, hasTouch: true });
  }
  // same screen size on our own connection to Edge, so sharp pictures really are sharp
  await s.cdp.send('Emulation.setDeviceMetricsOverride', { width: s.live.vw, height: s.live.vh, deviceScaleFactor: m, mobile: true }).catch(() => {});
  await s.cdp.send('Emulation.setTouchEmulationEnabled', { enabled: true, maxTouchPoints: 5 }).catch(() => {});
  await s.cdp.send('Page.stopScreencast').catch(() => {});
  await s.cdp.send('Page.startScreencast', { format: 'jpeg', quality: m > 1 ? 45 : 48,
    maxWidth: Math.round(s.live.vw * m), maxHeight: Math.round(s.live.vh * m), everyNthFrame: 1 });
  s.casting = true;
  s.liveScale = m;
  s.sentId = s.fid; // wait for a fresh picture in the new size
  s.frame = null;
}

async function stopLive(s) {
  if (s.casting && s.cdp) await s.cdp.send('Page.stopScreencast').catch(() => {});
  s.casting = false;
  if (s.cdp) await s.cdp.send('Emulation.clearDeviceMetricsOverride').catch(() => {});
  if (s.page && !s.page.isClosed()) await s.page.setViewport(viewport(s)).catch(() => {});
}

// wait for a picture the phone has not seen yet
function nextFrame(s, ms) {
  if (s.frame && s.frame.id > s.sentId) return Promise.resolve(s.frame);
  return new Promise((ok) => {
    let done = false;
    const fin = () => { if (!done) { done = true; ok(s.frame); } };
    s.waiters.push(fin);
    setTimeout(fin, ms);
  });
}

// phone spot (CSS px on the phone) -> spot on the page in Edge
async function livePoint(s, page, x, y) {
  const k = s.live ? s.live.vw / s.live.w : VW / PHONE_W;
  const sc = s.casting && s.scale ? s.scale
    : await page.evaluate(() => (window.visualViewport ? visualViewport.scale : 1) || 1).catch(() => 1);
  return { x: x * k / sc, y: y * k / sc, k: k / sc };
}

const LIVE_JS = function () {
  var BAR = 40, KB = 40;
  var d = document, W, H, cur = 0, running = false, gen = 0;
  function $(i) { return d.getElementById(i); }
  function now() { return new Date().getTime(); }
  var queue = [], qbusy = false;
  function x(url, cb) {
    var r = new XMLHttpRequest();
    r.open('GET', url + (url.indexOf('?') < 0 ? '?' : '&') + 'r=' + now() + Math.random(), true);
    r.onreadystatechange = function () { if (r.readyState == 4 && cb) cb(r.status, r.responseText); };
    r.send(null);
  }
  function q(url) { queue.push(url); pump(); } // keys/taps go out in order
  function pump() {
    if (qbusy || !queue.length) return;
    qbusy = true;
    x(queue.shift(), function (st, t) { qbusy = false; info(t); pump(); });
  }
  function info(t) {
    if (!t || t.indexOf('\n') < 0) return;
    var p = t.split('\n');
    if (p[0] && d.activeElement != $('u')) $('u').value = p[0];
    if (p[1]) d.title = p[1];
    if (p[2] && p[2].indexOf('bankid ') === 0) bankid(p[2]);
    else if (p[2] && p[2].indexOf('app ') === 0) applink(p[2]);
    else if (p.length > 2 && !p[2] && bidOpen) bidClose();
  }
  function soon() { // after a tap: ask again soon (a BankID button, a new page title...)
    setTimeout(function () { x('/live/info', function (st, t) { info(t); }); }, 900);
    setTimeout(function () { x('/live/info', function (st, t) { info(t); }); }, 2500);
  }

  // ---- the site wants to open another app (mail, phone, Swish...) ----
  var appSeen = '';
  function applink(line) {
    var a = line.split(' '), id = a[1], u = decodeURIComponent(a[2] || '');
    if (id == appSeen) return;
    appSeen = id;
    var sc = (/^([a-z0-9+.-]+):/i.exec(u) || ['', 'app'])[1].toLowerCase();
    if (/^(mailto|tel|sms|maps)$/.test(sc)) {
      var o = $('bid'); bidOpen = true;
      o.innerHTML = '<div class="bt">Open on this iPhone?</div><p>' + u.replace(/&/g, '&amp;').replace(/</g, '&lt;').substring(0, 120) + '</p>' +
        '<a class="bb" id="aop" href="#">Open</a><a class="bb bx" id="acl" href="#">Close</a>';
      o.style.display = 'block';
      $('aop').href = u; $('aop').onclick = function () { bidClose(); return true; };
      $('acl').onclick = function () { bidClose(); return false; };
    } else toast('This page wanted to open the app "' + sc + '". That is not possible here.', 6000);
  }

  // ---- BankID: the site wants to open the BankID app ----
  var bidSeen = '', bidOpen = false;
  function bidClose() { $('bid').style.display = 'none'; bidOpen = false; }
  function bankid(line) {
    var a = line.split(' '), tok = a[1], id = a[2];
    if (id == bidSeen) return;
    bidSeen = id; bidOpen = true;
    var h = '<div class="bt">BankID</div>';
    if (IOS >= 16 && tok != '-') h += '<a class="bb" id="bph" href="bankid:///?autostarttoken=' + tok + '&amp;redirect=null">Open BankID on this iPhone</a>';
    else h += '<p>The BankID app cannot run on this iPhone (it needs iOS 16 or newer). Choose:</p>';
    h += '<a class="bb" id="bqr" href="#">QR code: scan this screen with a phone that has BankID</a>';
    if (tok != '-') h += '<a class="bb" id="bpc" href="#">Open BankID on the PC</a>';
    h += '<a class="bb bx" id="bcl" href="#">Close</a>';
    var o = $('bid'); o.innerHTML = h; o.style.display = 'block';
    if ($('bph')) $('bph').onclick = function () { x('/live/bankid?a=phone'); bidClose(); return true; };
    $('bqr').onclick = function () {
      x('/live/bankid?a=qr'); bidClose();
      toast('On the page choose <b>Mobilt BankID p&aring; annan enhet</b> (BankID on another device). ' +
        'Then scan the code on this screen with your other phone. Sharper code: Menu &gt; Picture: HD.', 12000);
      return false;
    };
    if ($('bpc')) $('bpc').onclick = function () {
      bidClose();
      x('/live/bankid?a=pc', function (st, t) {
        var r = (t || '').split('\n')[3] || '';
        toast(r == 'ok' ? 'BankID opened on the PC. Sign there, then look here again.' : 'Could not open BankID on the PC: ' + r, 7000);
      });
      return false;
    };
    $('bcl').onclick = function () { x('/live/bankid?a=close'); bidClose(); return false; };
  }
  var imgs = [$('i0'), $('i1')];
  function next() {
    var my = gen, n = imgs[1 - cur];
    n.onload = function () {
      if (my != gen) return;
      n.style.visibility = 'visible'; imgs[cur].style.visibility = 'hidden'; cur = 1 - cur; next();
    };
    n.onerror = function () { if (my == gen) setTimeout(next, 800); };
    n.src = '/live/next?r=' + now() + Math.random();
  }
  var TOP = 0, lastWH = '', laying = false;
  // width + rotation only: the keyboard opening must not re-lay out the screen
  function key() { return window.innerWidth + 'x' + (window.orientation || 0); }
  function layout() {
    if (laying || key() === lastWH) return;
    laying = true;
    // hide Safari's address bar: make the page a bit taller, then scroll down 1 px
    d.body.style.height = (window.innerHeight + 120) + 'px';
    window.scrollTo(0, 1);
    setTimeout(function () {
      var vh = window.innerHeight;
      TOP = window.pageYOffset || 0;
      d.body.style.height = (vh + TOP) + 'px';
      var app = $('app');
      app.style.top = TOP + 'px'; app.style.height = vh + 'px';
      W = window.innerWidth; H = vh - BAR - KB;
      // rotate the stream when the phone is sideways
      var sideways = (window.orientation === 90 || window.orientation === -90);
      if (sideways) { var tmp = W; W = H; H = tmp; }
      var s = $('scr');
      s.style.width = (sideways ? H : W) + 'px';
      s.style.height = (sideways ? W : H) + 'px';
      for (var i = 0; i < 2; i++) {
        imgs[i].style.width = W + 'px';
        imgs[i].style.height = H + 'px';
      }
      lastWH = key(); laying = false;
      gen++;
      x('/live/start?w=' + W + '&h=' + H + '&dpr=' + (window.devicePixelRatio || 1), function () { next(); });
    }, 400);
  }
  window.__relayout = function () { lastWH = ''; layout(); };
  d.body.ontouchmove = function (e) { e.preventDefault(); }; // keep Safari's bar hidden

  /* ---- SOUND: the note button in the top bar ----
     iOS 6+   : Web Audio, small u-law pieces, about 0.2 s late (needs one tap to be allowed)
     iOS 3-5  : MP3 stream in an <audio> element (1-3 s late)
     iOS 7+   : a silent looping <audio> also plays, so the silent switch does not mute the sound */
  var snd = $('snd'), sb = $('bs'), soundOn = false, unlocked = false, told = false;
  var AC = window.AudioContext || window.webkitAudioContext, actx = null, aSeq = 0, aT = 0, aGen = 0, keep = [], sil = null, MU = null;
  var IOS = (function () { var m = /OS (\d+)_\d/.exec(navigator.userAgent); return m ? parseInt(m[1], 10) : 0; })();
  var tt = null;
  function toast(msg, ms) {
    var t = $('tst'); t.innerHTML = msg; t.style.display = 'block';
    clearTimeout(tt); tt = setTimeout(function () { t.style.display = 'none'; }, ms || 3500);
  }
  function mp3Start() { snd.src = '/live/sound.mp3?r=' + now(); snd.load(); snd.play(); }
  if (snd.addEventListener) {
    snd.addEventListener('error', function () { if (soundOn && !actx) setTimeout(mp3Start, 1500); }, false);
    snd.addEventListener('ended', function () { if (soundOn && !actx) setTimeout(mp3Start, 500); }, false);
  }
  function hold(n) { keep.push(n); if (keep.length > 16) keep.shift(); } // iOS 6 forgets sounds nobody holds on to
  function unlock() { // must run inside the tap
    try {
      if (!actx) {
        actx = new AC();
        // iOS 9+ bug: a first sound context can come out at the wrong speed (crackle). Make a fresh one.
        if (IOS >= 9 && actx.sampleRate !== 44100 && actx.close) {
          var b0 = actx.createBuffer(1, 1, 44100), s1 = actx.createBufferSource();
          s1.buffer = b0; s1.connect(actx.destination); if (s1.start) s1.start(0); else s1.noteOn(0);
          try { actx.close(); } catch (e1) {}
          actx = new AC();
        }
      }
      if (actx.resume && actx.state !== 'running') actx.resume();
      var b = actx.createBuffer(1, 1, 22050), s0 = actx.createBufferSource();
      s0.buffer = b; s0.connect(actx.destination);
      if (s0.start) s0.start(0); else s0.noteOn(0);
      hold(s0);
      return true;
    } catch (e) { actx = null; return false; }
  }
  function wakeSound() { if (soundOn && actx && actx.resume && actx.state !== 'running') actx.resume(); }
  function silentOn() {
    if (IOS < 7) return;
    try {
      if (!sil) {
        sil = d.createElement('audio');
        sil.setAttribute('x-webkit-airplay', 'deny');
        sil.loop = true; sil.preload = 'auto'; sil.src = '/live/silence.wav';
        d.body.appendChild(sil);
      }
      var pr = sil.play();
      if (pr && pr['catch']) pr['catch'](function () {});
    } catch (e) {}
  }
  function silentOff() { if (sil) { try { sil.pause(); } catch (e) {} } }
  function muTable() { // u-law byte -> sound value
    MU = new Float32Array(256);
    for (var i = 0; i < 256; i++) {
      var u = ~i & 255, t = (((u & 15) << 3) + 132) << ((u >> 4) & 7);
      MU[i] = ((u & 128) ? (132 - t) : (t - 132)) / 32768;
    }
  }
  function playPiece(ab, ch, lead) {
    var u = new Uint8Array(ab), n = (u.length / ch) | 0, rate = 22050, buf = null, i, o, c, D;
    if (!n) return;
    var t = actx.currentTime;
    if (aT < t + 0.02) aT = t + lead;          // ran dry: start again a little ahead (smooth, no overlap)
    else if (aT > t + lead + 0.5) return;       // far behind: skip this piece so sound stays with the picture
    try { buf = actx.createBuffer(ch, n, rate); } catch (e) { buf = null; }
    if (buf) {
      for (c = 0; c < ch; c++) { D = buf.getChannelData(c); for (i = 0, o = c; i < n; i++, o += ch) D[i] = MU[u[o]]; }
    } else { // this iPhone wants its own rate
      var tgt = actx.sampleRate, outN = Math.max(1, Math.round(n * tgt / rate)), step = rate / tgt;
      buf = actx.createBuffer(ch, outN, tgt);
      for (c = 0; c < ch; c++) { D = buf.getChannelData(c); for (o = 0; o < outN; o++) D[o] = MU[u[Math.floor(o * step) * ch + c]]; }
    }
    var src = actx.createBufferSource();
    src.buffer = buf; src.connect(actx.destination);
    if (src.start) src.start(aT); else src.noteOn(aT);
    hold(src);
    aT += buf.duration;
  }
  function pcmLoop(g) {
    if (g != aGen) return;
    var r = new XMLHttpRequest();
    r.open('GET', '/live/pcm?after=' + aSeq + '&r=' + now() + Math.random(), true);
    r.responseType = 'arraybuffer';
    r.onload = function () {
      if (g != aGen) return;
      if (r.status != 200) { setTimeout(function () { pcmLoop(g); }, 1000); return; }
      aSeq = parseInt(r.getResponseHeader('X-Seq'), 10) || aSeq;
      var ch = r.getResponseHeader('X-Fmt') == 'mu1' ? 1 : 2, lead = parseFloat(r.getResponseHeader('X-Lead')) || 0.2;
      var got = r.response && r.response.byteLength;
      if (got) playPiece(r.response, ch, lead);
      if (got) pcmLoop(g); else setTimeout(function () { pcmLoop(g); }, 100);
    };
    r.onerror = function () { if (g == aGen) setTimeout(function () { pcmLoop(g); }, 1000); };
    r.send(null);
  }
  function soundStart() {
    if (AC) {
      if (!MU) muTable();
      if (unlock()) { silentOn(); aGen++; aSeq = 0; aT = 0; pcmLoop(aGen); return true; }
    }
    if (!snd.play) return false; // iOS 1-2: no sound player in Safari
    mp3Start();
    return true;
  }
  function soundStop() {
    aGen++; silentOff();
    if (snd.pause) { try { snd.pause(); } catch (e) {} }
    if (snd.getAttribute && snd.getAttribute('src')) { snd.removeAttribute('src'); try { snd.load(); } catch (e2) {} }
  }
  function soundSet(want) {
    if (want == soundOn) return;
    if (want) {
      if (!soundStart()) { toast('Sound needs iOS 3 or newer.'); return; }
      soundOn = true; unlocked = true;
      if (!told) {
        told = true;
        toast('&#9835; Sound ON' + (IOS >= 7 ? '. Nothing? Turn the volume up.' :
          '. Nothing? Turn the silent switch (side of the iPhone) OFF and the volume up.'), 5000);
      }
    } else { soundOn = false; soundStop(); }
    sb.style.background = soundOn ? '#2e9e44' : '#3b4b5e';
  }
  var usedTouch = false;
  sb.ontouchend = function (e) { usedTouch = true; e.preventDefault(); soundSet(!soundOn); };
  sb.onclick = function () { if (!usedTouch) soundSet(!soundOn); return false; };
  // shake (from MOTION_JS) = sound on/off, after the button was tapped once
  window.__ioMotion = function (act) {
    if (act != 'shake') return;
    if (!unlocked) { toast('Tap the &#9835; button once to allow sound.'); return; }
    soundSet(!soundOn);
  };

  window.onload = layout;
  window.onorientationchange = window.__relayout;
  setInterval(layout, 1500); // some iOS versions tell about rotation late or not at all

  // touch: a tap is sent as a finger tap; a swipe is sent as a real finger swipe (Edge scrolls and glides itself)
  var scr = $('scr'), sx, sy, t0, drag = false, tq = [], sending = false;
  function tsend() {
    if (sending || !tq.length) return;
    sending = true;
    var e = tq.join(';'); tq = [];
    x('/live/touch?e=' + e, function () { sending = false; tsend(); });
  }
  function P(px, py) { return Math.round(px) + ',' + Math.round(py - TOP - BAR); }
  function tap(px, py) {
    $('t').value = ''; last = '';
    q('/live/tap?x=' + Math.round(px) + '&y=' + Math.round(py - TOP - BAR));
    soon();
  }
  scr.ontouchstart = function (e) {
    if (e.touches.length > 1) return;
    var t = e.touches[0];
    sx = t.pageX; sy = t.pageY; t0 = now(); drag = false;
    wakeSound(); // after the phone was locked, iOS pauses sound until the next touch
    e.preventDefault();
  };
  scr.ontouchmove = function (e) {
    var t = e.touches[0];
    if (!drag && (Math.abs(t.pageX - sx) > 6 || Math.abs(t.pageY - sy) > 6)) { drag = true; tq.push('s,' + P(sx, sy) + ',0'); }
    if (drag) {
      if (tq.length && tq[tq.length - 1].charAt(0) == 'm') tq.pop(); // network busy: only the newest finger spot
      tq.push('m,' + P(t.pageX, t.pageY) + ',' + (now() - t0));
      tsend();
    }
    e.preventDefault();
  };
  scr.ontouchend = function (e) {
    var t = e.changedTouches[0];
    if (drag) { tq.push('m,' + P(t.pageX, t.pageY) + ',' + (now() - t0)); tq.push('e,' + P(t.pageX, t.pageY) + ',' + (now() - t0)); tsend(); }
    else tap(sx, sy);
    e.preventDefault();
  };
  scr.onclick = function (e) { tap(e.pageX, e.pageY); }; // phones without touch events (iOS 1)

  // typing: what you write in the box goes to the page, letter by letter
  var tin = $('t'), last = '', poll = null;
  function diff() {
    var v = tin.value;
    if (v == last) return;
    var i = 0;
    while (i < v.length && i < last.length && v.charAt(i) == last.charAt(i)) i++;
    var del = last.length - i, add = v.substring(i);
    last = v;
    q('/live/key?del=' + del + '&t=' + encodeURIComponent(add));
  }
  tin.onfocus = function () { poll = setInterval(diff, 120); };
  tin.onblur = function () { clearInterval(poll); diff(); };
  $('tf').onsubmit = function () { diff(); q('/live/key?k=Enter'); tin.value = ''; last = ''; soon(); return false; };
  $('kd').onclick = function () { diff(); q('/live/key?k=Backspace'); return false; };
  $('ke').onclick = function () { diff(); q('/live/key?k=Enter'); tin.value = ''; last = ''; soon(); return false; };

  // bar
  $('uf').onsubmit = function () { $('u').blur(); q('/live/go?u=' + encodeURIComponent($('u').value)); return false; };
  $('bb').onclick = function () { q('/live/nav?a=back'); return false; };
  $('bf').onclick = function () { q('/live/nav?a=forward'); return false; };
  $('bm').onclick = function () { var m = $('menu'); m.style.display = m.style.display == 'block' ? 'none' : 'block'; return false; };
  window.liveCmd = function (u) { $('menu').style.display = 'none'; q(u); return false; };
  setInterval(function () { if (!qbusy && !sending) x('/live/info', function (st, t) { info(t); }); }, 6000);
};

/* --------------------------------------------- Shake -> sound, rotate */
// Rotation: the live view lays itself out again. Shake: sound on/off (after the note button was
// tapped once - iOS only allows sound to start from a tap). Tilting no longer mutes: iOS reports
// "face up" with the opposite sign on many versions, so lying the phone flat muted the sound.
const MOTION_JS = function () {
  window.addEventListener('orientationchange', function () {
    setTimeout(function () { if (window.__relayout) window.__relayout(); }, 300);
  }, false);
  var last = null, lastShakeAt = 0;
  function onMotion(e) {
    var a = e.accelerationIncludingGravity;
    if (!a || a.x == null) return;
    if (last) {
      var force = Math.abs(a.x - last.x) + Math.abs(a.y - last.y) + Math.abs(a.z - last.z);
      var t = new Date().getTime();
      if (force > 30 && t - lastShakeAt > 900) { lastShakeAt = t; if (window.__ioMotion) window.__ioMotion('shake'); }
    }
    last = { x: a.x, y: a.y, z: a.z };
  }
  if (window.DeviceMotionEvent) window.addEventListener('devicemotion', onMotion, false);
};

/* --------------------------------------------- Text mode: page -> simple HTML */

// Shared by Node and by the Edge page: points url(...) in CSS at our server.
function rewriteCss(css, base) {
  css = css.replace(/@font-face\s*\{[^}]*\}/gi, '');
  css = css.replace(/@import\s+(?:url\()?\s*['"]?([^'")\s;]+)['"]?\s*\)?([^;]*);/gi, function (m, u, rest) {
    try { return '@import "/css?u=' + encodeURIComponent(new URL(u, base).href) + '"' + rest + ';'; } catch (e) { return ''; }
  });
  return css.replace(/url\(\s*(['"]?)([^'")]+)\1\s*\)/gi, function (m, q, u) {
    u = u.trim();
    if (/^data:/i.test(u)) return /^data:image\/(png|gif|jpe?g)/i.test(u) ? m : 'url()';
    if (u.charAt(0) === '#') return m;
    var abs;
    try { abs = new URL(u, base).href; } catch (e) { return m; }
    if (!/^https?:/i.test(abs) || /\.(woff2?|ttf|otf|eot)(\?|#|$)/i.test(abs)) return 'url()';
    return 'url("/img?u=' + encodeURIComponent(abs) + '")';
  });
}

// Runs INSIDE Edge. Copies the visible page, removes scripts & hidden parts, fixes links.
function extractInPage(o, rewriteCss) {
  var enc = encodeURIComponent;
  var body = document.body;
  if (!body) return { title: document.title, url: location.href, html: '<p>(This page has no content.)</p>', head: '', lang: '' };

  var DROP = { SCRIPT: 1, NOSCRIPT: 1, TEMPLATE: 1, SVG: 1, CANVAS: 1, OBJECT: 1, EMBED: 1, META: 1, BASE: 1,
    SOURCE: 1, TRACK: 1, PARAM: 1, MATH: 1, PORTAL: 1 };
  if (!o.css) { DROP.STYLE = 1; DROP.LINK = 1; }
  var NOVIS = { OPTION: 1, OPTGROUP: 1, MAP: 1, AREA: 1, STYLE: 1, LINK: 1, TITLE: 1, BR: 1, WBR: 1 };
  var KEEP = {};
  ('href src alt title name value type action method colspan rowspan width height id for checked selected ' +
    'disabled multiple size maxlength rows cols label readonly start reversed summary border cellpadding ' +
    'cellspacing align valign dir lang placeholder usemap shape coords datetime' +
    (o.css ? ' class style bgcolor color face rel media' : '')).split(' ').forEach(function (a) { KEEP[a] = 1; });

  function abs(u) { try { return new URL(u, document.baseURI).href; } catch (e) { return ''; } }
  function fromSrcset(ss) {
    var best = '', bestD = 1e9;
    String(ss || '').split(/,\s+/).forEach(function (part) {
      var m = part.trim().split(/\s+/); if (!m[0]) return;
      var w = 640;
      if (m[1] && /w$/.test(m[1])) w = parseInt(m[1], 10); else if (m[1] && /x$/.test(m[1])) w = parseFloat(m[1]) * 400;
      var d = Math.abs(w - o.imgW) + (w < o.imgW ? 200 : 0);
      if (d < bestD) { bestD = d; best = m[0]; }
    });
    return best;
  }
  function pickImg(img) {
    var u = img.currentSrc || '';
    if (!u || u.indexOf('data:') === 0) {
      var lazy = img.getAttribute('data-src') || img.getAttribute('data-lazy-src') || img.getAttribute('data-original') ||
        img.getAttribute('data-url') || '';
      var ss = img.getAttribute('data-srcset') || img.getAttribute('srcset') || '';
      if (lazy) u = lazy; else if (ss) u = fromSrcset(ss); else if (!u) u = img.getAttribute('src') || '';
    }
    if ((!u || u.indexOf('data:') === 0) && img.parentNode && img.parentNode.tagName === 'PICTURE') {
      var so = img.parentNode.querySelector('source[srcset],source[data-srcset]');
      if (so) u = fromSrcset(so.getAttribute('srcset') || so.getAttribute('data-srcset'));
    }
    if (!u) return '';
    return u.indexOf('data:') === 0 ? u : abs(u);
  }
  function sheetText(el) {
    try { if (el.sheet && el.sheet.cssRules) return Array.prototype.map.call(el.sheet.cssRules, function (r) { return r.cssText; }).join('\n'); } catch (e) {}
    return el.textContent || '';
  }

  var live = [body].concat(Array.prototype.slice.call(body.getElementsByTagName('*')));
  var n = live.length, kill = new Uint8Array(n), i, el, tag;

  // 1) find hidden things using Edge's real layout
  for (i = 1; i < n; i++) {
    el = live[i]; tag = el.tagName.toUpperCase();
    if (DROP[tag]) { kill[i] = 1; i += el.getElementsByTagName('*').length; continue; }
    if (NOVIS[tag] || (tag === 'INPUT' && el.type === 'hidden')) continue;
    var cs = getComputedStyle(el);
    if (cs.display === 'none' || cs.visibility === 'hidden' ||
      ((cs.position === 'absolute' || cs.position === 'fixed') && el.offsetWidth <= 1 && el.offsetHeight <= 1)) {
      kill[i] = 1; i += el.getElementsByTagName('*').length;
    }
  }

  // 2) work on a copy so the real page is not touched
  var clone = body.cloneNode(true);
  var cl = [clone].concat(Array.prototype.slice.call(clone.getElementsByTagName('*')));
  function drop(c) { if (c.parentNode) c.parentNode.removeChild(c); }
  function swap(c, node) { if (c.parentNode) c.parentNode.replaceChild(node, c); }
  function text(t) { var sp = document.createElement('span'); sp.textContent = t; return sp; }
  function link(href, t) { var a = document.createElement('a'); a.setAttribute('href', href); a.textContent = t; return a; }

  for (i = 1; i < n; i++) {
    var c = cl[i], l = live[i];
    tag = l.tagName.toUpperCase();
    var sub = l.getElementsByTagName('*').length;
    if (kill[i]) { drop(c); i += sub; continue; }

    if (tag === 'IFRAME' || tag === 'FRAME') {
      var fs = l.src || '';
      if (/^https?:/i.test(fs) && l.offsetWidth > 60 && l.offsetHeight > 40) {
        var h = ''; try { h = new URL(fs).hostname; } catch (e) {}
        swap(c, link('/go?u=' + enc(fs), '[Frame: ' + h + ']'));
      } else drop(c);
      i += sub; continue;
    }
    if (tag === 'VIDEO' || tag === 'AUDIO') { swap(c, text('[' + (tag === 'VIDEO' ? 'Video' : 'Audio') + ' - use Modern mode]')); i += sub; continue; }

    for (var a = c.attributes.length - 1; a >= 0; a--) {
      var nm = c.attributes[a].name;
      if (nm.slice(0, 2) === 'on' || !KEEP[nm]) c.removeAttribute(nm);
    }

    if (tag === 'A' || tag === 'AREA') {
      var ha = l.getAttribute('href');
      if (ha != null) {
        if (ha.charAt(0) === '#') c.setAttribute('href', ha);
        else {
          var hu = abs(ha);
          if (/^https?:/i.test(hu)) c.setAttribute('href', '/go?u=' + enc(hu));
          else if (/^(mailto|tel|sms):/i.test(hu)) c.setAttribute('href', hu);
          else c.removeAttribute('href');
        }
      }
    } else if (tag === 'IMG' || (tag === 'INPUT' && l.type === 'image')) {
      var wA = +l.getAttribute('width'), hA = +l.getAttribute('height');
      if (tag === 'IMG' && ((wA && wA <= 2) || (hA && hA <= 2))) { drop(c); continue; }
      var u = tag === 'IMG' ? pickImg(l) : abs(l.getAttribute('src') || '');
      var okData = /^data:image\/(png|gif|jpe?g)/i.test(u) && u.length < 30000;
      if (tag === 'IMG' && (!o.img || !u || (u.indexOf('data:') === 0 && !okData))) {
        var alt = (l.getAttribute('alt') || '').trim();
        if (alt && alt.length < 120) swap(c, text('[' + alt + ']')); else drop(c);
        continue;
      }
      c.setAttribute('src', u.indexOf('data:') === 0 ? u : '/img?u=' + enc(u) + '&w=' + o.imgW);
    } else if (tag === 'FORM') {
      var act = abs(l.getAttribute('action') || location.href);
      var meth = (l.getAttribute('method') || 'get').toLowerCase();
      c.removeAttribute('enctype'); c.removeAttribute('target');
      if (meth === 'post') {
        c.setAttribute('method', 'post');
        c.setAttribute('action', '/post?__u=' + enc(act));
      } else {
        c.setAttribute('method', 'get');
        c.setAttribute('action', '/go');
        var hi = document.createElement('input');
        hi.setAttribute('type', 'hidden'); hi.setAttribute('name', '__u'); hi.setAttribute('value', act);
        c.insertBefore(hi, c.firstChild);
      }
    } else if (tag === 'INPUT') {
      var ty = (l.type || '').toLowerCase();
      if (ty === 'checkbox' || ty === 'radio') { if (l.checked) c.setAttribute('checked', 'checked'); else c.removeAttribute('checked'); }
      else if (ty !== 'password' && ty !== 'file' && l.value) c.setAttribute('value', l.value);
    } else if (tag === 'LINK') {
      if (/stylesheet/i.test(l.rel) && /^https?:/i.test(l.href)) c.setAttribute('href', '/css?u=' + enc(l.href)); else drop(c);
    } else if (tag === 'STYLE') {
      c.textContent = rewriteCss(sheetText(l), document.baseURI);
    }
    if (o.css && c.getAttribute('style')) c.setAttribute('style', rewriteCss(c.getAttribute('style'), document.baseURI));
  }

  var head = '';
  if (o.css) {
    Array.prototype.forEach.call(document.querySelectorAll('head link[rel~="stylesheet"], head style'), function (s) {
      if (s.tagName === 'LINK') { if (/^https?:/i.test(s.href)) head += '<link rel="stylesheet" href="/css?u=' + enc(s.href) + '">'; }
      else head += '<style>' + rewriteCss(sheetText(s), document.baseURI).replace(/<\/style/gi, '<\\/style') + '</style>';
    });
    try {
      (document.adoptedStyleSheets || []).forEach(function (sh) {
        head += '<style>' + rewriteCss(Array.prototype.map.call(sh.cssRules, function (r) { return r.cssText; }).join('\n'), document.baseURI) + '</style>';
      });
    } catch (e) {}
  }
  return { title: document.title, url: location.href, html: clone.innerHTML, head: head, lang: document.documentElement.lang || '' };
}

async function extract(s) {
  const page = await ensurePage(s);
  const o = { css: !!s.prefs.css, img: !!s.prefs.img, imgW: s.prefs.hd ? 640 : 360 };
  const r = await page.evaluate('(' + extractInPage.toString() + ')(' + JSON.stringify(o) + ',' + rewriteCss.toString() + ')');
  r.html = r.html.replace(/<!--[\s\S]*?-->/g, '');
  return r;
}

/* ------------------------------------------------------------- images/css */

let ICON = null;
const TINY_GIF = Buffer.from('R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7', 'base64');
const imgCache = new Map();
let imgBytes = 0;
const IMG_MAX = 80 * 1024 * 1024;
const inflight = new Map();

async function convert(buf, type, w) {
  if (!sharp) return { buf, type };
  try {
    const img = sharp(buf, { failOn: 'none', animated: false, limitInputPixels: 1e8 });
    const m = await img.metadata();
    if (m.format === 'gif' && (m.pages || 1) > 1 && buf.length < 1.5e6) return { buf, type: 'image/gif' };
    if (['jpeg', 'png', 'gif'].includes(m.format) && (m.width || 0) <= w && buf.length < 300e3 && !m.isProgressive) {
      return { buf, type: 'image/' + m.format };
    }
    const p = img.rotate().resize({ width: w, height: w * 4, fit: 'inside', withoutEnlargement: true });
    if (m.hasAlpha) return { buf: await p.png({ compressionLevel: 7 }).toBuffer(), type: 'image/png' };
    return { buf: await p.flatten({ background: '#ffffff' }).jpeg({ quality: 70, progressive: false }).toBuffer(), type: 'image/jpeg' };
  } catch (e) {
    return { buf, type };
  }
}

async function getImage(u, w, referer) {
  const key = w + ' ' + u;
  const hit = imgCache.get(key);
  if (hit) { imgCache.delete(key); imgCache.set(key, hit); return hit; }
  if (inflight.has(key)) return inflight.get(key);
  const p = (async () => {
    const headers = { 'User-Agent': UA || 'Mozilla/5.0', Accept: 'image/png,image/jpeg,image/gif,image/svg+xml,image/*;q=0.8,*/*;q=0.5' };
    if (referer && /^https?:/.test(referer)) headers.Referer = referer;
    const r = await fetch(u, { headers, redirect: 'follow', signal: AbortSignal.timeout(12000) });
    if (!r.ok) throw new Error('HTTP ' + r.status);
    const buf = Buffer.from(await r.arrayBuffer());
    return convert(buf, (r.headers.get('content-type') || 'image/jpeg').split(';')[0], w);
  })();
  inflight.set(key, p);
  try {
    const v = await p;
    imgCache.set(key, v); imgBytes += v.buf.length;
    while (imgBytes > IMG_MAX && imgCache.size) {
      const [k0, v0] = imgCache.entries().next().value;
      imgCache.delete(k0); imgBytes -= v0.buf.length;
    }
    return v;
  } finally {
    inflight.delete(key);
  }
}

/* --------------------------------------------------------------- HTML out */

const esc = (t) => String(t == null ? '' : t).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');

const BAR_CSS =
  'body{margin:0;-webkit-text-size-adjust:100%}' +
  '#xb{background:#1d2733 !important;color:#fff !important;padding:5px !important;font:13px Helvetica,Arial,sans-serif !important;text-align:left !important}' +
  '#xb form{margin:0 !important;padding:0 !important}' +
  '#xu{width:250px;font-size:15px;padding:3px;border:1px solid #888;margin:0}' +
  '#xg{font-size:14px;margin:0 0 0 2px}' +
  '#xl{margin-top:4px;font-size:12px !important}' +
  '#xb a,#xb a:visited{color:#8fd0ff !important;margin-right:7px;line-height:24px;text-decoration:none;font-weight:bold;white-space:nowrap}' +
  '#xp img{max-width:100%;height:auto}';
const PLAIN_CSS =
  'body{font:16px/1.4 Helvetica,Arial,sans-serif;color:#111;background:#fff;word-wrap:break-word}' +
  '#xp{padding:6px 8px}#xp a{color:#0645ad}#xp pre{white-space:pre-wrap}' +
  '#xp table{max-width:100%}#xp input,#xp select,#xp textarea,#xp button{max-width:100%;font-size:16px}' +
  '#xp h1{font-size:22px}#xp h2{font-size:19px}#xp h3{font-size:17px}#xp ul,#xp ol{padding-left:22px}';
const SHOT_CSS =
  'body{background:#fff;font:14px Helvetica,Arial,sans-serif}' +
  '#xs{margin:0;padding:0}#xs input{display:block;border:0;margin:0;padding:0}' +
  '.xr{background:#1d2733;color:#fff;padding:3px 4px;margin:0;font-size:13px}' +
  '.xr form{margin:0}' +
  '.xr a,.xr a:visited{display:inline-block;background:#3b4b5e;color:#fff;padding:7px 7px;margin:2px 0;font-size:13px;text-decoration:none;font-weight:bold;-webkit-border-radius:5px}' +
  '#xt{width:140px;font-size:15px}' +
  '#xm{display:block;text-align:center;padding:14px;background:#e8eef5;color:#06c;font-weight:bold;text-decoration:none}';

function pageHead(title, extraHead, css, lang) {
  return '<!DOCTYPE html>\n<html' + (lang ? ' lang="' + esc(lang) + '"' : '') + '><head><meta charset="utf-8">' +
    '<meta name="viewport" content="width=device-width, initial-scale=1">' +
    '<meta name="format-detection" content="telephone=no">' +
    '<meta name="apple-mobile-web-app-capable" content="yes">' +
    '<title>' + esc(title) + '</title>' + (extraHead || '') + '<style>' + css + '</style></head><body>';
}

function toolbar(s, url) {
  const p = s.prefs, shot = p.mode === 'shot';
  const L = (h, t) => '<a href="' + h + '">' + t + '</a>';
  return '<div id="xb"><form action="/go" method="get"><input type="text" name="u" id="xu" value="' +
    esc(url && url !== 'about:blank' ? url : '') + '" autocorrect="off" autocapitalize="off">' +
    '<input type="submit" value="Go" id="xg"></form><div id="xl">' +
    L('/home', 'Home') + L('/nav?a=back', 'Back') + (shot ? L('/nav?a=forward', 'Fwd') : '') + L('/nav?a=reload', 'Reload') +
    L('/set?mode=live', 'Live') + (shot ? L('/set?mode=text', 'Lite') : L('/set?mode=shot', 'Modern')) +
    (shot ? '' : L('/set?css=' + (p.css ? 0 : 1), p.css ? 'Plain' : 'Styles') + L('/set?img=' + (p.img ? 0 : 1), p.img ? 'NoImg' : 'Img')) +
    L('/set?hd=' + (p.hd ? 0 : 1), p.hd ? 'SD' : 'HD') + '</div></div>';
}

function textPage(s, r) {
  return pageHead(r.title || r.url, s.prefs.css ? r.head : '', BAR_CSS + (s.prefs.css ? '' : PLAIN_CSS), r.lang) +
    toolbar(s, r.url) + '<div id="xp">' + r.html + '</div></body></html>';
}

function shotPage(s, c, t, at) {
  const B = (h, txt) => '<a href="' + h + '">' + txt + '</a>';
  let tiles = '';
  c.tiles.forEach((tl, i) => {
    tiles += '<input type="image" name="t' + i + '" id="t' + i + '" src="/tile?i=' + i + '&amp;t=' + t + '" width="' + PHONE_W +
      '" height="' + tl.dispH + '" alt="">';
  });
  const jump = at > 0 ? '<script>(function(){function j(){var e=document.getElementById("t' + at + '");if(e)window.scrollTo(0,e.offsetTop-30);}' +
    'j();window.onload=j;})();</script>' : '';
  return pageHead(c.title || c.url, '', BAR_CSS + SHOT_CSS) + toolbar(s, c.url) +
    '<div class="xr"><form action="/type" method="get"><input type="text" name="text" id="xt" autocorrect="off" autocapitalize="off" placeholder="Tap a box, type here">' +
    ' <input type="submit" value="Type"> <input type="submit" name="enter" value="Type+Enter"></form></div>' +
    '<form action="/click" method="get" id="xs">' + tiles + '</form>' + jump +
    (c.more ? '<a id="xm" href="/more">Show more of this page</a>' : '') +
    '<div class="xr">' + B('/key?k=Enter', 'Enter') + B('/key?k=Backspace', 'Del') + B('/key?k=Tab', 'Tab') + B('/key?k=Escape', 'Esc') +
    B('/scroll?d=up', 'Up') + B('/scroll?d=down', 'Down') + B('/view', 'Refresh') + '</div></body></html>';
}

function livePage(s) {
  const p = s.prefs;
  const url = s.page && !s.page.isClosed() ? s.page.url() : '';
  const css =
    'html,body{margin:0;padding:0;background:#000;font-family:Helvetica,Arial,sans-serif;-webkit-text-size-adjust:100%}' +
    '#app{position:absolute;left:0;right:0;top:0;height:100%;overflow:hidden}' +
    '#bar,#kb{position:absolute;left:0;right:0;height:40px;background:#1d2733}#bar{top:0}#kb{bottom:0}' +
    '#bar form,#kb form{margin:0}' +
    '.b{position:absolute;top:5px;height:30px;line-height:30px;color:#fff;font-weight:bold;font-size:15px;text-align:center;' +
    'background:#3b4b5e;-webkit-border-radius:6px;text-decoration:none}' +
    '#u,#t{position:absolute;top:6px;height:28px;font-size:15px;border:0;padding:0 6px;-webkit-border-radius:6px;-webkit-appearance:none;-webkit-box-sizing:border-box}' +
    '#u{left:72px;right:112px}#t{left:5px;right:118px}' +
    '#tst{display:none;position:absolute;left:10px;right:10px;top:50px;background:#000;background:rgba(0,0,0,.85);color:#fff;' +
    'padding:10px;font-size:15px;text-align:center;-webkit-border-radius:8px;z-index:13}' +
    '#bid{display:none;position:absolute;left:8px;right:8px;top:48px;background:#fff;color:#111;padding:10px;z-index:12;' +
    '-webkit-border-radius:10px;font-size:15px}#bid .bt{font-weight:bold;font-size:19px;margin-bottom:6px}#bid p{margin:4px 0 8px}' +
    '#bid .bb{display:block;margin:7px 0;padding:11px;background:#1a6fd1;color:#fff;text-decoration:none;text-align:center;' +
    'font-weight:bold;-webkit-border-radius:7px}#bid .bx{background:#777}' +
    '#scr{position:absolute;left:0;top:40px;overflow:hidden;background:#fff}' +
    '#scr img{position:absolute;left:0;top:0;display:block;border:0;visibility:hidden}' +
    '#menu{display:none;position:absolute;right:4px;top:40px;width:190px;background:#1d2733;z-index:9;-webkit-border-radius:0 0 8px 8px;padding:4px 0}' +
    '#menu a{display:block;color:#fff;padding:11px 14px;font-size:16px;text-decoration:none;border-top:1px solid #2e3b4a}';
  const C = (u, t) => '<a href="#" onclick="return liveCmd(\'' + u + '\')">' + t + '</a>';
  const G = (u, t) => '<a href="' + u + '" onclick="location.href=\'' + u + '\';return false">' + t + '</a>';
  return '<!DOCTYPE html>\n<html><head><meta charset="utf-8">' +
    '<meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1, user-scalable=no">' +
    '<meta name="apple-mobile-web-app-capable" content="yes"><meta name="apple-mobile-web-app-status-bar-style" content="black">' +
    '<meta name="format-detection" content="telephone=no"><link rel="apple-touch-icon" href="/icon.png">' +
    '<title>' + esc(url || 'Web') + '</title><style>' + css + '</style></head><body>' +
    '<div id="app"><audio id="snd" preload="none"></audio>' +
    '<div id="bar"><a href="#" class="b" id="bb" style="left:4px;width:30px">&lsaquo;</a>' +
    '<a href="#" class="b" id="bf" style="left:38px;width:30px">&rsaquo;</a>' +
    '<form id="uf" action="/go"><input type="text" id="u" name="u" value="' + esc(url) + '" autocorrect="off" autocapitalize="off"></form>' +
    '<a href="#" class="b" id="bs" style="right:66px;width:40px;font-size:19px">&#9835;</a>' +
    '<a href="#" class="b" id="bm" style="right:4px;width:58px">Menu</a></div><div id="tst"></div><div id="bid"></div>' +
    '<div id="menu">' + G('/home', 'Home / Search') + C('/live/nav?a=reload', 'Reload') + C('/live/scroll?top=1', 'Go to top') +
    C('/live/scroll?dy=-400', 'Scroll up') + C('/live/scroll?dy=400', 'Scroll down') + C('/live/key?k=Escape', 'Esc key') + C('/live/key?k=Tab', 'Tab key') + C('/live/fresh', 'Page stuck? Fix it') +
    G('/set?hd=' + (p.hd === null ? 1 : p.hd === 1 ? 0 : 'auto'), 'Picture: ' + (p.hd === null ? 'Auto' : p.hd ? 'HD' : 'SD') + ' (change)') + G('/set?mode=shot', 'Modern (no live)') + G('/set?mode=text', 'Lite (text)') + '</div>' +
    '<div id="scr"><img id="i0" alt=""><img id="i1" alt=""></div>' +
    '<div id="kb"><form id="tf" action="#"><input type="text" id="t" placeholder="Tap a box on the page, then type here" autocorrect="off" autocapitalize="off"></form>' +
    '<a href="#" class="b" id="kd" style="right:62px;width:52px">Del</a><a href="#" class="b" id="ke" style="right:4px;width:54px">Enter</a></div>' +
    '</div><script>(' + LIVE_JS.toString() + ')();</script>' +
    '<script>(' + MOTION_JS.toString() + ')();</script></body></html>';
}

function homePage(s) {
  const p = s.page && !s.page.isClosed() ? s.page.url() : '';
  return pageHead('Home', '', BAR_CSS + PLAIN_CSS + '.bk a{display:block;padding:9px 4px;border-bottom:1px solid #ddd;font-size:17px;text-decoration:none}') +
    toolbar(s, p) + '<div id="xp"><h2>Search the web</h2>' +
    '<form action="/go" method="get"><input type="text" name="q" style="width:220px" autocorrect="off"> <input type="submit" value="Search"></form>' +
    (p && p !== 'about:blank' ? '<p><a href="/view">&laquo; Back to ' + esc(p.slice(0, 60)) + '</a></p>' : '') +
    '<h2>Sites</h2><div class="bk">' + BOOKMARKS.map(([n, u]) => '<a href="/go?u=' + encodeURIComponent(u) + '">' + esc(n) + '</a>').join('') + '</div>' +
    '<h3>Modes</h3><p><b>Live</b> = the real page, moving live like a video. Swipe to scroll, tap to click. Best.<br>' +
    '<b>Modern</b> = the real modern page, drawn by Edge. Scroll it and tap it like a normal browser. ' +
    'To write: tap the text box on the page, then type in the box at the top.<br>' +
    '<b>Lite</b> = simple text page, fastest on slow Wi-Fi.</p>' +
    '<h3>Sound</h3><p>In Live mode tap the <b>&#9835;</b> button (top bar). Green = sound on. ' +
    'After that, shaking the phone also turns sound on/off. Rotate the phone and the live view follows.</p>' +
    '</div></body></html>';
}

function errorPage(s, msg, url) {
  return pageHead('Error', '', BAR_CSS + PLAIN_CSS) + toolbar(s, url) +
    '<div id="xp"><h2>Could not open the page</h2><p>' + esc(msg) + '</p>' +
    (url ? '<p><a href="/go?u=' + encodeURIComponent(url) + '">Try again</a></p>' : '') +
    '<p><a href="/set?mode=shot">Try Modern mode</a> &nbsp; <a href="/home">Home</a></p></div></body></html>';
}

/* ----------------------------------------------------------------- server */

function send(req, res, code, type, body, extra) {
  let buf = Buffer.isBuffer(body) ? body : Buffer.from(String(body), 'utf8');
  const h = Object.assign({ 'Content-Type': type, 'Cache-Control': 'no-store' }, extra || {});
  if (/^text\//.test(type) && buf.length > 1024 && /\bgzip\b/.test(req.headers['accept-encoding'] || '')) {
    buf = zlib.gzipSync(buf, { level: 4 });
    h['Content-Encoding'] = 'gzip';
    h.Vary = 'Accept-Encoding';
  }
  h['Content-Length'] = buf.length;
  res.writeHead(code, h);
  res.end(req.method === 'HEAD' ? undefined : buf);
}
const HTML = 'text/html; charset=utf-8';
function redirect(res, loc) { res.writeHead(302, { Location: loc, 'Content-Length': 0, 'Cache-Control': 'no-store' }); res.end(); }

function toUrl(t) {
  t = String(t || '').trim();
  if (!t) return '';
  if (/^https?:\/\//i.test(t)) return t;
  if (/^[a-z][a-z0-9+.-]*:/i.test(t) && !/^[^\s/:]+\.[a-z]{2,}(:\d+)?(\/|$)/i.test(t)) return ''; // block file:, edge:, etc.
  if (/\s/.test(t) || (!/\.[a-z]{2,}/i.test(t) && !/^(localhost|\d+\.\d+\.\d+\.\d+)/i.test(t))) return SEARCH + encodeURIComponent(t);
  return 'http' + (/^(localhost|\d+\.)/.test(t) ? '' : 's') + '://' + t;
}

function readBody(req, max) {
  return new Promise((ok, bad) => {
    const chunks = []; let n = 0;
    req.on('data', (c) => { n += c.length; if (n > max) { bad(new Error('Form too big')); req.destroy(); } else chunks.push(c); });
    req.on('end', () => ok(Buffer.concat(chunks).toString('utf8')));
    req.on('error', bad);
  });
}

const dec = (x) => { try { return decodeURIComponent(String(x).replace(/\+/g, ' ')); } catch (e) { return String(x); } };

// Show the current page (Lite or Modern)
async function renderView(req, res, s, cacheable) {
  const page = s.page;
  if (!page || page.isClosed() || page.url() === 'about:blank') return redirect(res, '/home');
  if (s.prefs.mode === 'live') return send(req, res, 200, HTML, livePage(s));
  if (s.prefs.mode === 'text') {
    const r = await withLock(s, () => extract(s));
    return send(req, res, 200, HTML, textPage(s, r), cacheable ? { 'Cache-Control': 'private, max-age=120' } : null);
  }
  const c = await withLock(s, async () => {
    if (s.blocked) { // page was opened in Lite mode without pictures: load it fully
      s.blocked = false;
      await page.reload({ waitUntil: 'domcontentloaded', timeout: 15000 }).catch(() => {});
      await settle(page, 2000);
      await warm(s, page);
    }
    return capture(s);
  });
  s.cap = c;
  s.capT = Date.now();
  const at = Math.min(Math.max(parseInt(new URL(req.url, 'http://x').searchParams.get('at'), 10) || 0, 0), c.tiles.length - 1);
  return send(req, res, 200, HTML, shotPage(s, c, s.capT, at));
}

async function handle(req, res) {
  const U = new URL(req.url, 'http://x');
  const q = U.searchParams;
  const route = U.pathname;
  const ip = clientIp(req), lan = isPrivateIp(ip);

  // For the OldWeb .deb on the iPhone: "is this my PC?" (no password needed; it tells nothing)
  if (route === '/oldweb/ping') { // + the PC's own address on the phone's network (home only)
    const me = String(req.socket.localAddress || '').replace(/^::ffff:/, '');
    return send(req, res, 200, 'text/plain', 'OLDWEB ' + SERVER_ID + (lan && /^[\d.]+$/.test(me) ? ' ' + me : '') + '\n');
  }
  if (route === '/oldweb/info') { // home network only: the address to use when away from home
    if (!lan) return send(req, res, 403, 'text/plain', 'home network only\n');
    return send(req, res, 200, 'text/plain', 'OLDWEB ' + SERVER_ID + '\next=' + (extIp || '') + '\nport=' + PORT +
      '\nports=' + openedPorts.join(',') + '\n');
  }
  if (!lan) { // from the internet: password first
    if (route === '/oldweb/login') {
      const t = badTries.get(ip), recent = t && Date.now() - t.t < 15 * 60 * 1000;
      if (recent && t.n >= 10) return send(req, res, 200, HTML, loginPage('Too many wrong passwords. Wait 15 minutes.'));
      if (passOk(q.get('pw'))) {
        badTries.delete(ip);
        res.writeHead(302, { Location: '/', 'Set-Cookie': 'owp=' + PASS + '; ' + COOKIE_END, 'Content-Length': 0, 'Cache-Control': 'no-store' });
        return res.end();
      }
      badTries.set(ip, { n: (recent ? t.n : 0) + 1, t: Date.now() });
      return send(req, res, 200, HTML, loginPage('Wrong password. Try again.'));
    }
    if (!passOk(cookie(req, 'owp'))) {
      if (/^\/(live\/|img$|css$|tile$)/.test(route)) return send(req, res, 403, 'text/plain', 'password needed\n');
      return send(req, res, 200, HTML, loginPage());
    }
  }
  if (route === '/oldweb/login') return redirect(res, '/');
  // give the phone its own tab cookie (keeps the same tab when the network changes)
  if (!/^[a-f0-9]{16}$/.test(cookie(req, 'ows')) && !/^\/(live\/|img$|css$|tile$|icon\.png$)/.test(route)) {
    res.setHeader('Set-Cookie', 'ows=' + crypto.randomBytes(8).toString('hex') + '; ' + COOKIE_END);
  }
  const s = getSession(req);

  if (route === '/' ) return s.page && !s.page.isClosed() && s.page.url() !== 'about:blank' ? redirect(res, '/view') : redirect(res, '/home');
  if (route === '/home') return send(req, res, 200, HTML, homePage(s));
  if (route === '/view') return renderView(req, res, s);

  if (route === '/go') {
    let target = '';
    const raw = req.url.indexOf('?') >= 0 ? req.url.slice(req.url.indexOf('?') + 1) : '';
    const pairs = raw ? raw.split('&') : [];
    let formUrl = null;
    const rest = [];
    for (const p of pairs) {
      const eq = p.indexOf('=');
      if (dec(eq < 0 ? p : p.slice(0, eq)) === '__u' && formUrl === null) formUrl = dec(eq < 0 ? '' : p.slice(eq + 1));
      else rest.push(p);
    }
    if (formUrl !== null) { // a GET form from a website was sent
      try { const t = new URL(formUrl); t.search = rest.join('&'); t.hash = ''; target = t.href; } catch (e) {}
    } else if (q.get('q') != null) target = SEARCH + encodeURIComponent(q.get('q'));
    else target = toUrl(q.get('u'));
    if (!/^https?:\/\//i.test(target)) return redirect(res, '/home');
    if (s.prefs.mode === 'live') { // Live: show the page while it loads
      const page = await ensurePage(s);
      page.goto(target, { waitUntil: 'domcontentloaded', timeout: 30000 }).catch(() => {});
      return send(req, res, 200, HTML, livePage(s));
    }
    try {
      await withLock(s, () => navigate(s, target));
    } catch (e) {
      return send(req, res, 200, HTML, errorPage(s, e.message, target));
    }
    return renderView(req, res, s, true);
  }

  if (route === '/post' && req.method === 'POST') {
    const action = q.get('__u') || '';
    const body = await readBody(req, 2e6);
    if (!/^https?:\/\//i.test(action)) return redirect(res, '/home');
    try {
      await withLock(s, () => act(s, (page) => page.evaluate((action, pairs) => {
        const f = document.createElement('form');
        f.method = 'post'; f.action = action; f.acceptCharset = 'utf-8';
        pairs.forEach(([k, v]) => { const i = document.createElement('input'); i.type = 'hidden'; i.name = k; i.value = v; f.appendChild(i); });
        (document.body || document.documentElement).appendChild(f);
        HTMLFormElement.prototype.submit.call(f);
      }, action, [...new URLSearchParams(body)])));
    } catch (e) {
      return send(req, res, 200, HTML, errorPage(s, e.message, ''));
    }
    return redirect(res, '/view');
  }

  if (route === '/tile') {
    const c = s.cap, tl = c && c.tiles[parseInt(q.get('i'), 10) || 0];
    if (!tl) return send(req, res, 200, 'image/gif', TINY_GIF);
    return send(req, res, 200, 'image/jpeg', tl.buf, { 'Cache-Control': 'private, max-age=600' });
  }

  if (route === '/click') {
    const c = s.cap;
    let tile = -1, x = 0, y = 0;
    for (const [k, v] of q) { const m = /^t(\d+)\.x$/.exec(k); if (m) { tile = +m[1]; x = parseFloat(v) || 0; y = parseFloat(q.get('t' + m[1] + '.y')) || 0; } }
    if (!c || tile < 0) return redirect(res, '/view');
    // spot on the phone picture -> spot on the page in Edge
    const k = c.lw / PHONE_W;
    const lx = x * k, ly = (tile * c.tileDisp + y) * k;
    s.lastTile = tile;
    const navved = await withLock(s, () => act(s, async (page) => {
      const sy = await page.evaluate((ly) => {
        window.scrollTo(0, ly < innerHeight ? 0 : ly - innerHeight / 2);
        return window.scrollY;
      }, ly);
      await page.mouse.click(Math.round(lx), Math.round(ly - sy));
    }));
    return redirect(res, '/view' + (navved ? '' : '?at=' + tile));
  }
  if (route === '/more') {
    s.maxTiles = Math.min(s.maxTiles + TILES, 48);
    const at = s.cap ? s.cap.tiles.length - 1 : 0;
    await withLock(s, () => ensurePage(s).then((p) => warm(s, p)));
    return redirect(res, '/view?at=' + at);
  }
  const back = (navved) => '/view' + (navved || !s.lastTile ? '' : '?at=' + s.lastTile);
  if (route === '/type') {
    const txt = q.get('text') || '';
    const navved = await withLock(s, () => act(s, async (page) => {
      if (txt) await page.keyboard.type(txt);
      if (q.get('enter')) await page.keyboard.press('Enter');
    }));
    return redirect(res, back(navved));
  }
  if (route === '/key') {
    const k = q.get('k');
    let navved = false;
    if (['Enter', 'Backspace', 'Tab', 'Escape', 'ArrowUp', 'ArrowDown', 'ArrowLeft', 'ArrowRight', 'Space'].includes(k)) {
      navved = await withLock(s, () => act(s, (page) => page.keyboard.press(k)));
    }
    return redirect(res, back(navved));
  }
  if (route === '/scroll') {
    const d = q.get('d');
    await withLock(s, async () => {
      const page = await ensurePage(s);
      if (d === 'top') await page.evaluate(() => window.scrollTo(0, 0));
      else {
        await page.mouse.move(VW / 2, VH / 2);
        await page.mouse.wheel({ deltaY: (d === 'up' ? -1 : 1) * (VH - 120) });
      }
      await sleep(250);
    });
    return redirect(res, '/view');
  }
  if (route === '/nav') {
    const a = q.get('a');
    await withLock(s, async () => {
      const page = await ensurePage(s);
      const o = { waitUntil: 'domcontentloaded', timeout: 15000 };
      if (a === 'back') await page.goBack(o).catch(() => {});
      else if (a === 'forward') await page.goForward(o).catch(() => {});
      else if (a === 'reload') await page.reload(o).catch(() => {});
      await settle(page, 1500);
      s.blocked = s.prefs.mode === 'text';
      s.lastTile = 0; s.maxTiles = TILES;
      if (s.prefs.mode === 'shot') await warm(s, page);
    });
    return redirect(res, '/view');
  }
  if (route === '/set') {
    const p = s.prefs;
    const m = q.get('mode');
    if (m === 'text' || m === 'shot' || m === 'live') {
      if (p.mode === 'live' && m !== 'live') await stopLive(s);
      p.mode = m;
    }
    s.lastTile = 0;
    for (const k of ['css', 'img']) if (q.get(k) != null) p[k] = q.get(k) === '1' ? 1 : 0;
    if (q.get('hd') != null) p.hd = q.get('hd') === '1' ? 1 : q.get('hd') === '0' ? 0 : null;
    return redirect(res, '/view');
  }

  if (route.startsWith('/live/')) {
    const page = await ensurePage(s);
    const bid = s.bankid && !s.bankid.done && Date.now() - s.bankid.t < 180000 ? 'bankid ' + (s.bankid.token || '-') + ' ' + s.bankid.t
      : s.applink && Date.now() - s.applink.t < 20000 ? 'app ' + s.applink.t + ' ' + encodeURIComponent(s.applink.url) : '';
    const status = () => send(req, res, 200, 'text/plain; charset=utf-8', page.url() + '\n' + (s.lastTitle || '') + '\n' + bid);
    if (/^\/live\/(info|start|nav|go)$/.test(route)) page.title().then((t) => { s.lastTitle = t; }).catch(() => {});
    const num = (k) => parseFloat(q.get(k)) || 0;
    switch (route) {
      case '/live/start':
        if (s.prefs.mode !== 'live') s.prefs.mode = 'live';
        await startLive(s, num('w'), num('h'), num('dpr'));
        return status();
      case '/live/next': {
        s.lastPull = Date.now();
        if (!s.casting && s.live) await startLive(s, s.live.w, s.live.h);
        let f = await nextFrame(s, s.frame ? 15000 : 500);
        if (!f) f = { id: s.fid, buf: await page.screenshot({ type: 'jpeg', quality: 55 }) };
        if (!f.buf) f.buf = Buffer.from(f.b64, 'base64');
        s.sentId = f.id;
        return send(req, res, 200, 'image/jpeg', f.buf);
      }
      case '/live/tap': {
        const pt = await livePoint(s, page, num('x'), num('y'));
        const tp = [{ x: Math.round(pt.x), y: Math.round(pt.y) }], t = Date.now() / 1000;
        s.cdp.send('Input.dispatchTouchEvent', { type: 'touchStart', touchPoints: tp, timestamp: t }).catch(() => {});
        s.cdp.send('Input.dispatchTouchEvent', { type: 'touchEnd', touchPoints: [], timestamp: t + 0.06 }).catch(() => {});
        return status();
      }
      case '/live/touch': { // a swipe from the phone, sent to Edge as a real finger swipe
        s.lastTouch = Date.now();
        const k = s.live ? s.live.vw / s.live.w : VW / PHONE_W;
        const sc = s.scale || 1;
        const evs = String(q.get('e') || '').split(';').map((e) => e.split(',')).filter((e) => e.length === 4);
        if (!evs.length) return status();
        if (evs[0][0] === 's') { s.tBase = Date.now() - (+evs[evs.length - 1][3] || 0); s.tLast = 0; }
        const base = s.tBase || Date.now();
        for (const [ty, ex, ey, et] of evs) {
          const type = ty === 's' ? 'touchStart' : ty === 'm' ? 'touchMove' : 'touchEnd';
          const pt = { x: Math.round(+ex * k / sc), y: Math.round(+ey * k / sc) };
          // finger times from the phone, never in the future and always in order (for a natural glide)
          const ts = Math.max(Math.min(base + (+et || 0), Date.now()), (s.tLast || 0) + 1);
          s.tLast = ts;
          s.cdp.send('Input.dispatchTouchEvent', { type, touchPoints: type === 'touchEnd' ? [] : [pt], timestamp: ts / 1000 }).catch(() => {});
        }
        return status();
      }
      case '/live/scroll': {
        if (q.get('top')) { await page.evaluate(() => window.scrollTo(0, 0)).catch(() => {}); return status(); }
        const pt = await livePoint(s, page, num('x') || 160, num('y') || 200);
        s.cdp.send('Input.dispatchMouseEvent', { type: 'mouseWheel', x: Math.round(pt.x), y: Math.round(pt.y),
          deltaX: num('dx') * pt.k, deltaY: num('dy') * pt.k }).catch(() => {});
        return status();
      }
      case '/live/key': {
        const k = q.get('k');
        const del = Math.min(num('del'), 500);
        for (let i = 0; i < del; i++) await page.keyboard.press('Backspace');
        const t = q.get('t');
        if (t) { if (/^[\x20-\x7e]{1,30}$/.test(t)) await page.keyboard.type(t); else await page.keyboard.sendCharacter(t); }
        if (['Enter', 'Backspace', 'Tab', 'Escape'].includes(k)) await page.keyboard.press(k);
        return status();
      }
      case '/live/go': {
        const target = toUrl(q.get('u'));
        if (/^https?:\/\//i.test(target)) page.goto(target, { waitUntil: 'domcontentloaded', timeout: 30000 }).catch(() => {});
        return status();
      }
      case '/live/nav': {
        const a = q.get('a'), o = { waitUntil: 'domcontentloaded', timeout: 30000 };
        if (a === 'back') {
          // on a login window with nothing to go back to: close it (back to the site)
          const h = s.stack && s.stack.length ? await s.cdp.send('Page.getNavigationHistory').catch(() => null) : null;
          const prev = h && h.entries[h.currentIndex - 1];
          if (h && (!prev || /^about:blank/.test(prev.url))) page.close().catch(() => {});
          else page.goBack(o).catch(() => {});
        }
        else if (a === 'forward') page.goForward(o).catch(() => {});
        else if (a === 'reload') page.reload(o).catch(() => {});
        return status();
      }
      case '/live/sound.mp3':
        return addListener(s, req, res);
      case '/live/silence.wav':
        return send(req, res, 200, 'audio/wav', SILENCE_WAV, { 'Cache-Control': 'private, max-age=86400' });
      case '/live/pcm': { // low-delay sound pieces for iOS 6+ (played with Web Audio on the phone)
        if (!s.pcm) s.pcm = { seq: 0, chunks: [], waiters: [], lastPull: 0 };
        const p = s.pcm;
        p.lastPull = Date.now();
        let after = num('after');
        if (!after || after > p.seq) after = p.seq; // (re)start: only new sound, nothing old
        const wait = (ms) => new Promise((ok) => {
          p.waiters.push(ok);
          setTimeout(() => { p.waiters = p.waiters.filter((f) => f !== ok); ok(); }, ms);
        });
        const fresh = () => p.chunks.filter((c) => c.seq > after);
        if (!fresh().length) await wait(4000);
        // a bit more sound in one go = fewer requests (old iPhones and mobile data like that)
        const away = !isPrivateIp(clientIp(req));
        const want = away ? 3 : 2, most = away ? 110 : 60, t0 = Date.now();
        while (fresh().length < want && Date.now() - t0 < most) await wait(most - (Date.now() - t0));
        p.lastPull = Date.now();
        // never more than ~0.37 s at once, so the sound can't fall behind the picture
        const list = fresh().slice(-8);
        const body = pcmBody(list, away);
        res.writeHead(200, { 'Content-Type': 'application/octet-stream', 'Cache-Control': 'no-store', 'X-Seq': String(p.seq),
          'X-Fmt': away ? 'mu1' : 'mu2', 'X-Lead': away ? '0.35' : '0.18', 'Content-Length': body.length });
        return res.end(body);
      }
      case '/live/info':
        return status();
      case '/live/fresh': { // "Page stuck? Fix it": same page in a brand-new tab
        const url = page.url();
        const np = await (await getBrowser()).newPage();
        await setupPage(s, np);
        s.stack = [];
        await switchTo(s, np);
        page.close().catch(() => {});
        if (/^https?:/i.test(url)) np.goto(url, { waitUntil: 'domcontentloaded', timeout: 30000 }).catch(() => {});
        return status();
      }
      case '/live/bankid': { // the phone chose: pc / qr / phone / close
        const a = q.get('a');
        let msg = 'ok';
        if (s.bankid && a === 'pc') msg = bankIdOnPc(s.bankid.token);
        if (s.bankid) s.bankid.done = true;
        return send(req, res, 200, 'text/plain; charset=utf-8', page.url() + '\n' + (s.lastTitle || '') + '\n\n' + msg);
      }
    }
    return send(req, res, 404, 'text/plain', 'Not found');
  }
  if (route === '/icon.png' || route === '/favicon.ico') {
    if (!ICON) ICON = await sharp(Buffer.from('<svg xmlns="http://www.w3.org/2000/svg" width="114" height="114"><rect width="114" height="114" fill="#1a6fd1"/>' +
      '<circle cx="57" cy="57" r="34" fill="none" stroke="#fff" stroke-width="7"/><path d="M23 57h68M57 23c-16 18-16 50 0 68M57 23c16 18 16 50 0 68" fill="none" stroke="#fff" stroke-width="5"/></svg>')).png().toBuffer();
    return send(req, res, 200, 'image/png', ICON, { 'Cache-Control': 'public, max-age=86400' });
  }
  if (route === '/img') {
    const u = q.get('u') || '';
    const w = Math.min(Math.max(parseInt(q.get('w'), 10) || 360, 50), 1280);
    if (!/^https?:\/\//i.test(u)) return send(req, res, 200, 'image/gif', TINY_GIF);
    try {
      const v = await getImage(u, w, s.page && !s.page.isClosed() ? s.page.url() : '');
      return send(req, res, 200, v.type, v.buf, { 'Cache-Control': 'private, max-age=86400' });
    } catch (e) {
      return send(req, res, 200, 'image/gif', TINY_GIF, { 'Cache-Control': 'private, max-age=300' });
    }
  }
  if (route === '/css') {
    const u = q.get('u') || '';
    if (!/^https?:\/\//i.test(u)) return send(req, res, 200, 'text/css', '');
    try {
      const r = await fetch(u, { headers: { 'User-Agent': UA || 'Mozilla/5.0', Accept: 'text/css,*/*;q=0.1' }, signal: AbortSignal.timeout(10000) });
      const css = rewriteCss(await r.text(), r.url || u);
      return send(req, res, 200, 'text/css; charset=utf-8', css, { 'Cache-Control': 'private, max-age=86400' });
    } catch (e) {
      return send(req, res, 200, 'text/css', '');
    }
  }
  return send(req, res, 404, 'text/plain', 'Not found');
}

function makeServer() {
  const srv = http.createServer({ noDelay: true, keepAlive: true }, (req, res) => {
    handle(req, res).catch((e) => {
      console.error(e);
      if (!res.headersSent) {
        try { send(req, res, 500, HTML, errorPage(getSession(req), e.message, '')); } catch (e2) { res.end(); }
      }
    });
  });
  srv.keepAliveTimeout = 30000;
  return srv;
}

// Listen on ONE port only: 8106 (no port 80). The iPhone app connects to :8106.
const listenPorts = [PORT];
const openedPorts = [];
let bootDone = false;

function boot() {
  if (bootDone) return; bootDone = true;
  console.log('\n  Old iPhone Web Gateway is running.\n');
  console.log('  On your iPhone, open the OldWeb icon (or Safari) - it uses:');
  console.log('     http://oldweb.se:' + PORT + '    <- the OldWeb app maps this name to this PC');
  console.log('     http://' + MDNS_NAME + ':' + PORT + '    <- any iPhone on the same Wi-Fi / hotspot, no .deb needed');
  console.log('  (Same thing by IP, if you ever need it:)');
  let lanIp = '127.0.0.1';
  for (const list of Object.values(os.networkInterfaces())) {
    for (const a of list || []) if (a.family === 'IPv4' && !a.internal) { console.log('     http://' + a.address + ':' + PORT); if (lanIp === '127.0.0.1') lanIp = a.address; }
  }
  if (WANT_REMOTE) {
    (async () => {
      for (const p of openedPorts) await upnp.open(lanIp, p);
      console.log('  Router (for mobile data / hotspot): ' + upnp.state);
      await refreshExtIp(); setInterval(refreshExtIp, 10 * 60 * 1000).unref();
      console.log('  Password for mobile data (asked once on the phone): ' + PASS + '   (in owpass.txt)');
      const awayPort = ':' + PORT;
      if (DUCKDNS_DOMAIN) {
        await duckdnsUpdate(); setInterval(duckdnsUpdate, 5 * 60 * 1000).unref();
        console.log('  Away from home, the phone can use:  http://' + DUCKDNS_DOMAIN + '.duckdns.org' + awayPort + '/');
      } else if (extIp) {
        console.log('  Away from home (mobile data OR hotspot), the phone can use:  http://' + extIp + awayPort + '/');
        console.log('  (That internet IP can change. For a name that never changes, set DUCKDNS_DOMAIN + DUCKDNS_TOKEN.)');
      }
    })().catch(() => {});
  } else {
    console.log('  Remote access is OFF (REMOTE=0). Home Wi-Fi only.');
  }
  for (const sig of ['SIGINT', 'SIGTERM']) process.on(sig, () => { Promise.race([upnp.close(), new Promise(r => setTimeout(r, 2500))]).finally(() => process.exit(0)); });
  console.log('\n  Edge: ' + EDGE + '\n  (Keep this window open. Press Ctrl+C to stop.)\n');
  console.log('  Sound in Live mode: tap the note button in the top bar (green = on).');
  console.log('  Rotate the phone and the live view follows.\n');
  startMdns();
  getBrowser().catch((e) => console.error('Could not start Edge:', e.message));
}

let pending = listenPorts.length;
for (const p of listenPorts) {
  const srv = makeServer();
  srv.on('error', (e) => {
    if (p === PORT && e.code === 'EADDRINUSE') { console.error('\n  Port ' + PORT + ' is already in use. Is the gateway already running?\n'); process.exit(1); }
    console.error('\n  Could not open port ' + PORT + ': ' + e.code + '\n'); process.exit(1);
  });
  srv.listen(p, '0.0.0.0', () => { openedPorts.push(p); if (--pending === 0) boot(); });
}

async function quit() {
  try { if (browserP) await (await browserP).close(); } catch (e) {}
  process.exit(0);
}
process.on('SIGINT', quit);
process.on('SIGTERM', quit);
process.on('SIGHUP', quit);