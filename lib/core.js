// LiteDog — 轻量级网站检测工具（零依赖 Node.js）
// 功能：HTTP 测速 / TCP Ping / DNS 查询 / 端口检测 / HTTP 响应头检测
const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const dns = require('dns');
const net = require('net');
const os = require('os');
const { URL } = require('url');

const PORT = Number(process.env.PORT || 3000);
// 仓库根目录（lib/ 的上一级），serveIndex 从这里读 index.html
const ROOT = path.join(__dirname, '..');
const MAX_BODY_BYTES = 2 * 1024 * 1024;

const now = () => Number(process.hrtime.bigint()) / 1e6;
const round1 = (v) => Math.round(v * 10) / 10;

function sendJson(res, status, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Access-Control-Allow-Origin': '*',
    'Cache-Control': 'no-store'
  });
  res.end(body);
}

function startStream(res) {
  res.writeHead(200, {
    'Content-Type': 'application/x-ndjson; charset=utf-8',
    'Access-Control-Allow-Origin': '*',
    'Cache-Control': 'no-store',
    'X-Accel-Buffering': 'no'
  });
}
const sendLine = (res, obj) => res.write(JSON.stringify(obj) + '\n');

// ---------- IP 安全检查（SSRF 防护） ----------
function isPrivateIPv4(ip) {
  const m = ip.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!m) return true;
  const a = Number(m[1]);
  const b = Number(m[2]);
  if (a === 0 || a === 10 || a === 127) return true;
  if (a === 100 && b >= 64 && b <= 127) return true;
  if (a === 169 && b === 254) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 192 && (b === 0 || b === 88)) return true;
  if (a === 198 && (b === 18 || b === 19)) return true;
  if (a >= 224) return true;
  return false;
}

function isPrivateIp(ip, family) {
  if (family === 6) {
    const s = String(ip).toLowerCase();
    const mapped = s.match(/::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/);
    if (mapped) return isPrivateIPv4(mapped[1]);
    if (s === '::' || s === '::1') return true;
    if (/^f[cd]/.test(s)) return true;
    if (/^fe[89ab]/.test(s)) return true;
    if (/^2001:db8/.test(s)) return true;
    return false;
  }
  return isPrivateIPv4(ip);
}

function lookupPublic(host) {
  return new Promise((resolve, reject) => {
    dns.lookup(host, { all: true, verbatim: true }, (err, addrs) => {
      if (err) return reject(new Error('DNS 解析失败: ' + err.message));
      const pub = addrs.find((a) => !isPrivateIp(a.address, a.family));
      if (!pub) return reject(new Error('目标解析为私有/保留地址，已拒绝检测'));
      resolve(pub);
    });
  });
}

const HOST_RE = /^[\w.-]{1,253}$/;

// ---------- HTTP 测速 ----------
async function timedRequest(rawUrl, opts) {
  const maxRedirects = (opts && opts.maxRedirects) || 5;
  const redirects = (opts && opts.redirects) || [];
  const timeoutMs = (opts && opts.timeoutMs) || 10000;

  const u = new URL(rawUrl);
  if (!/^https?:$/.test(u.protocol)) throw new Error('仅支持 http/https 协议');

  const tDns0 = now();
  const addr = await lookupPublic(u.hostname);
  const dnsMs = round1(now() - tDns0);

  const isHttps = u.protocol === 'https:';
  const port = Number(u.port) || (isHttps ? 443 : 80);

  return await new Promise((resolve, reject) => {
    const t0 = now();
    const timings = { tcp: 0, tls: 0, ttfb: 0 };
    let finished = false;
    let truncated = false;

    const req = (isHttps ? https : http).request({
      host: addr.address,
      port,
      path: u.pathname + u.search,
      method: 'GET',
      agent: false,
      timeout: timeoutMs,
      rejectUnauthorized: false,
      servername: isHttps ? u.hostname : undefined,
      headers: {
        'Host': u.host,
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 LiteDog/1.0',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
        'Accept-Encoding': 'gzip, deflate, br',
        'Connection': 'close'
      }
    }, (res) => {
      timings.ttfb = round1(now() - t0);

      let tlsInfo = null;
      if (isHttps && res.socket && res.socket.getCipher) {
        try {
          tlsInfo = {
            protocol: res.socket.getProtocol ? res.socket.getProtocol() : null,
            cipher: (res.socket.getCipher() || {}).name || null
          };
        } catch (e) { /* ignore */ }
      }

      let size = 0;
      const finish = (err) => {
        if (finished) return;
        finished = true;
        const total = round1(now() - t0);
        if (err && !truncated) {
          reject(err);
          return;
        }
        const tlsTotal = timings.tls || timings.tcp;
        const result = {
          url: rawUrl,
          status: res.statusCode,
          statusMessage: res.statusMessage,
          httpVersion: res.httpVersion,
          size,
          truncated,
          ip: addr.address,
          family: addr.family,
          tls: tlsInfo,
          timings: {
            dns: dnsMs,
            tcp: round1(timings.tcp),
            tls: round1(Math.max(0, timings.tls - timings.tcp)),
            wait: round1(Math.max(0, timings.ttfb - tlsTotal)),
            download: round1(Math.max(0, total - timings.ttfb)),
            total: round1(dnsMs + total)
          }
        };
        const loc = res.headers.location;
        if (res.statusCode >= 300 && res.statusCode < 400 && loc && redirects.length < maxRedirects) {
          let next;
          try { next = new URL(loc, u).href; } catch (e) {
            result.redirects = redirects;
            resolve(result);
            return;
          }
          timedRequest(next, {
            maxRedirects,
            timeoutMs,
            redirects: redirects.concat([{ url: rawUrl, status: res.statusCode, location: next }])
          }).then(resolve, reject);
        } else {
          result.redirects = redirects;
          resolve(result);
        }
      };

      res.on('data', (c) => {
        size += c.length;
        if (size > MAX_BODY_BYTES) {
          truncated = true;
          try { req.destroy(); } catch (e) { /* ignore */ }
          finish(null);
        }
      });
      res.on('end', () => finish(null));
      res.on('error', (e) => finish(new Error('读取响应失败: ' + e.message)));
      res.on('aborted', () => finish(truncated ? null : new Error('连接被中断')));
    });

    req.on('socket', (socket) => {
      socket.on('connect', () => { timings.tcp = now() - t0; });
      socket.on('secureConnect', () => { timings.tls = now() - t0; });
    });
    req.on('timeout', () => {
      try { req.destroy(new Error('请求超时 (' + timeoutMs / 1000 + 's)')); } catch (e) { /* ignore */ }
    });
    req.on('error', (e) => {
      if (!finished) { finished = true; reject(new Error(e.message || '请求失败')); }
    });
    req.end();
  });
}

// ---------- TCP Ping ----------
function tcpPing(host, port, timeoutMs) {
  return new Promise((resolve) => {
    const t0 = now();
    let done = false;
    const socket = net.connect({ host, port });
    const finish = (ok, err) => {
      if (done) return;
      done = true;
      try { socket.destroy(); } catch (e) { /* ignore */ }
      resolve({ ok, ms: ok ? round1(now() - t0) : null, error: err || null });
    };
    socket.setTimeout(timeoutMs, () => finish(false, '超时'));
    socket.on('connect', () => finish(true, null));
    socket.on('error', (e) => finish(false, e.code || e.message));
  });
}

// ---------- DNS ----------
const resolver = new dns.promises.Resolver({ timeout: 4000, tries: 2 });

function normalizeRecords(type, r) {
  if (type === 'MX') return r.map((x) => x.priority + ' ' + x.exchange);
  if (type === 'SOA') {
    return [r.nsname + ' ' + r.hostmaster + ' serial=' + r.serial +
      ' refresh=' + r.refresh + ' retry=' + r.retry +
      ' expire=' + r.expire + ' minttl=' + r.minttl];
  }
  if (type === 'CAA') {
    return r.map((x) => Object.keys(x)
      .filter((k) => k !== 'critical' && x[k] != null)
      .map((k) => k + '=' + x[k]).join(' '));
  }
  if (type === 'TXT') return r.map((x) => x.join(''));
  return r.map((x) => (typeof x === 'string' ? x : JSON.stringify(x)));
}

async function resolveType(host, type) {
  const fns = {
    A: () => resolver.resolve4(host),
    AAAA: () => resolver.resolve6(host),
    CNAME: () => resolver.resolveCname(host),
    NS: () => resolver.resolveNs(host),
    TXT: () => resolver.resolveTxt(host),
    MX: () => resolver.resolveMx(host),
    SOA: () => resolver.resolveSoa(host),
    CAA: () => resolver.resolveCaa(host)
  };
  const fn = fns[type];
  if (!fn) throw new Error('不支持的记录类型');
  const r = await fn();
  return normalizeRecords(type, Array.isArray(r) ? r : [r]);
}

// ---------- 端口检测 ----------
const COMMON_PORTS = [
  [21, 'FTP'], [22, 'SSH'], [25, 'SMTP'], [53, 'DNS'], [80, 'HTTP'],
  [110, 'POP3'], [143, 'IMAP'], [443, 'HTTPS'], [465, 'SMTPS'], [587, 'SMTP提交'],
  [993, 'IMAPS'], [995, 'POP3S'], [1433, 'MSSQL'], [3306, 'MySQL'], [3389, '远程桌面'],
  [5432, 'PostgreSQL'], [6379, 'Redis'], [8080, 'HTTP备用'], [8443, 'HTTPS备用'], [27017, 'MongoDB']
];

function checkPort(host, port, timeoutMs) {
  return new Promise((resolve) => {
    const t0 = now();
    let done = false;
    const socket = net.connect({ host, port });
    const finish = (open, errCode) => {
      if (done) return;
      done = true;
      try { socket.destroy(); } catch (e) { /* ignore */ }
      resolve({ open, ms: open ? round1(now() - t0) : null, errCode: errCode || null });
    };
    socket.setTimeout(timeoutMs, () => finish(false, 'ETIMEDOUT'));
    socket.on('connect', () => finish(true, null));
    socket.on('error', (e) => finish(false, e.code || 'ERROR'));
  });
}

// ---------- 处理器 ----------
function nodeInfo() {
  return {
    region: process.env.RENDER_REGION || null,
    service: process.env.RENDER_SERVICE_NAME || process.env.RENDER_SERVICE_ID || null,
    externalUrl: process.env.RENDER_EXTERNAL_URL || null,
    hostname: os.hostname(),
    node: process.version
  };
}

function serveIndex(res) {
  fs.readFile(path.join(ROOT, 'index.html'), (err, data) => {
    if (err) return sendJson(res, 404, { error: 'index.html 缺失' });
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
    res.end(data);
  });
}

function parseUrlParam(sp, res) {
  const raw = (sp.get('url') || '').trim();
  try {
    const u = new URL(raw);
    if (!/^https?:$/.test(u.protocol)) throw new Error('bad protocol');
    return u;
  } catch (e) {
    sendJson(res, 400, { error: '请提供合法的 http/https URL' });
    return null;
  }
}

async function handleHttpTest(req, res, sp) {
  const u = parseUrlParam(sp, res);
  if (!u) return;
  const times = Math.max(1, Math.min(5, parseInt(sp.get('times'), 10) || 1));
  startStream(res);
  sendLine(res, { type: 'start', url: u.href, times });
  for (let i = 1; i <= times; i++) {
    try {
      const r = await timedRequest(u.href);
      sendLine(res, {
        type: 'result', index: i,
        status: r.status, statusMessage: r.statusMessage, httpVersion: r.httpVersion,
        size: r.size, truncated: r.truncated, ip: r.ip, family: r.family,
        tls: r.tls, timings: r.timings
      });
    } catch (e) {
      sendLine(res, { type: 'result', index: i, error: e.message });
    }
  }
  sendLine(res, { type: 'done' });
  res.end();
}

async function handlePing(req, res, sp) {
  const host = (sp.get('host') || '').trim();
  const port = Math.max(1, Math.min(65535, parseInt(sp.get('port'), 10) || 443));
  const count = Math.max(1, Math.min(10, parseInt(sp.get('count'), 10) || 4));
  if (!HOST_RE.test(host)) return sendJson(res, 400, { error: '请提供合法的域名或 IP' });

  let ip;
  try {
    const literal = net.isIP(host);
    if (literal) {
      if (isPrivateIp(host, literal)) return sendJson(res, 400, { error: '不允许检测私有/保留 IP' });
      ip = { address: host, family: literal };
    } else {
      ip = await lookupPublic(host);
    }
  } catch (e) {
    return sendJson(res, 400, { error: e.message });
  }

  startStream(res);
  sendLine(res, { type: 'start', host, ip: ip.address, port, count });
  let sent = 0;
  let received = 0;
  const times = [];
  for (let i = 1; i <= count; i++) {
    sent++;
    const r = await tcpPing(ip.address, port, 3000);
    if (r.ok) { received++; times.push(r.ms); }
    sendLine(res, { type: 'ping', seq: i, ok: r.ok, ms: r.ms, error: r.error });
  }
  const loss = sent ? round1(((sent - received) / sent) * 100) : 100;
  sendLine(res, {
    type: 'summary', sent, received, loss,
    min: times.length ? Math.min.apply(null, times) : null,
    avg: times.length ? round1(times.reduce((a, b) => a + b, 0) / times.length) : null,
    max: times.length ? Math.max.apply(null, times) : null
  });
  res.end();
}

async function handleDns(req, res, sp) {
  const host = (sp.get('host') || '').trim();
  const type = (sp.get('type') || 'ALL').toUpperCase();
  if (!HOST_RE.test(host)) return sendJson(res, 400, { error: '请提供合法的域名' });
  const allTypes = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SOA', 'CAA'];
  const want = type === 'ALL' ? allTypes : allTypes.filter((t) => t === type);
  if (!want.length) return sendJson(res, 400, { error: '不支持的记录类型: ' + type });
  const records = {};
  await Promise.all(want.map(async (t) => {
    try {
      const rr = await resolveType(host, t);
      records[t] = { ok: true, records: rr };
    } catch (e) {
      const code = e.code || e.message;
      records[t] = { ok: false, error: /ENODATA|ENOTFOUND/.test(code) ? '无记录' : String(code) };
    }
  }));
  sendJson(res, 200, { host, type, records });
}

async function handlePort(req, res, sp) {
  const host = (sp.get('host') || '').trim();
  if (!HOST_RE.test(host)) return sendJson(res, 400, { error: '请提供合法的域名或 IP' });
  let ports;
  const portsParam = (sp.get('ports') || '').trim();
  if (portsParam) {
    let list = portsParam.split(/[,\s，、]+/).map((x) => parseInt(x, 10)).filter((n) => n >= 1 && n <= 65535);
    list = Array.from(new Set(list)).slice(0, 12);
    if (!list.length) return sendJson(res, 400, { error: '请提供有效端口 (1-65535)' });
    ports = list.map((p) => [p, '自定义']);
  } else {
    ports = COMMON_PORTS;
  }

  let ip;
  try {
    const literal = net.isIP(host);
    if (literal) {
      if (isPrivateIp(host, literal)) return sendJson(res, 400, { error: '不允许检测私有/保留 IP' });
      ip = { address: host, family: literal };
    } else {
      ip = await lookupPublic(host);
    }
  } catch (e) {
    return sendJson(res, 400, { error: e.message });
  }

  startStream(res);
  const t0 = now();
  sendLine(res, { type: 'start', host, ip: ip.address, ports: ports.map((p) => p[0]) });
  let open = 0;
  const BATCH = 8;
  for (let i = 0; i < ports.length; i += BATCH) {
    const batch = ports.slice(i, i + BATCH);
    const results = await Promise.all(batch.map(async ([p, svc]) => {
      const r = await checkPort(ip.address, p, 2500);
      if (r.open) open++;
      return { type: 'port', port: p, service: svc, open: r.open, ms: r.ms, errCode: r.errCode };
    }));
    results.forEach((r) => sendLine(res, r));
  }
  sendLine(res, { type: 'summary', open, total: ports.length, elapsedMs: round1(now() - t0) });
  res.end();
}

async function handleHeaders(req, res, sp) {
  const u = parseUrlParam(sp, res);
  if (!u) return;
  try {
    const r = await timedRequest(u.href, { timeoutMs: 12000 });
    sendJson(res, 200, r);
  } catch (e) {
    sendJson(res, 502, { error: e.message });
  }
}

// ---------- IP 检测 ----------
function firstHeader(req, name) {
  const v = req.headers[name];
  if (Array.isArray(v)) return v[0] || '';
  return v || '';
}

const VERCEL_GEO_KEYS = [
  ['x-vercel-ip-country', 'country'],
  ['x-vercel-ip-country-region', 'region'],
  ['x-vercel-ip-city', 'city'],
  ['x-vercel-ip-latitude', 'latitude'],
  ['x-vercel-ip-longitude', 'longitude'],
  ['x-vercel-ip-timezone', 'timezone'],
  ['x-vercel-ip-postal-code', 'postalCode'],
  ['x-vercel-ip-continent', 'continent']
];

function getClientIp(req) {
  const raw = firstHeader(req, 'x-forwarded-for');
  let ip = raw ? String(raw).split(',')[0].trim() : '';
  if (!ip) ip = firstHeader(req, 'x-real-ip');
  if (!ip && req.socket && req.socket.remoteAddress) ip = req.socket.remoteAddress;
  ip = String(ip || '');
  if (/^::ffff:/i.test(ip)) ip = ip.slice(7);
  const family = net.isIP(ip);
  return { ip, family: family || 0 };
}

function parseVercelRegion(req) {
  const id = firstHeader(req, 'x-vercel-id');
  return id ? String(id).split(':')[0] : '';
}

function handleIp(req, res) {
  // 本地调试：设置 LITEDOG_TEST_IP 可模拟公网客户端 IP
  const testIp = process.env.LITEDOG_TEST_IP || '';
  const { ip, family } = testIp ? { ip: testIp, family: net.isIP(testIp) } : getClientIp(req);
  const geo = {};
  for (const [h, k] of VERCEL_GEO_KEYS) {
    let v = firstHeader(req, h);
    if (!v) continue;
    try { v = decodeURIComponent(v); } catch (e) { /* ignore */ }
    geo[k] = v;
  }
  sendJson(res, 200, {
    ip,
    family,
    version: family === 6 ? 'IPv6' : (family === 4 ? 'IPv4' : '未知'),
    geo,
    host: firstHeader(req, 'host'),
    protocol: firstHeader(req, 'x-forwarded-proto') || 'https',
    edgeRegion: parseVercelRegion(req),
    userAgent: firstHeader(req, 'user-agent'),
    serverNode: process.version,
    time: new Date().toISOString()
  });
}

// ---------- IP 质量检测（IPinfo + ip-api.com） ----------
async function fetchJsonTimeout(url, timeoutMs) {
  const r = await fetch(url, { signal: AbortSignal.timeout(timeoutMs || 6000), headers: { 'User-Agent': 'LiteDog/1.0' } });
  if (!r.ok) throw new Error('HTTP ' + r.status);
  return r.json();
}

function orgLooksHosting(s) {
  return /cloud|amazon|aws|azure|google|aliyun|alibaba|tencent|digitalocean|linode|vultr|ovh|hetzner|hosting|server|data ?cent|idc|colo|oracle|microsoft|leaseweb|choopa/i.test(s || '');
}

function classifyIpType(ipapi, lite) {
  if (ipapi && ipapi.mobile) return { key: 'mobile', label: '移动网络' };
  if (ipapi && ipapi.hosting) return { key: 'hosting', label: 'IDC 机房 IP' };
  if (ipapi && ipapi.proxy) return { key: 'proxy', label: '代理 / VPN' };
  const s = ((ipapi && (ipapi.isp || ipapi.org)) || '') + ' ' + ((lite && (lite.as_name || lite.as_domain)) || '');
  if (orgLooksHosting(s)) return { key: 'hosting', label: 'IDC 机房 IP' };
  return { key: 'isp', label: '住宅 / 商业宽带' };
}

function calcRisk(ipapi, type) {
  let score = 15;
  if (ipapi) {
    if (ipapi.proxy) score += 45;
    if (ipapi.hosting) score += 20;
    if (ipapi.mobile) score += 5;
  }
  if (type.key === 'proxy') score = Math.max(score, 70);
  score = Math.max(0, Math.min(100, Math.round(score)));
  const label = score < 30 ? '低风险' : (score < 60 ? '中性' : '高风险');
  return { score, label };
}

function estimateSharing(ipapi, type) {
  if (type.key === 'hosting') return { text: '可能多人共享', level: '差' };
  if (type.key === 'proxy') return { text: '代理池共享', level: '差' };
  if (type.key === 'mobile') return { text: '移动 NAT 共享', level: '一般' };
  return { text: '1 - 10', level: '极好' };
}

function guessNative(type) {
  if (type.key === 'hosting') return { native: false, label: '广播 IP（估算）' };
  return { native: true, label: '原生 IP（估算）' };
}

function sceneScores(type, risk) {
  const s = (type.key === 'hosting' || risk.score >= 60) ? 1 : (risk.score < 30 ? (type.key === 'isp' ? 5 : 4) : 3);
  const stars = Math.max(1, Math.min(5, s));
  return [
    { name: 'TikTok', stars },
    { name: '跨境电商', stars },
    { name: '社媒运营', stars },
    { name: 'AI 应用', stars: type.key === 'hosting' ? 2 : stars }
  ];
}

// 解析 Scamalytics 免费查询页中的欺诈分值与风险等级
function parseScamalytics(html) {
  const sm = html.match(/Fraud Score:\s*(\d+)/i);
  if (!sm) return null;
  const rm = html.match(/panel_title[^>]*>\s*([A-Za-z ]{3,20}?Risk)\s*</i);
  return { score: parseInt(sm[1], 10), risk: rm ? rm[1].trim() : '' };
}

async function handleIpCheck(req, res, sp) {
  const t0 = Date.now();
  const hostParam = sp ? (sp.get('host') || '').trim() : '';
  let ip, family;
  if (hostParam) {
    // 查询指定的 IP 或域名
    const literal = net.isIP(hostParam);
    if (literal) {
      if (isPrivateIp(hostParam, literal)) return sendJson(res, 400, { error: '不允许查询私有/保留 IP' });
      ip = hostParam;
      family = literal;
    } else {
      if (!HOST_RE.test(hostParam)) return sendJson(res, 400, { error: '请提供合法的 IP 或域名' });
      try {
        const pub = await lookupPublic(hostParam);
        ip = pub.address;
        family = pub.family;
      } catch (e) {
        return sendJson(res, 400, { error: e.message });
      }
    }
  } else {
    // 默认查询访客自己的出口 IP；本地调试可用 LITEDOG_TEST_IP 模拟
    const testIp = process.env.LITEDOG_TEST_IP || '';
    const own = testIp ? { ip: testIp, family: net.isIP(testIp) } : getClientIp(req);
    ip = own.ip;
    family = own.family;
    if (!net.isIP(ip)) return sendJson(res, 400, { error: '无法识别客户端 IP' });
    if (!testIp && isPrivateIp(ip, family)) return sendJson(res, 400, { error: '私有/本地 IP，无法做质量检测' });
  }
  const token = process.env.IPINFO_TOKEN || '';
  const q = token ? ('?token=' + encodeURIComponent(token)) : '';
  const browserUa = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36';
  const jobs = [
    fetchJsonTimeout('https://api.ipinfo.io/lite/' + encodeURIComponent(ip) + q, 6000),
    fetchJsonTimeout('https://ipinfo.io/' + encodeURIComponent(ip) + '/json' + q, 6000),
    fetchJsonTimeout('http://ip-api.com/json/' + encodeURIComponent(ip) + '?fields=status,country,countryCode,regionName,city,isp,org,as,asname,mobile,proxy,hosting,query', 6000),
    // 中文数据源（ip-api 支持 lang=zh-CN），用于中英双语展示
    fetchJsonTimeout('http://ip-api.com/json/' + encodeURIComponent(ip) + '?lang=zh-CN&fields=status,country,regionName,city,isp,org,as,asname', 6000),
    // Scamalytics 欺诈值（解析其免费查询页，失败不影响主流程）
    (async () => {
      const r = await fetch('https://scamalytics.com/ip/' + encodeURIComponent(ip), {
        signal: AbortSignal.timeout(8000),
        headers: { 'User-Agent': browserUa, 'Accept-Language': 'en-US,en;q=0.9' }
      });
      if (!r.ok) throw new Error('HTTP ' + r.status);
      return parseScamalytics(await r.text());
    })(),
    // CIDR 网段（RIPEstat 公开接口，失败则忽略）
    (async () => {
      const r = await fetch('https://stat.ripe.net/data/prefix-overview/data.json?resource=' + encodeURIComponent(ip), {
        signal: AbortSignal.timeout(6000),
        headers: { 'User-Agent': 'LiteDog/1.0' }
      });
      if (!r.ok) throw new Error('HTTP ' + r.status);
      const j = await r.json();
      return (j && j.data && j.data.resource) || null;
    })()
  ];
  const [liteR, infoR, apiR, zhR, scamR, bgpR] = await Promise.allSettled(jobs);
  const lite = liteR.status === 'fulfilled' ? liteR.value : null;
  const info = infoR.status === 'fulfilled' ? infoR.value : null;
  const ipapi = (apiR.status === 'fulfilled' && apiR.value && apiR.value.status === 'success') ? apiR.value : null;
  const zhApi = (zhR.status === 'fulfilled' && zhR.value && zhR.value.status === 'success') ? zhR.value : null;
  const zh = zhApi ? {
    country: zhApi.country || '',
    region: zhApi.regionName || '',
    city: zhApi.city || '',
    isp: zhApi.isp || '',
    org: zhApi.org || '',
    as: zhApi.as || '',
    asname: zhApi.asname || ''
  } : null;
  const fraud = (scamR.status === 'fulfilled' && scamR.value) ? scamR.value : null;
  const cidr = bgpR.status === 'fulfilled' ? bgpR.value : null;
  const type = classifyIpType(ipapi, lite);
  const risk = calcRisk(ipapi, type);
  const sharing = estimateSharing(ipapi, type);
  const native = guessNative(type);
  sendJson(res, 200, {
    ip,
    family,
    version: family === 6 ? 'IPv6' : 'IPv4',
    type,
    risk,
    fraud,
    cidr,
    zh,
    elapsedMs: Date.now() - t0,
    sharing,
    native,
    scenes: sceneScores(type, risk),
    asn: {
      number: (lite && lite.asn) || (ipapi && ipapi.as) || '',
      name: (lite && lite.as_name) || '',
      domain: (lite && lite.as_domain) || '',
      isp: (ipapi && ipapi.isp) || '',
      org: (ipapi && ipapi.org) || (info && info.org) || ''
    },
    geo: {
      // 国家/地区/城市优先取 ip-api（与中文数据同源，保证中英对照一致）
      country: (ipapi && ipapi.country) || (lite && lite.country) || (info && info.country) || '',
      countryCode: (ipapi && ipapi.countryCode) || (lite && lite.country_code) || (info && info.country) || '',
      region: (ipapi && ipapi.regionName) || (info && info.region) || '',
      city: (ipapi && ipapi.city) || (info && info.city) || '',
      loc: (info && info.loc) || '',
      timezone: (info && info.timezone) || ''
    },
    flags: {
      proxy: !!(ipapi && ipapi.proxy),
      hosting: !!(ipapi && ipapi.hosting),
      mobile: !!(ipapi && ipapi.mobile)
    },
    sources: { lite: !!lite, ipinfo: !!info, ipapi: !!ipapi },
    time: new Date().toISOString()
  });
}

// ---------- 路由 ----------
async function route(req, res) {
  if (req.method === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type'
    });
    res.end();
    return;
  }
  if (req.method !== 'GET') return sendJson(res, 405, { error: '仅支持 GET' });
  const u = new URL(req.url, 'http://localhost');
  const p = u.pathname;
  if (p === '/' || p === '/index.html') return serveIndex(res);
  if (p === '/api/nodeinfo') return sendJson(res, 200, nodeInfo());
  if (p === '/api/http') return handleHttpTest(req, res, u.searchParams);
  if (p === '/api/ping') return handlePing(req, res, u.searchParams);
  if (p === '/api/dns') return handleDns(req, res, u.searchParams);
  if (p === '/api/port') return handlePort(req, res, u.searchParams);
  if (p === '/api/headers') return handleHeaders(req, res, u.searchParams);
  if (p === '/api/ip') return handleIp(req, res);
  if (p === '/api/ipcheck') return handleIpCheck(req, res, u.searchParams);
  if (p === '/favicon.ico' || p === '/favicon.svg') {
    res.writeHead(200, { 'Content-Type': 'image/svg+xml' });
    return res.end('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><text y="82" font-size="82">⚡</text></svg>');
  }
  return sendJson(res, 404, { error: 'Not Found' });
}

const server = http.createServer((req, res) => {
  Promise.resolve(route(req, res)).catch((e) => {
    try { sendJson(res, 500, { error: e.message || '服务器内部错误' }); } catch (e2) { /* ignore */ }
  });
});

server.on('clientError', (err, socket) => {
  try { socket.end('HTTP/1.1 400 Bad Request\r\n\r\n'); } catch (e) { /* ignore */ }
});

if (require.main === module) {
  server.listen(PORT, '0.0.0.0', () => {
    console.log('LiteDog listening on 0.0.0.0:' + PORT);
  });
}

module.exports = { route, nodeInfo, handleHttpTest, handlePing, handleDns, handlePort, handleHeaders, handleIp, handleIpCheck, serveIndex };

process.on('uncaughtException', (e) => console.error('[uncaughtException]', e.message));
process.on('unhandledRejection', (e) => console.error('[unhandledRejection]', (e && e.message) || e));
