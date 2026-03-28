const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = process.env.PORT || 3000;
const ACCESS_PASSWORD = process.env.ACCESS_PASSWORD || 'zedge2026';
const SESSION_EXPIRY_MS = 7 * 24 * 60 * 60 * 1000; // 7 days

const sessions = new Map(); // sessionId -> { expires }

const loginHtml = fs.readFileSync(path.join(__dirname, 'login.html'), 'utf8');
const appHtml = fs.readFileSync(path.join(__dirname, 'index.html'), 'utf8');

function parseBody(req) {
  return new Promise((resolve) => {
    let body = '';
    req.on('data', c => body += c);
    req.on('end', () => {
      try { resolve(JSON.parse(body)); } catch { resolve({}); }
    });
  });
}

function parseCookies(req) {
  const cookies = {};
  (req.headers.cookie || '').split(';').forEach(c => {
    const [k, v] = c.trim().split('=');
    if (k) cookies[k] = v;
  });
  return cookies;
}

function isAuthenticated(req) {
  const cookies = parseCookies(req);
  const sid = cookies.session;
  if (!sid) return false;
  const session = sessions.get(sid);
  if (!session) return false;
  if (Date.now() > session.expires) { sessions.delete(sid); return false; }
  return true;
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);
  
  // --- Login with password ---
  if (url.pathname === '/auth/login' && req.method === 'POST') {
    const { password } = await parseBody(req);
    
    if (!password || password !== ACCESS_PASSWORD) {
      res.writeHead(403, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ error: 'Wrong password.' }));
    }

    const sessionId = crypto.randomBytes(32).toString('hex');
    sessions.set(sessionId, { expires: Date.now() + SESSION_EXPIRY_MS });
    
    res.writeHead(200, {
      'Content-Type': 'application/json',
      'Set-Cookie': `session=${sessionId}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${SESSION_EXPIRY_MS / 1000}`
    });
    return res.end(JSON.stringify({ ok: true }));
  }

  // --- Logout ---
  if (url.pathname === '/auth/logout') {
    const cookies = parseCookies(req);
    if (cookies.session) sessions.delete(cookies.session);
    res.writeHead(302, {
      'Set-Cookie': 'session=; Path=/; HttpOnly; Max-Age=0',
      'Location': '/'
    });
    return res.end();
  }

  // --- Main page ---
  if (!isAuthenticated(req)) {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    return res.end(loginHtml);
  }

  res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
  res.end(appHtml);
});

// Cleanup expired sessions every 5 min
setInterval(() => {
  const now = Date.now();
  for (const [k, v] of sessions) if (now > v.expires) sessions.delete(k);
}, 5 * 60 * 1000);

server.listen(PORT, () => console.log(`Server running on port ${PORT}`));
