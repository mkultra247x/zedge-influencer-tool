const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = process.env.PORT || 3000;
const RESEND_API_KEY = process.env.RESEND_API_KEY || '';
const APP_URL = process.env.APP_URL || `http://localhost:${PORT}`;
const ALLOWED_DOMAIN = '@zedge.net';
const TOKEN_EXPIRY_MS = 15 * 60 * 1000; // 15 minutes
const SESSION_EXPIRY_MS = 7 * 24 * 60 * 60 * 1000; // 7 days

// In-memory stores (fine for single instance)
const pendingTokens = new Map(); // token -> { email, expires }
const sessions = new Map();      // sessionId -> { email, expires }

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
  return session.email;
}

async function sendMagicLink(email, token) {
  const link = `${APP_URL}/auth/verify?token=${token}`;
  
  if (!RESEND_API_KEY) {
    console.log(`\n📧 Magic link for ${email}: ${link}\n`);
    return true;
  }

  const res = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${RESEND_API_KEY}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      from: 'Zedge Influencer Finder <noreply@resend.dev>',
      to: email,
      subject: '🔑 Your login link — Zedge Influencer Finder',
      html: `
        <div style="font-family:sans-serif;max-width:480px;margin:0 auto;padding:40px 20px;">
          <h2 style="color:#6c5ce7;">Zedge Influencer Finder</h2>
          <p>Click the button below to sign in. This link expires in 15 minutes.</p>
          <a href="${link}" style="display:inline-block;background:#6c5ce7;color:white;padding:14px 28px;border-radius:8px;text-decoration:none;font-weight:600;margin:20px 0;">Sign In →</a>
          <p style="color:#888;font-size:13px;">If you didn't request this, ignore this email.</p>
          <p style="color:#888;font-size:12px;">Or copy this link: ${link}</p>
        </div>
      `
    })
  });
  return res.ok;
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);
  
  // --- API: Request magic link ---
  if (url.pathname === '/auth/login' && req.method === 'POST') {
    const { email } = await parseBody(req);
    
    if (!email || !email.toLowerCase().endsWith(ALLOWED_DOMAIN)) {
      res.writeHead(403, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ error: `Only ${ALLOWED_DOMAIN} emails are allowed.` }));
    }

    const token = crypto.randomBytes(32).toString('hex');
    pendingTokens.set(token, { email: email.toLowerCase(), expires: Date.now() + TOKEN_EXPIRY_MS });
    
    const sent = await sendMagicLink(email.toLowerCase(), token);
    
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({ ok: true, message: 'Check your email for the login link.' }));
  }

  // --- Verify magic link ---
  if (url.pathname === '/auth/verify') {
    const token = url.searchParams.get('token');
    const pending = pendingTokens.get(token);
    
    if (!pending || Date.now() > pending.expires) {
      pendingTokens.delete(token);
      res.writeHead(200, { 'Content-Type': 'text/html' });
      return res.end(`<html><body style="font-family:sans-serif;display:flex;justify-content:center;align-items:center;height:100vh;background:#0f0f13;color:#ff6b6b;"><div style="text-align:center;"><h2>Link expired or invalid</h2><p><a href="/" style="color:#a29bfe;">Request a new one →</a></p></div></body></html>`);
    }

    pendingTokens.delete(token);
    const sessionId = crypto.randomBytes(32).toString('hex');
    sessions.set(sessionId, { email: pending.email, expires: Date.now() + SESSION_EXPIRY_MS });
    
    res.writeHead(302, {
      'Set-Cookie': `session=${sessionId}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${SESSION_EXPIRY_MS / 1000}`,
      'Location': '/'
    });
    return res.end();
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

  // --- Auth status ---
  if (url.pathname === '/auth/status') {
    const email = isAuthenticated(req);
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({ authenticated: !!email, email: email || null }));
  }

  // --- Main page ---
  const email = isAuthenticated(req);
  if (!email) {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    return res.end(loginHtml);
  }

  res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
  res.end(appHtml);
});

// Cleanup expired tokens/sessions every 5 min
setInterval(() => {
  const now = Date.now();
  for (const [k, v] of pendingTokens) if (now > v.expires) pendingTokens.delete(k);
  for (const [k, v] of sessions) if (now > v.expires) sessions.delete(k);
}, 5 * 60 * 1000);

server.listen(PORT, () => console.log(`Server running on port ${PORT}`));
