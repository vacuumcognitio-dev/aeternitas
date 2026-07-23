const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const PORT = Number(process.env.PORT || 3000);
const USERNAME = process.env.AETERNITAS_USER;
const PASSWORD = process.env.AETERNITAS_PASSWORD;
const ROOT = __dirname;
const SESSION_TTL = 2 * 60 * 60 * 1000;
const MAX_ATTEMPTS = 5;
const WINDOW_MS = 15 * 60 * 1000;
const sessions = new Map();
const attempts = new Map();

if (!USERNAME || !PASSWORD) {
  console.error('Defina AETERNITAS_USER e AETERNITAS_PASSWORD antes de iniciar o servidor.');
  process.exit(1);
}

const publicFiles = new Map([
  ['/', 'index.html'], ['/index.html', 'index.html'], ['/sobre.html', 'sobre.html'],
  ['/atualizacoes.html', 'atualizacoes.html'], ['/download.html', 'download.html'],
  ['/css/style.css', 'css/style.css'], ['/js/app.js', 'js/app.js'],
]);
const contentTypes = { '.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8', '.png': 'image/png' };

function safeEqual(left, right) {
  const a = Buffer.from(left);
  const b = Buffer.from(right);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}
function cookies(request) {
  return Object.fromEntries((request.headers.cookie || '').split(';').map((item) => {
    const [key, ...value] = item.trim().split('=');
    return [key, decodeURIComponent(value.join('='))];
  }).filter(([key]) => key));
}
function activeSession(request) {
  const token = cookies(request).aeternitas_session;
  const session = token && sessions.get(token);
  if (!session || session.expires < Date.now()) {
    if (token) sessions.delete(token);
    return false;
  }
  return true;
}
function securityHeaders(response) {
  response.setHeader('X-Content-Type-Options', 'nosniff');
  response.setHeader('X-Frame-Options', 'DENY');
  response.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  response.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  response.setHeader('Content-Security-Policy', "default-src 'self'; style-src 'self' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src 'self'; script-src 'self'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'");
}
function json(response, status, payload) {
  response.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' });
  response.end(JSON.stringify(payload));
}
function sendFile(response, file) {
  fs.readFile(path.join(ROOT, file), (error, data) => {
    if (error) return json(response, 404, { error: 'Arquivo não encontrado.' });
    response.writeHead(200, { 'Content-Type': contentTypes[path.extname(file)] || 'application/octet-stream' });
    response.end(data);
  });
}
function clientIp(request) { return request.socket.remoteAddress || 'unknown'; }
function isBlocked(ip) {
  const record = attempts.get(ip);
  if (!record || record.until < Date.now()) { attempts.delete(ip); return false; }
  return record.count >= MAX_ATTEMPTS;
}
function registerFailure(ip) {
  const record = attempts.get(ip);
  if (!record || record.until < Date.now()) attempts.set(ip, { count: 1, until: Date.now() + WINDOW_MS });
  else record.count += 1;
}
setInterval(() => {
  const now = Date.now();
  for (const [token, session] of sessions) if (session.expires < now) sessions.delete(token);
}, 15 * 60 * 1000).unref();

const server = http.createServer((request, response) => {
  securityHeaders(response);
  const url = new URL(request.url, 'http://' + (request.headers.host || 'localhost'));
  const pathname = url.pathname;

  if (request.method === 'GET' && pathname === '/api/session') return json(response, 200, { authenticated: activeSession(request) });
  if (request.method === 'POST' && pathname === '/api/logout') {
    const token = cookies(request).aeternitas_session;
    if (token) sessions.delete(token);
    response.setHeader('Set-Cookie', 'aeternitas_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0');
    return json(response, 200, { ok: true });
  }
  if (request.method === 'POST' && pathname === '/api/login') {
    const ip = clientIp(request);
    if (isBlocked(ip)) return json(response, 429, { error: 'Muitas tentativas. Tente novamente mais tarde.' });
    let body = '';
    request.on('data', (chunk) => { body += chunk; if (body.length > 10000) request.destroy(); });
    request.on('end', () => {
      try {
        const data = JSON.parse(body);
        if (!safeEqual(String(data.username || ''), USERNAME) || !safeEqual(String(data.password || ''), PASSWORD)) {
          registerFailure(ip);
          return json(response, 401, { error: 'Usuário ou senha incorretos.' });
        }
        attempts.delete(ip);
        const token = crypto.randomBytes(32).toString('base64url');
        sessions.set(token, { expires: Date.now() + SESSION_TTL });
        const secure = (request.headers['x-forwarded-proto'] === 'https' || request.socket.encrypted) ? '; Secure' : '';
        response.setHeader('Set-Cookie', 'aeternitas_session=' + token + '; HttpOnly; SameSite=Strict; Path=/; Max-Age=' + (SESSION_TTL / 1000) + secure);
        return json(response, 200, { ok: true });
      } catch { return json(response, 400, { error: 'Solicitação inválida.' }); }
    });
    return;
  }
  if (request.method === 'GET' && /^\/downloads\/Insania-win(32|64)\.exe$/.test(pathname)) {
    if (!activeSession(request)) return json(response, 401, { error: 'Acesso não autorizado.' });
    const file = pathname.slice(1);
    response.setHeader('Content-Disposition', 'attachment; filename="' + path.basename(file) + '"');
    return sendFile(response, file);
  }
  if (request.method === 'GET' && publicFiles.has(pathname)) return sendFile(response, publicFiles.get(pathname));
  return json(response, 404, { error: 'Página não encontrada.' });
});

server.listen(PORT, () => console.log('Aeternitas em http://localhost:' + PORT));
