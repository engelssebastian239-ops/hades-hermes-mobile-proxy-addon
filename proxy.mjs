import http from 'node:http';

export const PROXY_DEFAULTS = Object.freeze({
  listenHost: '127.0.0.1',
  listenPort: 8098,
  upstreamHost: 'a90308c2-hermes-agent',
  upstreamPort: 8099,
  authCheckTimeoutMs: 1500,
  websocketAuthRecheckMs: 15000,
});

// Hermes v0.20.5 can emit PKCE and SSO marker cookies as well as the
// access/refresh/provider cookies. Treat every Hermes auth cookie as sensitive.
const HERMES_AUTH_COOKIE = /^(?:__Host-|__Secure-)?hermes_(?:session_[a-z0-9_]+|sso_attempt)=/i;
const HOP_BY_HOP = new Set([
  'connection',
  'keep-alive',
  'proxy-authenticate',
  'proxy-authorization',
  'te',
  'trailer',
  'transfer-encoding',
  'upgrade',
]);

function normalizePublicHost(value) {
  if (typeof value !== 'string') throw new Error('invalid_public_host');
  const host = value.trim().toLowerCase();
  if (
    !host ||
    host.length > 253 ||
    !/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+ts\.net$/.test(host)
  ) {
    throw new Error('invalid_public_host');
  }
  return host;
}

function safeHostHeader(value, expectedHost) {
  const host = String(value ?? '').toLowerCase();
  return host === expectedHost || host === expectedHost + ':443';
}

function safeOrigin(value, expectedHost) {
  if (value == null || value === '') return true;
  try {
    const origin = new URL(String(value));
    return (
      origin.protocol === 'https:' &&
      origin.hostname.toLowerCase() === expectedHost &&
      (origin.port === '' || origin.port === '443') &&
      origin.username === '' &&
      origin.password === '' &&
      origin.pathname === '/' &&
      origin.search === '' &&
      origin.hash === ''
    );
  } catch {
    return false;
  }
}

function requestPath(req) {
  if (typeof req.url !== 'string' || !req.url.startsWith('/') || req.url.startsWith('//')) {
    return null;
  }
  try {
    const parsed = new URL(req.url, 'https://proxy.invalid');
    return parsed.origin === 'https://proxy.invalid' ? parsed.pathname : null;
  } catch {
    return null;
  }
}

function authProviderPresent(value) {
  const providers = Array.isArray(value) ? value : value?.providers;
  if (!Array.isArray(providers)) return false;
  return providers.some((provider) =>
    typeof provider === 'string'
      ? provider === 'basic'
      : provider && typeof provider === 'object' && provider.name === 'basic',
  );
}

function cookieParts(cookie) {
  const [pair, ...rawAttributes] = String(cookie).split(';');
  const attributes = new Map(
    rawAttributes.map((attribute) => {
      const index = attribute.indexOf('=');
      return index < 0
        ? [attribute.trim().toLowerCase(), '']
        : [
            attribute.slice(0, index).trim().toLowerCase(),
            attribute.slice(index + 1).trim().toLowerCase(),
          ];
    }),
  );
  return { pair: pair.trim(), attributes };
}

function isCookieDeletion(attributes) {
  const maxAge = attributes.get('max-age');
  return maxAge !== undefined && Number.isFinite(Number(maxAge)) && Number(maxAge) <= 0;
}

function sessionCookieIsSecure(cookie) {
  const { pair, attributes } = cookieParts(cookie);
  if (!HERMES_AUTH_COOKIE.test(pair)) return true;
  if (attributes.has('domain')) return false;
  if (!isCookieDeletion(attributes) && !pair.toLowerCase().startsWith('__host-')) return false;
  return (
    attributes.has('secure') &&
    attributes.has('httponly') &&
    attributes.get('path') === '/' &&
    ['lax', 'strict'].includes(attributes.get('samesite'))
  );
}

function hasSecureAccessCookie(cookies) {
  return (cookies ?? []).some((cookie) => {
    const pair = String(cookie).split(';', 1)[0].trim();
    return /^__Host-hermes_session_at=/i.test(pair) && sessionCookieIsSecure(cookie);
  });
}

function secureHermesAuthCookies(path, statusCode, sourceHeaders) {
  const cookies = setCookieHeaders(sourceHeaders);
  const secured = [];
  for (const original of cookies) {
    const { pair, attributes } = cookieParts(original);
    let cookie = original;
    if (HERMES_AUTH_COOKIE.test(pair) && isCookieDeletion(attributes) && !attributes.has('secure')) {
      // Hermes v0.20.5 clears every cookie-name variant with Max-Age=0 but
      // omits Secure on the deletion headers. This route is always HTTPS, so
      // add Secure at the edge; never relax validation for live credentials.
      cookie += '; Secure';
    }
    if (!sessionCookieIsSecure(cookie)) return null;
    secured.push(cookie);
  }
  if (path === '/auth/password-login' && statusCode >= 200 && statusCode < 300) {
    if (!hasSecureAccessCookie(secured)) return null;
  }
  if (cookies.length === 0) return sourceHeaders;
  return { ...sourceHeaders, 'set-cookie': secured };
}

function strippedHeaders(source, { publicHost, websocket = false }) {
  const connectionTokens = String(source.connection ?? '')
    .split(',')
    .map((token) => token.trim().toLowerCase())
    .filter(Boolean);
  const headers = {};

  for (const [rawName, value] of Object.entries(source)) {
    const name = rawName.toLowerCase();
    if (
      HOP_BY_HOP.has(name) ||
      connectionTokens.includes(name) ||
      name === 'host' ||
      name === 'forwarded' ||
      name === 'x-real-ip' ||
      name === 'true-client-ip' ||
      name === 'x-client-ip' ||
      name.startsWith('x-forwarded-')
    ) {
      continue;
    }
    headers[name] = value;
  }

  headers.host = publicHost;
  headers['x-forwarded-proto'] = 'https';
  headers['x-forwarded-host'] = publicHost;
  headers['x-forwarded-port'] = '443';
  if (websocket) {
    headers.connection = 'Upgrade';
    headers.upgrade = 'websocket';
  }
  return headers;
}

function writeError(res, statusCode, code, headers = {}) {
  const body = JSON.stringify({ error: code }) + '\n';
  res.writeHead(statusCode, {
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store',
    'content-length': Buffer.byteLength(body),
    ...headers,
  });
  res.end(body);
}

function writeSocketError(socket, statusCode, reason) {
  const body = JSON.stringify({ error: reason }) + '\n';
  socket.end(
    'HTTP/1.1 ' + statusCode + ' ' + reason + '\r\n' +
      'Content-Type: application/json; charset=utf-8\r\n' +
      'Cache-Control: no-store\r\n' +
      'Content-Length: ' + Buffer.byteLength(body) + '\r\n' +
      'Connection: close\r\n\r\n' +
      body,
  );
}

function fixedWindowLimiter({ now, max, windowMs }) {
  const buckets = new Map();
  return (key) => {
    const time = now();
    const current = buckets.get(key);
    if (!current || time - current.startedAt >= windowMs) {
      buckets.set(key, { startedAt: time, count: 1 });
      return false;
    }
    if (current.count >= max) return true;
    current.count += 1;
    return false;
  };
}

function readJsonEndpoint({ host, port, publicHost, path, timeoutMs, maxBytes }) {
  return new Promise((resolve) => {
    let settled = false;
    const finish = (value) => {
      if (settled) return;
      settled = true;
      resolve(value);
    };
    const req = http.request(
      {
        hostname: host,
        port,
        path,
        method: 'GET',
        headers: {
          host: publicHost,
          'x-forwarded-proto': 'https',
          'x-forwarded-host': publicHost,
          'x-forwarded-port': '443',
          connection: 'close',
        },
        timeout: timeoutMs,
      },
      (res) => {
        if (res.statusCode !== 200) {
          res.resume();
          finish(null);
          return;
        }
        let size = 0;
        const chunks = [];
        res.on('data', (chunk) => {
          size += chunk.length;
          if (size > maxBytes) {
            chunks.length = 0;
            res.destroy();
            finish(null);
          } else {
            chunks.push(chunk);
          }
        });
        res.on('end', () => {
          try {
            finish(JSON.parse(Buffer.concat(chunks).toString('utf8')));
          } catch {
            finish(null);
          }
        });
        res.on('error', () => finish(null));
      },
    );
    req.on('timeout', () => req.destroy(new Error('timeout')));
    req.on('error', () => finish(null));
    req.end();
  });
}

async function readAuthStatus({ host, port, publicHost, timeoutMs, maxBytes }) {
  const request = { host, port, publicHost, timeoutMs, maxBytes };
  const status = await readJsonEndpoint({ ...request, path: '/api/status' });
  if (status?.auth_required !== true && status?.auth_required !== false) {
    return { authRequired: null, basicProvider: null };
  }
  if (status.auth_required === false) {
    return { authRequired: false, basicProvider: null };
  }

  // Provider discovery is a separate public endpoint in the Hermes Dashboard
  // contract. Do not assume /api/status embeds provider metadata: that shape
  // is not part of its stable status payload.
  const providers = await readJsonEndpoint({ ...request, path: '/api/auth/providers' });
  if (!providers) return { authRequired: true, basicProvider: null };
  return { authRequired: true, basicProvider: authProviderPresent(providers) };
}

export async function inspectHermesAuthGate({
  host = PROXY_DEFAULTS.upstreamHost,
  port = PROXY_DEFAULTS.upstreamPort,
  publicHost = 'localhost',
  timeoutMs = PROXY_DEFAULTS.authCheckTimeoutMs,
  maxBytes = 16 * 1024,
} = {}) {
  try {
    return await readAuthStatus({ host, port, publicHost, timeoutMs, maxBytes });
  } catch {
    return { authRequired: null, basicProvider: null };
  }
}

function setCookieHeaders(headers) {
  const value = headers['set-cookie'];
  return value == null ? [] : Array.isArray(value) ? value : [value];
}

function responseHeaders(source) {
  const connectionTokens = String(source.connection ?? '')
    .split(',')
    .map((token) => token.trim().toLowerCase())
    .filter(Boolean);
  const headers = {};
  for (const [rawName, value] of Object.entries(source)) {
    const name = rawName.toLowerCase();
    if (HOP_BY_HOP.has(name) || connectionTokens.includes(name)) continue;
    headers[name] = value;
  }
  return headers;
}

export function createHermesProxy({
  publicHost,
  listenHost = PROXY_DEFAULTS.listenHost,
  listenPort = PROXY_DEFAULTS.listenPort,
  upstreamHost = PROXY_DEFAULTS.upstreamHost,
  upstreamPort = PROXY_DEFAULTS.upstreamPort,
  allowTokenOnly = false,
  authCheckTimeoutMs = PROXY_DEFAULTS.authCheckTimeoutMs,
  websocketAuthRecheckMs = PROXY_DEFAULTS.websocketAuthRecheckMs,
  maxAuthStatusBytes = 16 * 1024,
  loginLimit = 6,
  ticketLimit = 30,
  limiterWindowMs = 60_000,
  now = Date.now,
  logger = () => {},
} = {}) {
  const pinnedPublicHost = normalizePublicHost(publicHost);
  if (listenHost !== '127.0.0.1') throw new Error('loopback_only');
  if (!Number.isInteger(listenPort) || listenPort < 0 || listenPort > 65535) {
    throw new Error('invalid_listen_port');
  }
  if (
    typeof upstreamHost !== 'string' ||
    !/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$|^\d{1,3}(?:\.\d{1,3}){3}$/i.test(
      upstreamHost,
    ) ||
    !Number.isInteger(upstreamPort) ||
    upstreamPort < 1 ||
    upstreamPort > 65535
  ) {
    throw new Error('invalid_fixed_upstream');
  }

  const rateLimited = fixedWindowLimiter({ now, max: loginLimit, windowMs: limiterWindowMs });
  const ticketLimited = fixedWindowLimiter({ now, max: ticketLimit, windowMs: limiterWindowMs });
  let activeAuthChecks = 0;
  const activeWebSocketSockets = new Set();
  const authGateReady = () => {
    if (activeAuthChecks >= 32) return Promise.resolve(false);
    activeAuthChecks += 1;
    return readAuthStatus({
      host: upstreamHost,
      port: upstreamPort,
      publicHost: pinnedPublicHost,
      timeoutMs: authCheckTimeoutMs,
      maxBytes: maxAuthStatusBytes,
    }).finally(() => {
      activeAuthChecks -= 1;
    }).then((gate) =>
      (gate.authRequired === true && gate.basicProvider === true) ||
      (allowTokenOnly === true && gate.authRequired === false && gate.basicProvider === null),
    );
  };

  const server = http.createServer(async (req, res) => {
    const path = requestPath(req);
    if (!path) return writeError(res, 400, 'invalid_request_target');
    if (!safeHostHeader(req.headers.host, pinnedPublicHost)) {
      return writeError(res, 421, 'host_not_allowed');
    }
    if (!safeOrigin(req.headers.origin, pinnedPublicHost)) {
      return writeError(res, 403, 'origin_not_allowed');
    }

    if (path === '/auth/password-login' && req.method === 'POST' && rateLimited('password-login')) {
      return writeError(res, 429, 'login_rate_limited', { 'retry-after': '60' });
    }
    if (path === '/api/auth/ws-ticket' && req.method === 'POST' && ticketLimited('ws-ticket')) {
      return writeError(res, 429, 'ticket_rate_limited', { 'retry-after': '60' });
    }
    if (!(await authGateReady())) return writeError(res, 503, 'hermes_auth_unavailable');

    const headers = strippedHeaders(req.headers, { publicHost: pinnedPublicHost });
    const upstream = http.request({
      hostname: upstreamHost,
      port: upstreamPort,
      method: req.method,
      path: req.url,
      headers,
    });
    upstream.on('response', (upstreamRes) => {
      const secureHeaders = secureHermesAuthCookies(
        path,
        upstreamRes.statusCode ?? 502,
        upstreamRes.headers,
      );
      if (secureHeaders === null) {
        upstreamRes.resume();
        logger({ event: 'proxy_rejected_insecure_cookie' });
        return writeError(res, 502, 'upstream_cookie_policy_failed');
      }
      res.writeHead(upstreamRes.statusCode ?? 502, responseHeaders(secureHeaders));
      upstreamRes.pipe(res);
    });
    upstream.on('error', (error) => {
      logger({ event: 'proxy_upstream_error', code: typeof error.code === 'string' ? error.code : 'unknown' });
      if (!res.headersSent) writeError(res, 502, 'upstream_unavailable');
      else res.destroy();
    });
    req.on('aborted', () => upstream.destroy());
    req.pipe(upstream);
  });

  server.on('upgrade', async (req, clientSocket, clientHead) => {
    const path = requestPath(req);
    if (!path || !safeHostHeader(req.headers.host, pinnedPublicHost)) {
      return writeSocketError(clientSocket, 421, 'host_not_allowed');
    }
    if (
      !safeOrigin(req.headers.origin, pinnedPublicHost) ||
      String(req.headers.upgrade ?? '').toLowerCase() !== 'websocket' ||
      !String(req.headers.connection ?? '')
        .split(',')
        .some((part) => part.trim().toLowerCase() === 'upgrade') ||
      !req.headers['sec-websocket-key'] ||
      String(req.headers['sec-websocket-version'] ?? '') !== '13'
    ) {
      return writeSocketError(clientSocket, 400, 'invalid_websocket_upgrade');
    }
    if (!(await authGateReady())) return writeSocketError(clientSocket, 503, 'hermes_auth_unavailable');

    const headers = strippedHeaders(req.headers, { publicHost: pinnedPublicHost, websocket: true });
    const upstream = http.request({
      hostname: upstreamHost,
      port: upstreamPort,
      method: 'GET',
      path: req.url,
      headers,
    });
    let upgraded = false;
    upstream.on('upgrade', (upstreamRes, upstreamSocket, upstreamHead) => {
      if (upstreamRes.statusCode !== 101) {
        upstreamSocket.destroy();
        return writeSocketError(clientSocket, 502, 'upstream_upgrade_failed');
      }
      upgraded = true;
      clientSocket.write('HTTP/' + upstreamRes.httpVersion + ' ' + upstreamRes.statusCode + ' ' + upstreamRes.statusMessage + '\r\n');
      for (let i = 0; i < upstreamRes.rawHeaders.length; i += 2) {
        clientSocket.write(upstreamRes.rawHeaders[i] + ': ' + upstreamRes.rawHeaders[i + 1] + '\r\n');
      }
      clientSocket.write('\r\n');
      if (upstreamHead.length) clientSocket.write(upstreamHead);
      if (clientHead.length) upstreamSocket.write(clientHead);
      clientSocket.pipe(upstreamSocket);
      upstreamSocket.pipe(clientSocket);
      activeWebSocketSockets.add(clientSocket);
      activeWebSocketSockets.add(upstreamSocket);

      let checking = false;
      const monitor = setInterval(async () => {
        if (checking || clientSocket.destroyed || upstreamSocket.destroyed) return;
        checking = true;
        try {
          if (!(await authGateReady())) {
            logger({ event: 'proxy_websocket_closed_auth_unavailable' });
            clientSocket.destroy();
            upstreamSocket.destroy();
          }
        } finally {
          checking = false;
        }
      }, websocketAuthRecheckMs);
      monitor.unref();
      const cleanup = () => {
        clearInterval(monitor);
        activeWebSocketSockets.delete(clientSocket);
        activeWebSocketSockets.delete(upstreamSocket);
        if (!clientSocket.destroyed) clientSocket.destroy();
        if (!upstreamSocket.destroyed) upstreamSocket.destroy();
      };
      clientSocket.once('close', cleanup);
      upstreamSocket.once('close', cleanup);
    });
    upstream.on('response', (upstreamRes) => {
      const status = upstreamRes.statusCode ?? 502;
      const headersRaw = upstreamRes.rawHeaders;
      clientSocket.write('HTTP/' + upstreamRes.httpVersion + ' ' + status + ' ' + upstreamRes.statusMessage + '\r\n');
      for (let i = 0; i < headersRaw.length; i += 2) {
        clientSocket.write(headersRaw[i] + ': ' + headersRaw[i + 1] + '\r\n');
      }
      clientSocket.write('\r\n');
      upstreamRes.pipe(clientSocket);
    });
    upstream.on('error', (error) => {
      logger({ event: 'proxy_websocket_upstream_error', code: typeof error.code === 'string' ? error.code : 'unknown' });
      if (!clientSocket.destroyed && !upgraded) {
        writeSocketError(clientSocket, 502, 'upstream_unavailable');
      } else {
        clientSocket.destroy();
      }
    });
    clientSocket.once('close', () => upstream.destroy());
    upstream.end();
  });

  server.on('connect', (_req, socket) => writeSocketError(socket, 405, 'method_not_allowed'));
  server.headersTimeout = 10_000;
  server.requestTimeout = 120_000;
  server.keepAliveTimeout = 5_000;
  server.maxHeadersCount = 100;

  return {
    server,
    authGateReady,
    async listen() {
      if (!(await authGateReady())) throw new Error('hermes_auth_unavailable');
      await new Promise((resolve, reject) => {
        server.once('error', reject);
        server.listen(listenPort, listenHost, () => {
          server.removeListener('error', reject);
          resolve();
        });
      });
      return server.address();
    },
    async close() {
      for (const socket of activeWebSocketSockets) socket.destroy();
      activeWebSocketSockets.clear();
      if (!server.listening) return;
      await new Promise((resolve, reject) => {
        server.close((error) => (error ? reject(error) : resolve()));
        server.closeAllConnections?.();
      });
    },
  };
}

export function secureAccessCookieForTest(cookie) {
  return sessionCookieIsSecure(cookie);
}

export function secureHermesAuthCookiesForTest(path, statusCode, headers) {
  return secureHermesAuthCookies(path, statusCode, headers);
}
