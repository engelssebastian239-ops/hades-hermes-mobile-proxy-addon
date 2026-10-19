import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import net from 'node:net';
import test from 'node:test';
import {
  createHermesProxy,
  PROXY_DEFAULTS,
  secureAccessCookieForTest,
  secureHermesAuthCookiesForTest,
} from '../proxy.mjs';

const publicHost = 'svc-hermes.tailnet.ts.net';
const secureCookie =
  '__Host-hermes_session_at=synthetic-cookie; Path=/; HttpOnly; SameSite=Lax; Secure';

function listen(server) {
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      server.removeListener('error', reject);
      resolve(server.address().port);
    });
  });
}

function request(port, {
  path = '/api/status',
  method = 'GET',
  headers = {},
  body,
} = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request(
      {
        hostname: '127.0.0.1',
        port,
        path,
        method,
        headers: { host: publicHost, ...headers },
      },
      (res) => {
        const chunks = [];
        res.on('data', (chunk) => chunks.push(chunk));
        res.on('end', () =>
          resolve({
            status: res.statusCode,
            headers: res.headers,
            body: Buffer.concat(chunks).toString('utf8'),
          }),
        );
      },
    );
    req.on('error', reject);
    if (body) req.write(body);
    req.end();
  });
}

function statusBody(authRequired = true) {
  return JSON.stringify({ auth_required: authRequired });
}

async function harness({
  authRequired = true,
  providers = [{ name: 'basic' }],
  allowTokenOnly = false,
  onRequest = () => {},
  onUpgrade = () => {},
  limitOverrides = {},
  logger = () => {},
  wsAuthRecheckMs = 60_000,
} = {}) {
  let authState = { authRequired, providers };
  const seen = [];
  const wsSockets = [];
  const upstream = http.createServer((req, res) => {
    if (req.url === '/api/status') {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(statusBody(authState.authRequired));
      return;
    }
    if (req.url === '/api/auth/providers') {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ providers: authState.providers }));
      return;
    }
    const chunks = [];
    req.on('data', (chunk) => chunks.push(chunk));
    req.on('end', () => {
      const record = {
        method: req.method,
        url: req.url,
        headers: req.headers,
        body: Buffer.concat(chunks).toString('utf8'),
      };
      seen.push(record);
      onRequest(record, res);
    });
  });
  upstream.on('upgrade', (req, socket, head) => {
    const record = { url: req.url, headers: req.headers, head };
    seen.push(record);
    onUpgrade(record);
    const accept = crypto
      .createHash('sha1')
      .update(req.headers['sec-websocket-key'] + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11')
      .digest('base64');
    socket.write(
      'HTTP/1.1 101 Switching Protocols\r\n' +
        'Upgrade: websocket\r\n' +
        'Connection: Upgrade\r\n' +
        'Sec-WebSocket-Accept: ' + accept + '\r\n\r\n',
    );
    const frameBody = Buffer.from('synthetic chat response');
    socket.write(Buffer.concat([Buffer.from([0x81, frameBody.length]), frameBody]));
    wsSockets.push(socket);
    if (head.length) socket.unshift(head);
  });
  const upstreamPort = await listen(upstream);
  const proxy = createHermesProxy({
    publicHost,
    upstreamHost: '127.0.0.1',
    upstreamPort,
    allowTokenOnly,
    listenPort: 0,
    websocketAuthRecheckMs: wsAuthRecheckMs,
    ...limitOverrides,
    logger,
  });
  try {
    await proxy.listen();
  } catch (error) {
    await new Promise((resolve) => upstream.close(resolve));
    throw error;
  }
  const proxyPort = proxy.server.address().port;
  return {
    proxy,
    upstream,
    proxyPort,
    seen,
    wsSockets,
    setAuth(authRequired, providers = [{ name: 'basic' }]) {
      authState = { authRequired, providers };
    },
    async stopUpstream() {
      await new Promise((resolve) => upstream.close(resolve));
    },
    async close() {
      await proxy.close();
      for (const socket of wsSockets) socket.destroy();
      if (upstream.listening) await new Promise((resolve) => upstream.close(resolve));
    },
  };
}

test('proxy binds only to loopback and preflights an active basic-auth gate', async () => {
  assert.equal(PROXY_DEFAULTS.listenHost, '127.0.0.1');
  assert.throws(() => createHermesProxy({ publicHost, listenHost: '0.0.0.0' }), /loopback_only/);
  assert.throws(
    () => createHermesProxy({ publicHost: 'not-a-tailnet-host.example' }),
    /invalid_public_host/,
  );
  const h = await harness();
  try {
    assert.equal(h.proxy.server.address().address, '127.0.0.1');
  } finally {
    await h.close();
  }
});

test('HTTP status and mobile password login preserve paths, cookies, and HTTPS headers', async () => {
  let loginRecord;
  const h = await harness({
    onRequest(record, res) {
      if (record.url === '/api/auth/providers') {
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end('{"providers":[{"name":"basic","supports_password":true}]}');
        return;
      }
      if (record.url === '/api/sessions') {
        assert.match(record.headers.cookie ?? '', /__Host-hermes_session_at=synthetic-cookie/);
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end('{"sessions":[{"id":"synthetic-session","title":"Synthetic chat"}]}');
        return;
      }
      if (record.url === '/api/sessions/synthetic-session/messages') {
        assert.match(record.headers.cookie ?? '', /__Host-hermes_session_at=synthetic-cookie/);
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end('{"messages":[{"role":"assistant","content":"Synthetic history"}]}');
        return;
      }
      if (record.url === '/auth/password-login') {
        loginRecord = record;
        res.writeHead(200, {
          'content-type': 'application/json',
          'set-cookie': [
            secureCookie,
            '__Host-hermes_session_provider=basic; Path=/; HttpOnly; SameSite=Lax; Secure',
          ],
        });
        res.end('{"ok":true}');
        return;
      }
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(statusBody());
    },
  });
  try {
    const status = await request(h.proxyPort, {
      headers: {
        origin: 'https://' + publicHost,
        'x-forwarded-proto': 'http',
        'x-forwarded-host': 'attacker.invalid',
        'x-forwarded-for': '192.0.2.44',
        forwarded: 'for=192.0.2.44;proto=http',
      },
    });
    assert.equal(status.status, 200);
    assert.deepEqual(JSON.parse(status.body), { auth_required: true });

    const providers = await request(h.proxyPort, { path: '/api/auth/providers' });
    assert.equal(JSON.parse(providers.body).providers[0].name, 'basic');
    const login = await request(h.proxyPort, {
      path: '/auth/password-login',
      method: 'POST',
      headers: {
        origin: 'https://' + publicHost,
        'content-type': 'application/json',
      },
      body: JSON.stringify({
        provider: 'basic',
        username: 'synthetic-user',
        password: 'synthetic-password',
        next: '',
      }),
    });
    assert.equal(login.status, 200);
    assert.equal(login.headers['set-cookie'].length, 2);
    assert.match(login.headers['set-cookie'][0], /; Secure/i);
    const sessionCookieHeader = secureCookie.split(';', 1)[0];
    const sessions = await request(h.proxyPort, {
      path: '/api/sessions',
      headers: { cookie: sessionCookieHeader },
    });
    assert.equal(JSON.parse(sessions.body).sessions[0].id, 'synthetic-session');
    const history = await request(h.proxyPort, {
      path: '/api/sessions/synthetic-session/messages',
      headers: { cookie: sessionCookieHeader },
    });
    assert.equal(JSON.parse(history.body).messages[0].content, 'Synthetic history');
    assert.equal(loginRecord.headers.host, publicHost);
    assert.equal(loginRecord.headers['x-forwarded-proto'], 'https');
    assert.equal(loginRecord.headers['x-forwarded-host'], publicHost);
    assert.equal(loginRecord.headers['x-forwarded-port'], '443');
    assert.equal('x-forwarded-for' in loginRecord.headers, false);
    assert.equal('forwarded' in loginRecord.headers, false);
    assert.equal(loginRecord.body, JSON.stringify({
      provider: 'basic',
      username: 'synthetic-user',
      password: 'synthetic-password',
      next: '',
    }));
  } finally {
    await h.close();
  }
});

test('missing or expired Hermes sessions remain unauthorized and are not retried as success', async () => {
  const h = await harness({
    onRequest(record, res) {
      assert.equal(record.url, '/api/sessions');
      res.writeHead(401, { 'content-type': 'application/json', 'cache-control': 'no-store' });
      res.end('{"detail":"session expired"}');
    },
  });
  try {
    const missing = await request(h.proxyPort, { path: '/api/sessions' });
    const expired = await request(h.proxyPort, {
      path: '/api/sessions',
      headers: { cookie: '__Host-hermes_session_at=expired-synthetic-value' },
    });
    assert.equal(missing.status, 401);
    assert.equal(expired.status, 401);
    assert.equal(JSON.parse(expired.body).detail, 'session expired');
    assert.equal(h.seen.length, 2);
  } finally {
    await h.close();
  }
});

test('host and Origin mismatches are rejected before reaching Hermes', async () => {
  const h = await harness();
  try {
    const badHost = await request(h.proxyPort, { headers: { host: 'attacker.invalid' } });
    const badOrigin = await request(h.proxyPort, { headers: { origin: 'http://attacker.invalid' } });
    assert.equal(badHost.status, 421);
    assert.equal(badOrigin.status, 403);
    assert.deepEqual(h.seen, []);
  } finally {
    await h.close();
  }
});

test('unprotected or unverifiable upstream auth gates fail closed', async () => {
  const unprotectedUpstream = http.createServer((_req, res) => {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(statusBody(false, []));
  });
  const unprotectedPort = await listen(unprotectedUpstream);
  const unprotected = createHermesProxy({
    publicHost,
    upstreamHost: '127.0.0.1',
    upstreamPort: unprotectedPort,
    listenPort: 0,
  });
  await assert.rejects(unprotected.listen(), /hermes_auth_unavailable/);
  await new Promise((resolve) => unprotectedUpstream.close(resolve));

  const h = await harness({ authRequired: true, providers: ['basic'] });
  try {
    h.setAuth(true, []);
    assert.equal((await request(h.proxyPort)).status, 503);
    h.setAuth(false, ['basic']);
    assert.equal((await request(h.proxyPort)).status, 503);
    h.setAuth(true, [{ name: 'oauth' }]);
    assert.equal((await request(h.proxyPort)).status, 503);
  } finally {
    await h.close();
  }

  const unavailable = createHermesProxy({
    publicHost,
    upstreamHost: '127.0.0.1',
    upstreamPort: 1,
    listenPort: 0,
    authCheckTimeoutMs: 200,
  });
  await assert.rejects(unavailable.listen(), /hermes_auth_unavailable/);
});

test('loopback token-only mode is allowed only with explicit private-tailnet opt-in', async () => {
  const h = await harness({
    authRequired: false,
    providers: [],
    allowTokenOnly: true,
    onRequest(record, res) {
      if (record.url === '/api/sessions') {
        assert.equal(record.headers.authorization, 'Bearer synthetic-session-token');
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end('{"sessions":[{"id":"synthetic-session"}]}');
        return;
      }
      res.writeHead(404);
      res.end();
    },
  });
  try {
    const status = await request(h.proxyPort);
    assert.equal(status.status, 200);
    assert.deepEqual(JSON.parse(status.body), { auth_required: false });
    const sessions = await request(h.proxyPort, {
      path: '/api/sessions',
      headers: { authorization: 'Bearer synthetic-session-token' },
    });
    assert.equal(sessions.status, 200);
    assert.equal(JSON.parse(sessions.body).sessions[0].id, 'synthetic-session');
  } finally {
    await h.close();
  }
});

test('successful password login without secure session cookies is blocked', async () => {
  const logs = [];
  const h = await harness({
    logger: (event) => logs.push(event),
    onRequest(_record, res) {
      res.writeHead(200, {
        'content-type': 'application/json',
        'set-cookie': 'hermes_session_at=synthetic-cookie; Path=/; HttpOnly; SameSite=Lax',
      });
      res.end('{"ok":true}');
    },
  });
  try {
    const response = await request(h.proxyPort, {
      path: '/auth/password-login',
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: '{"provider":"basic","username":"synthetic","password":"synthetic","next":""}',
    });
    assert.equal(response.status, 502);
    assert.equal(response.headers['set-cookie'], undefined);
    assert.match(response.body, /upstream_cookie_policy_failed/);
    assert.deepEqual(logs, [{ event: 'proxy_rejected_insecure_cookie' }]);
    assert.equal(
      secureAccessCookieForTest('hermes_session_at=x; Path=/; HttpOnly; SameSite=Lax'),
      false,
    );
    assert.equal(secureAccessCookieForTest(secureCookie), true);
  } finally {
    await h.close();
  }
});

test('Hermes 0.20.5 logout deletions gain Secure while live auth cookies stay strictly checked', async () => {
  const deletions = [
    'hermes_session_at=; Max-Age=0; Path=/; HttpOnly; SameSite=lax',
    '__Host-hermes_session_rt=; Max-Age=0; Path=/; HttpOnly; SameSite=lax',
    '__Secure-hermes_session_provider=; Max-Age=0; Path=/; HttpOnly; SameSite=lax',
    'hermes_session_pkce=; Max-Age=0; Path=/; HttpOnly; SameSite=lax',
    '__Host-hermes_sso_attempt=; Max-Age=0; Path=/; HttpOnly; SameSite=lax',
  ];
  const rewritten = secureHermesAuthCookiesForTest('/auth/logout', 200, { 'set-cookie': deletions });
  assert.ok(rewritten);
  assert.equal(rewritten['set-cookie'].length, deletions.length);
  for (const cookie of rewritten['set-cookie']) {
    assert.match(cookie, /; Secure$/i);
    assert.match(cookie, /Max-Age=0/i);
    assert.match(cookie, /Path=\//i);
    assert.match(cookie, /HttpOnly/i);
    assert.match(cookie, /SameSite=lax/i);
  }

  assert.equal(
    secureHermesAuthCookiesForTest('/auth/logout', 200, {
      'set-cookie': 'hermes_session_at=attacker-controlled-live-value; Path=/; HttpOnly; SameSite=Lax',
    }),
    null,
  );
  assert.equal(
    secureHermesAuthCookiesForTest('/auth/password-login', 200, {
      'set-cookie': '__Secure-hermes_session_at=synthetic; Path=/; HttpOnly; SameSite=Lax; Secure',
    }),
    null,
  );
  assert.equal(
    secureHermesAuthCookiesForTest('/auth/password-login', 200, {
      'set-cookie': '__Host-hermes_session_at=synthetic; Domain=tailnet.ts.net; Path=/; HttpOnly; SameSite=Lax; Secure',
    }),
    null,
  );
  assert.equal(
    secureHermesAuthCookiesForTest('/auth/logout', 200, {
      'set-cookie': 'hermes_session_at=; Max-Age=0; Path=/hermes; HttpOnly; SameSite=Lax',
    }),
    null,
  );
  assert.equal(
    secureHermesAuthCookiesForTest('/auth/logout', 200, {
      'set-cookie': 'hermes_sso_attempt=; Max-Age=0; Path=/; HttpOnly; SameSite=Lax',
    })['set-cookie'][0],
    'hermes_sso_attempt=; Max-Age=0; Path=/; HttpOnly; SameSite=Lax; Secure',
  );
});

test('logout response through the proxy clears Hermes auth cookies with Secure and logs no values', async () => {
  const logs = [];
  const clearCookies = [
    'hermes_session_at=; Max-Age=0; Path=/; HttpOnly; SameSite=lax',
    '__Host-hermes_session_rt=; Max-Age=0; Path=/; HttpOnly; SameSite=lax',
    'hermes_session_pkce=; Max-Age=0; Path=/; HttpOnly; SameSite=lax',
    '__Host-hermes_sso_attempt=; Max-Age=0; Path=/; HttpOnly; SameSite=lax',
  ];
  const h = await harness({
    logger: (event) => logs.push(event),
    onRequest(record, res) {
      assert.equal(record.url, '/auth/logout');
      res.writeHead(200, { 'set-cookie': clearCookies });
      res.end('{"ok":true}');
    },
  });
  try {
    const response = await request(h.proxyPort, {
      path: '/auth/logout',
      method: 'POST',
      headers: { origin: 'https://' + publicHost },
      body: '{}',
    });
    assert.equal(response.status, 200);
    assert.equal(response.headers['set-cookie'].length, clearCookies.length);
    assert.ok(response.headers['set-cookie'].every((cookie) => /; Secure$/i.test(cookie)));
    assert.deepEqual(JSON.parse(response.body), { ok: true });
    assert.deepEqual(logs, []);
  } finally {
    await h.close();
  }
});

test('one-use WebSocket tickets are forwarded without logging and WebSocket frames relay', async () => {
  const logs = [];
  let wsRecord;
  const h = await harness({
    logger: (event) => logs.push(event),
    onUpgrade(record) {
      wsRecord = record;
    },
    onRequest(record, res) {
      if (record.url === '/api/auth/ws-ticket') {
        assert.match(record.headers.cookie ?? '', /__Host-hermes_session_at=synthetic-cookie/);
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end('{"ticket":"synthetic-one-shot-ticket"}');
        return;
      }
      res.writeHead(404);
      res.end();
    },
  });
  try {
    const ticket = await request(h.proxyPort, {
      path: '/api/auth/ws-ticket',
      method: 'POST',
      headers: {
        origin: 'https://' + publicHost,
        cookie: secureCookie.split(';', 1)[0],
      },
      body: '{}',
    });
    assert.equal(ticket.status, 200);
    assert.equal(JSON.parse(ticket.body).ticket, 'synthetic-one-shot-ticket');

    const key = crypto.randomBytes(16).toString('base64');
    const ws = await new Promise((resolve, reject) => {
      const req = http.request({
        hostname: '127.0.0.1',
        port: h.proxyPort,
        path: '/api/ws?ticket=synthetic-one-shot-ticket',
        headers: {
          host: publicHost,
          origin: 'https://' + publicHost,
          connection: 'Upgrade',
          upgrade: 'websocket',
          'sec-websocket-version': '13',
          'sec-websocket-key': key,
          cookie: secureCookie.split(';', 1)[0],
          'x-forwarded-proto': 'http',
          'x-forwarded-for': '203.0.113.9',
        },
      });
      req.once('upgrade', (res, socket, head) => resolve({ res, socket, head }));
      req.once('response', (res) => reject(new Error('expected upgrade, got ' + res.statusCode)));
      req.once('error', reject);
      req.end();
    });
    assert.equal(ws.res.statusCode, 101);
    assert.equal(wsRecord.url, '/api/ws?ticket=synthetic-one-shot-ticket');
    assert.equal(wsRecord.headers.host, publicHost);
    assert.equal(wsRecord.headers['x-forwarded-proto'], 'https');
    assert.equal('x-forwarded-for' in wsRecord.headers, false);
    assert.equal(logs.some((entry) => JSON.stringify(entry).includes('synthetic-one-shot-ticket')), false);
    let received = Buffer.from(ws.head);
    const frameReceived = received.includes(Buffer.from('synthetic chat response')) || await new Promise((resolve) => {
      const timer = setTimeout(() => resolve(false), 500);
      ws.socket.on('data', (data) => {
        received = Buffer.concat([received, data]);
        if (received.includes(Buffer.from('synthetic chat response'))) {
          clearTimeout(timer);
          resolve(true);
        }
      });
      ws.socket.resume();
    });
    assert.equal(frameReceived, true);
    ws.socket.destroy();
  } finally {
    await h.close();
  }
});

test('token-only Hermes WebSocket query is forwarded with explicit opt-in and never logged by proxy', async () => {
  const logs = [];
  let wsRecord;
  const h = await harness({
    authRequired: false,
    providers: [],
    allowTokenOnly: true,
    logger: (event) => logs.push(event),
    onUpgrade(record) {
      wsRecord = record;
    },
  });
  try {
    const key = crypto.randomBytes(16).toString('base64');
    const ws = await new Promise((resolve, reject) => {
      const req = http.request({
        hostname: '127.0.0.1',
        port: h.proxyPort,
        path: '/api/ws?token=synthetic-session-token',
        headers: {
          host: publicHost,
          origin: 'https://' + publicHost,
          connection: 'Upgrade',
          upgrade: 'websocket',
          'sec-websocket-version': '13',
          'sec-websocket-key': key,
        },
      });
      req.once('upgrade', (res, socket, head) => resolve({ res, socket, head }));
      req.once('response', (res) => reject(new Error('expected upgrade, got ' + res.statusCode)));
      req.once('error', reject);
      req.end();
    });
    assert.equal(ws.res.statusCode, 101);
    assert.equal(wsRecord.url, '/api/ws?token=synthetic-session-token');
    assert.equal(logs.some((entry) => JSON.stringify(entry).includes('synthetic-session-token')), false);
    ws.socket.destroy();
  } finally {
    await h.close();
  }
});

test('post-TLS raw TCP forwarding carries REST and token WebSocket to the loopback helper', async () => {
  const logs = [];
  let wsRecord;
  const h = await harness({
    authRequired: false,
    providers: [],
    allowTokenOnly: true,
    logger: (event) => logs.push(event),
    onUpgrade(record) {
      wsRecord = record;
    },
  });
  const forwardedSockets = new Set();
  const forwarder = net.createServer((client) => {
    forwardedSockets.add(client);
    const target = net.connect(h.proxyPort, '127.0.0.1');
    client.pipe(target).pipe(client);
    client.once('close', () => {
      forwardedSockets.delete(client);
      target.destroy();
    });
    target.once('close', () => client.destroy());
    client.once('error', () => target.destroy());
    target.once('error', () => client.destroy());
  });
  const forwardPort = await listen(forwarder);
  let websocket;
  try {
    const status = await request(forwardPort, { path: '/api/status' });
    assert.equal(status.status, 200);
    assert.deepEqual(JSON.parse(status.body), { auth_required: false });

    const key = crypto.randomBytes(16).toString('base64');
    websocket = await new Promise((resolve, reject) => {
      const req = http.request({
        hostname: '127.0.0.1',
        port: forwardPort,
        path: '/api/ws?token=synthetic-session-token',
        headers: {
          host: publicHost,
          origin: 'https://' + publicHost,
          connection: 'Upgrade',
          upgrade: 'websocket',
          'sec-websocket-version': '13',
          'sec-websocket-key': key,
        },
      });
      req.once('upgrade', (res, socket, head) => resolve({ res, socket, head }));
      req.once('response', (res) => reject(new Error('expected upgrade, got ' + res.statusCode)));
      req.once('error', reject);
      req.end();
    });
    assert.equal(websocket.res.statusCode, 101);
    assert.equal(wsRecord.url, '/api/ws?token=synthetic-session-token');
    assert.doesNotMatch(JSON.stringify(logs), /synthetic-session-token|Bearer/);

    let received = Buffer.from(websocket.head);
    const frameReceived = received.includes(Buffer.from('synthetic chat response')) || await new Promise((resolve) => {
      const timer = setTimeout(() => resolve(false), 500);
      websocket.socket.on('data', (data) => {
        received = Buffer.concat([received, data]);
        if (received.includes(Buffer.from('synthetic chat response'))) {
          clearTimeout(timer);
          resolve(true);
        }
      });
      websocket.socket.resume();
    });
    assert.equal(frameReceived, true);
  } finally {
    websocket?.socket.destroy();
    for (const socket of forwardedSockets) socket.destroy();
    await new Promise((resolve) => forwarder.close(resolve));
    await h.close();
  }
});

test('token-only upstream failures log only a fixed event and error code', async () => {
  const logs = [];
  const syntheticToken = 'SYNTHETIC-TOKEN-NEVER-LOG-6c2f';
  const h = await harness({
    authRequired: false,
    providers: [],
    allowTokenOnly: true,
    logger: (event) => logs.push(event),
    onRequest(record, res) {
      assert.equal(record.headers.authorization, `Bearer ${syntheticToken}`);
      res.socket.destroy();
    },
  });
  try {
    const result = await request(h.proxyPort, {
      path: '/api/sessions',
      headers: { authorization: `Bearer ${syntheticToken}` },
    });
    assert.equal(result.status, 502);
    assert.deepEqual(logs, [{ event: 'proxy_upstream_error', code: 'ECONNRESET' }]);
    assert.doesNotMatch(JSON.stringify(logs), /SYNTHETIC-TOKEN|Bearer/);
  } finally {
    await h.close();
  }
});

test('password and ticket endpoints have bounded rate limits and do not log bodies', async () => {
  const logs = [];
  const h = await harness({
    logger: (event) => logs.push(event),
    limitOverrides: { loginLimit: 1, ticketLimit: 1, limiterWindowMs: 60_000 },
    onRequest(_record, res) {
      res.writeHead(401, { 'content-type': 'application/json' });
      res.end('{"detail":"invalid username or password"}');
    },
  });
  try {
    const login = () => request(h.proxyPort, {
      path: '/auth/password-login',
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: '{"password":"must-not-be-logged"}',
    });
    assert.equal((await login()).status, 401);
    assert.equal((await login()).status, 429);
    const ticket = () => request(h.proxyPort, {
      path: '/api/auth/ws-ticket',
      method: 'POST',
      body: '{}',
    });
    assert.equal((await ticket()).status, 401);
    assert.equal((await ticket()).status, 429);
    assert.deepEqual(logs, []);
  } finally {
    await h.close();
  }
});

test('absolute-form, protocol-relative, and malformed WebSocket requests are rejected', async () => {
  const h = await harness();
  try {
    const absolute = await request(h.proxyPort, { path: 'http://' + publicHost + '/api/status' });
    const protocolRelative = await request(h.proxyPort, { path: '//attacker.invalid/api/status' });
    assert.equal(absolute.status, 400);
    assert.equal(protocolRelative.status, 400);

    const invalidUpgrade = await new Promise((resolve, reject) => {
      const req = http.request({
        hostname: '127.0.0.1',
        port: h.proxyPort,
        path: '/api/ws',
        headers: { host: publicHost, connection: 'Upgrade', upgrade: 'websocket' },
      });
      req.once('response', (res) => resolve(res.statusCode));
      req.once('upgrade', () => reject(new Error('unexpected websocket upgrade')));
      req.once('error', reject);
      req.end();
    });
    assert.equal(invalidUpgrade, 400);
    assert.deepEqual(h.seen, []);
  } finally {
    await h.close();
  }
});

test('the runtime target is pinned and cannot be selected from add-on options', () => {
  assert.equal(PROXY_DEFAULTS.upstreamHost, 'a90308c2-hermes-agent');
  assert.equal(PROXY_DEFAULTS.upstreamPort, 8099);
  const launcher = fs.readFileSync(new URL('../server.mjs', import.meta.url), 'utf8');
  assert.match(launcher, /upstreamHost:\s*PROXY_DEFAULTS\.upstreamHost/);
  assert.doesNotMatch(launcher, /options\.upstream|HERMES_UPSTREAM/);
});

test('upstream outage after startup returns a generic unavailable response', async () => {
  const h = await harness();
  try {
    await h.stopUpstream();
    const response = await request(h.proxyPort);
    assert.equal(response.status, 503);
    assert.match(response.body, /hermes_auth_unavailable/);
  } finally {
    await h.close();
  }
});

test('an open WebSocket is closed when the upstream auth gate becomes unverifiable', async () => {
  const h = await harness({ wsAuthRecheckMs: 10 });
  try {
    const key = crypto.randomBytes(16).toString('base64');
    const ws = await new Promise((resolve, reject) => {
      const req = http.request({
        hostname: '127.0.0.1',
        port: h.proxyPort,
        path: '/api/ws?ticket=synthetic-ticket',
        headers: {
          host: publicHost,
          connection: 'Upgrade',
          upgrade: 'websocket',
          'sec-websocket-version': '13',
          'sec-websocket-key': key,
        },
      });
      req.once('upgrade', (res, socket) => resolve({ res, socket }));
      req.once('response', (res) => reject(new Error('expected upgrade, got ' + res.statusCode)));
      req.once('error', reject);
      req.end();
    });
    assert.equal(ws.res.statusCode, 101);
    h.setAuth(false, []);
    const closed = await new Promise((resolve) => {
      const timer = setTimeout(() => resolve(false), 1000);
      ws.socket.once('close', () => {
        clearTimeout(timer);
        resolve(true);
      });
      ws.socket.resume();
    });
    assert.equal(closed, true);
  } finally {
    await h.close();
  }
});

