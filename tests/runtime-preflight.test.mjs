import assert from 'node:assert/strict';
import http from 'node:http';
import test from 'node:test';
import { inspectHermesAuthGate, PROXY_DEFAULTS } from '../proxy.mjs';
import { runReadonlyPreflight } from '../runtime-preflight.mjs';

function listen(server) {
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      server.removeListener('error', reject);
      resolve(server.address().port);
    });
  });
}

test('read-only UI preflight exposes only fixed states and never leaks resolver or inspector data', async () => {
  const calls = [];
  const result = await runReadonlyPreflight({
    lookupHost: async (host) => {
      calls.push(['dns', host]);
      return [{ address: '192.0.2.10', family: 4 }];
    },
    checkTcpReachable: async (options) => {
      calls.push(['tcp', options.host, options.port]);
      return true;
    },
    inspectAuthGate: async (options) => {
      calls.push(['auth', options.host, options.port, options.publicHost, options.maxBytes]);
      return {
        authRequired: true,
        basicProvider: true,
        token: 'synthetic-secret-must-not-escape',
        ticket: 'synthetic-ticket-must-not-escape',
        responseBody: 'synthetic-password-must-not-escape',
      };
    },
  });
  assert.deepEqual(result, {
    event: 'readonly_preflight_complete',
    dns: 'resolved',
    tcp: 'reachable',
    auth: 'protected',
    basicProvider: 'available',
    listener: 'not_started',
    methods: 'GET_only',
    ok: true,
  });
  assert.deepEqual(calls, [
    ['dns', PROXY_DEFAULTS.upstreamHost],
    ['tcp', PROXY_DEFAULTS.upstreamHost, PROXY_DEFAULTS.upstreamPort],
    ['auth', PROXY_DEFAULTS.upstreamHost, PROXY_DEFAULTS.upstreamPort, 'localhost', 16 * 1024],
  ]);
  const serialized = JSON.stringify(result);
  assert.doesNotMatch(serialized, /192\.0\.2\.10|synthetic-secret|synthetic-ticket|synthetic-password/);
});

test('DNS and TCP failures stop before the auth requests and remain UNKNOWN rather than green', async () => {
  let tcpCalls = 0;
  let authCalls = 0;
  const dnsFailure = await runReadonlyPreflight({
    lookupHost: async () => { throw new Error('private address or secret'); },
    checkTcpReachable: async () => { tcpCalls += 1; return true; },
    inspectAuthGate: async () => { authCalls += 1; return { authRequired: true, basicProvider: true }; },
  });
  assert.equal(dnsFailure.dns, 'unresolved');
  assert.equal(dnsFailure.tcp, 'not_attempted');
  assert.equal(dnsFailure.auth, 'not_attempted');
  assert.equal(dnsFailure.ok, false);
  const tcpFailure = await runReadonlyPreflight({
    lookupHost: async () => [{ address: '2001:db8::1', family: 6 }],
    checkTcpReachable: async () => { tcpCalls += 1; return false; },
    inspectAuthGate: async () => { authCalls += 1; return { authRequired: true, basicProvider: true }; },
  });
  assert.equal(tcpFailure.dns, 'resolved');
  assert.equal(tcpFailure.tcp, 'unreachable');
  assert.equal(tcpFailure.auth, 'not_attempted');
  assert.equal(tcpFailure.ok, false);
  assert.equal(tcpCalls, 1);
  assert.equal(authCalls, 0);
});

test('Hermes auth preflight sends only GET to status and provider discovery', async () => {
  const requests = [];
  const upstream = http.createServer((req, res) => {
    requests.push({ method: req.method, url: req.url });
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(req.url === '/api/status'
      ? '{"auth_required":true}'
      : '{"providers":[{"name":"basic","supports_password":true}]}');
  });
  const port = await listen(upstream);
  try {
    const gate = await inspectHermesAuthGate({ host: '127.0.0.1', port, publicHost: 'localhost' });
    assert.deepEqual(gate, { authRequired: true, basicProvider: true });
    assert.deepEqual(requests, [
      { method: 'GET', url: '/api/status' },
      { method: 'GET', url: '/api/auth/providers' },
    ]);
  } finally {
    await new Promise((resolve) => upstream.close(resolve));
  }
});

test('loopback token-only mode passes preflight only with explicit tailnet-only opt-in', async () => {
  const gate = { authRequired: false, basicProvider: null };
  const denied = await runReadonlyPreflight({
    lookupHost: async () => [{ address: '192.0.2.12', family: 4 }],
    checkTcpReachable: async () => true,
    inspectAuthGate: async () => gate,
  });
  assert.equal(denied.ok, false);
  const allowed = await runReadonlyPreflight({
    lookupHost: async () => [{ address: '192.0.2.12', family: 4 }],
    checkTcpReachable: async () => true,
    inspectAuthGate: async () => gate,
    allowTokenOnly: true,
  });
  assert.equal(allowed.auth, 'token_only');
  assert.equal(allowed.basicProvider, 'not_required');
  assert.equal(allowed.listener, 'not_started');
  assert.equal(allowed.ok, true);
});

test('token-only opt-in requires the literal boolean true', async () => {
  for (const allowTokenOnly of ['true', 1, {}, null]) {
    const result = await runReadonlyPreflight({
      lookupHost: async () => [{ address: '192.0.2.12', family: 4 }],
      checkTcpReachable: async () => true,
      inspectAuthGate: async () => ({ authRequired: false, basicProvider: null }),
      allowTokenOnly,
    });
    assert.equal(result.auth, 'unprotected');
    assert.equal(result.ok, false);
    assert.equal(result.listener, 'not_started');
  }
});

test('unknown, open, and missing-provider auth states never pass the preflight', async () => {
  for (const gate of [
    { authRequired: null, basicProvider: null },
    { authRequired: false, basicProvider: null },
    { authRequired: true, basicProvider: null },
    { authRequired: true, basicProvider: false },
  ]) {
    const result = await runReadonlyPreflight({
      lookupHost: async () => [{ address: '192.0.2.11', family: 4 }],
      checkTcpReachable: async () => true,
      inspectAuthGate: async () => gate,
    });
    assert.equal(result.ok, false);
    assert.equal(
      result.auth,
      gate.authRequired === true ? 'protected' : gate.authRequired === false ? 'unprotected' : 'unknown',
    );
    assert.equal(
      result.basicProvider,
      gate.basicProvider === true ? 'available' : gate.basicProvider === false ? 'missing' : 'unknown',
    );
    assert.equal(result.listener, 'not_started');
  }
});

