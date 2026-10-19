import { lookup } from 'node:dns/promises';
import net from 'node:net';
import { inspectHermesAuthGate, PROXY_DEFAULTS } from './proxy.mjs';

const PREFLIGHT_TIMEOUT_MS = 1500;

function safeState(value, yes, no) {
  return value === true ? yes : value === false ? no : 'unknown';
}

function checkTcp({ host, port, timeoutMs = PREFLIGHT_TIMEOUT_MS, connect = net.connect }) {
  return new Promise((resolve) => {
    let settled = false;
    const finish = (reachable) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve(reachable);
    };
    const socket = connect({ host, port });
    socket.setTimeout(timeoutMs);
    socket.once('connect', () => finish(true));
    socket.once('timeout', () => finish(false));
    socket.once('error', () => finish(false));
  });
}

/**
 * One-shot, read-only UI preflight. It returns a strict enum-only record:
 * no resolved addresses, response bodies, URLs, headers, or exception text.
 * It performs DNS lookup, a TCP connect that sends no application data, and
 * GET-only Hermes auth-gate checks. It never binds a listener or mints a ticket.
 */
export async function runReadonlyPreflight({
  lookupHost = (host) => lookup(host, { all: true }),
  checkTcpReachable = checkTcp,
  inspectAuthGate = inspectHermesAuthGate,
  allowTokenOnly = false,
} = {}) {
  const result = {
    event: 'readonly_preflight_complete',
    dns: 'unresolved',
    tcp: 'not_attempted',
    auth: 'not_attempted',
    basicProvider: 'not_attempted',
    listener: 'not_started',
    methods: 'GET_only',
    ok: false,
  };

  try {
    const addresses = await lookupHost(PROXY_DEFAULTS.upstreamHost);
    if (!Array.isArray(addresses) || addresses.length === 0) return result;
    result.dns = 'resolved';
  } catch {
    return result;
  }

  try {
    if (!(await checkTcpReachable({
      host: PROXY_DEFAULTS.upstreamHost,
      port: PROXY_DEFAULTS.upstreamPort,
      timeoutMs: PREFLIGHT_TIMEOUT_MS,
    }))) {
      result.tcp = 'unreachable';
      return result;
    }
    result.tcp = 'reachable';
  } catch {
    result.tcp = 'unreachable';
    return result;
  }

  let gate;
  try {
    gate = await inspectAuthGate({
      host: PROXY_DEFAULTS.upstreamHost,
      port: PROXY_DEFAULTS.upstreamPort,
      publicHost: 'localhost',
      timeoutMs: PREFLIGHT_TIMEOUT_MS,
      maxBytes: 16 * 1024,
    });
  } catch {
    gate = null;
  }
  if (gate?.authRequired === false && allowTokenOnly === true) {
    result.auth = 'token_only';
    result.basicProvider = 'not_required';
    result.ok = true;
    return result;
  }
  result.auth = safeState(gate?.authRequired, 'protected', 'unprotected');
  result.basicProvider = safeState(gate?.basicProvider, 'available', 'missing');
  result.ok = result.auth === 'protected' && result.basicProvider === 'available';
  return result;
}

