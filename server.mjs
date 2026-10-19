import fs from 'node:fs';
import { createHermesProxy, PROXY_DEFAULTS } from './proxy.mjs';
import { runReadonlyPreflight } from './runtime-preflight.mjs';

const OPTIONS_FILE = '/data/options.json';
const DISABLED_SLEEP_MS = 60_000;

function logEvent(event) {
  // Never include headers, request paths, query strings, or bodies. WS tickets
  // are carried in query parameters and must not appear in logs.
  console.log(JSON.stringify({ event }));
}

async function waitUntilStopped() {
  await new Promise((resolve) => {
    const timer = setInterval(() => {}, DISABLED_SLEEP_MS);
    const stop = () => {
      clearInterval(timer);
      resolve();
    };
    process.once('SIGTERM', stop);
    process.once('SIGINT', stop);
  });
}

const DEFAULT_OPTIONS = {
  enabled: false,
  preflight_only: false,
  allow_token_only: false,
  public_host: '',
};

function ensureOptionsFile() {
  try {
    fs.mkdirSync('/data', { recursive: true });
    // Write defaults only if file missing or empty/corrupt
    let existing = null;
    try { existing = JSON.parse(fs.readFileSync(OPTIONS_FILE, 'utf8')); } catch {}
    if (!existing || typeof existing !== 'object') {
      fs.writeFileSync(OPTIONS_FILE, JSON.stringify(DEFAULT_OPTIONS), 'utf8');
    }
  } catch {}
}

async function readOptions(retries = 3, delayMs = 2000) {
  ensureOptionsFile();
  for (let i = 0; i < retries; i++) {
    try {
      return JSON.parse(fs.readFileSync(OPTIONS_FILE, 'utf8'));
    } catch {
      if (i < retries - 1) {
        await new Promise((r) => setTimeout(r, delayMs));
      }
    }
  }
  return DEFAULT_OPTIONS;
}

async function main() {
  const options = await readOptions();
  if (!options) {
    logEvent('configuration_unavailable');
    process.exitCode = 1;
    return;
  }

  if (options.preflight_only === true) {
    if (options.enabled === true) {
      logEvent('preflight_configuration_conflict');
      process.exitCode = 1;
      return;
    }
    console.log(JSON.stringify(await runReadonlyPreflight({ allowTokenOnly: options.allow_token_only === true })));
    await waitUntilStopped();
    return;
  }

  if (options.enabled !== true) {
    logEvent('disabled');
    await waitUntilStopped();
    return;
  }

  let proxy;
  try {
    proxy = createHermesProxy({
      publicHost: options.public_host,
      listenHost: PROXY_DEFAULTS.listenHost,
      listenPort: PROXY_DEFAULTS.listenPort,
      upstreamHost: PROXY_DEFAULTS.upstreamHost,
      upstreamPort: PROXY_DEFAULTS.upstreamPort,
      allowTokenOnly: options.allow_token_only === true,
      logger: (event) => logEvent(event.event),
    });
    await proxy.listen();
  } catch (error) {
    logEvent(error.message === 'hermes_auth_unavailable' ? 'startup_auth_gate_unverified' : 'startup_configuration_invalid');
    process.exitCode = 1;
    return;
  }

  logEvent('ready_loopback_only');
  const stop = async () => {
    await proxy.close().catch(() => {});
    process.exit(0);
  };
  process.once('SIGTERM', stop);
  process.once('SIGINT', stop);
}

await main();
