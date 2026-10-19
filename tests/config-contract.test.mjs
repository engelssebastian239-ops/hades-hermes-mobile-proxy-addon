import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import test from 'node:test';

const root = new URL('../', import.meta.url);
const read = (path) => fs.readFileSync(new URL(path, root), 'utf8');

test('candidate add-on starts disabled and exposes an opt-in read-only preflight without ports or APIs', () => {
  const config = read('config.yaml');
  assert.match(config, /host_network: true/);
  assert.match(config, /boot: manual/);
  assert.match(config, /enabled: false/);
  assert.match(config, /preflight_only: false/);
  assert.match(config, /allow_token_only: false/);
  assert.match(config, /public_host: ""/);
  assert.doesNotMatch(config, /^\s*ports:/m);
  assert.doesNotMatch(config, /^\s*(?:hassio_api|homeassistant_api|docker_api|full_access):\s*true/m);
  assert.doesNotMatch(config, /^\s*privileged:/m);
  assert.doesNotMatch(config, /^\s*map:/m);
  assert.match(config, /arch:\s*\n\s+- aarch64/);
  const runtime = read('server.mjs');
  assert.ok(runtime.indexOf("options.preflight_only === true") < runtime.indexOf('createHermesProxy({'));
  assert.match(runtime, /runReadonlyPreflight\(\{\s*allowTokenOnly: options\.allow_token_only === true\s*\}\)/);
  assert.doesNotMatch(runtime, /listen\(.*preflight/i);
});

test('M5.74 laris-co patch redacts Nginx queries and Hermes ticket errors without changing auth config', () => {
  const patch = read('patches/laris-co-hermes-haos-addons.patch');
  assert.match(patch, /diff --git a\/hermes-agent\/rootfs\/etc\/nginx\/hermes-ingress\.conf/);
  assert.match(patch, /log_format hermes_redacted/);
  assert.match(patch, /\$request_method \$uri \$server_protocol/);
  assert.match(patch, /location = \/api\/ws/);
  assert.match(patch, /error_log \/dev\/null emerg/);
  assert.doesNotMatch(patch, /\$request_uri|\$request\b|\$args|\$query_string/);
  assert.match(patch, /raise TicketInvalid\("unknown ticket"\)/);
  assert.match(patch, /access_log=False/);
  assert.match(patch, /log_level="warning"/);
  assert.doesNotMatch(patch, /diff --git a\/hermes-agent\/config\.yaml/);
  assert.doesNotMatch(patch, /diff --git a\/hermes-agent\/rootfs\/.*(?:auth|dashboard)/);
});

test('ticket-log patch fixtures are pinned to the reviewed upstream sources', () => {
  const nginxSource = read('tests/fixtures/hermes-agent/rootfs/etc/nginx/hermes-ingress.conf');
  const ticketSource = read('tests/fixtures/hermes-agent/hermes_cli/dashboard_auth/ws_tickets.py');
  const auditSource = read('tests/fixtures/hermes-agent/hermes_cli/dashboard_auth/audit.py');
  const webServerSource = read('tests/fixtures/hermes-agent/hermes_cli/web_server.py');
  const digest = (text) => createHash('sha256').update(text).digest('hex');
  assert.equal(digest(nginxSource), '718d35d8f816e73a3b08eb008dcccd37a54339c88553b7f4484305384846608b');
  assert.equal(digest(ticketSource), 'b66e29a067002ad8a345b49281d30c75d6ec2bb177d58214611db66925bb4429');
  assert.equal(digest(auditSource), 'c566a10a6c18b27debd3787e0072e1b25fc661d0c55cda0ffcb098ae02d35690');
  assert.equal(digest(webServerSource), 'c0a22eba905783574a3048c9629a7954fbffd97560c1dd8962bf15bb7d001ab2');
  assert.match(ticketSource, /truncated = \(ticket\[:8\]/);
  assert.match(auditSource, /"ticket"/);
  assert.match(webServerSource, /uvicorn\.Config\([\s\S]*log_level="warning"/);
});

test('Hermes WebSocket auth errors no longer interpolate ticket bytes into audit reasons', () => {
  const patch = read('patches/hermes-ws-ticket-redaction.patch');
  const addedLines = patch.split('\n').filter((line) => line.startsWith('+') && !line.startsWith('+++')).join('\n');
  assert.match(addedLines, /raise TicketInvalid\("unknown ticket"\)/);
  assert.match(addedLines, /do not reflect any part of the bearer ticket/);
  assert.match(addedLines, /access_log=False/);
  assert.doesNotMatch(addedLines, /ticket\[:8\]|\{truncated\}/);
});

test('token-only proxy gate stays opt-in and the combined release patch is source-pinned', () => {
  const config = read('config.yaml');
  const patch = read('patches/laris-co-hermes-haos-addons.patch');
  const source = read('tests/fixtures/hermes-agent/SOURCE.md');
  assert.match(config, /^  allow_token_only: false$/m);
  assert.match(source, /7b26c481a31a19e7e6c6178ff4bfa63f0b2e03a3/);
  assert.match(patch, /COPY apply_hermes_ticket_redaction\.py/);
  assert.doesNotMatch(patch, /openrouter_api_key|extra_env:|auth_required:/i);
});

test('container runs under a fixed unprivileged UID on a pinned ARM64 Node base', () => {
  const dockerfile = read('Dockerfile');
  assert.match(dockerfile, /^FROM node:24\.21\.0-alpine3\.23@sha256:[a-f0-9]{64}$/m);
  assert.match(dockerfile, /USER 10001:10001/);
  assert.match(dockerfile, /CMD \["node", "server\.mjs"\]/);
  assert.doesNotMatch(dockerfile, /CAP_SYS_ADMIN|docker\.sock|SUPERVISOR_TOKEN/i);
});

test('Tailscale example uses TLS-terminated TCP, avoiding the HTTP reverse-proxy query-log path', () => {
  const readme = read('README.md');
  assert.match(readme, /name:\s*["']?svc:hermes/);
  assert.match(readme, /target:\s*["']?tcp:\/\/127\.0\.0\.1:8098/);
  assert.match(readme, /protocol:\s*["']?tls-terminated-tcp/);
  assert.match(readme, /port:\s*443/);
  assert.match(readme, /Go's `httputil\.ReverseProxy` without a custom `ErrorHandler`/);
  assert.match(readme, /tls-terminated-tcp` Service\s+protocol on port 443/);
  assert.match(readme, /models only the post-TLS stream; it is not a Tailscale or HAOS runtime\s+test/);
  assert.match(readme, /Funnel disabled|Funnel off/i);
  assert.match(readme, /preserve every\s+existing Tailscale `services` entry verbatim/i);
});

test('template contains no real credentials and records provenance limits', () => {
  const readme = read('README.md');
  assert.match(readme, /HERMES_DASHBOARD_BASIC_AUTH_PASSWORD_HASH=<locally-generated-scrypt-hash>/i);
  assert.match(readme, /HERMES_DASHBOARD_BASIC_AUTH_SECRET=<stable-random-signing-key>/i);
  assert.match(readme, /synthetic/i);
  assert.match(readme, /not available|UNKNOWN/i);
  assert.doesNotMatch(readme, /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/);
});
