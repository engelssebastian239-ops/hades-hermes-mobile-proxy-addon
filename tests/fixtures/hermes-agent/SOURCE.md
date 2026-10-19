# Pinned upstream source fixtures

These are limited text fixtures for offline patch-application and logging tests.
They contain no runtime configuration, credentials, session data, or generated
assets.

| Fixture | Upstream source | Commit/tag | SHA-256 |
| --- | --- | --- | --- |
| `rootfs/etc/nginx/hermes-ingress.conf` | [laris-co Hermes HAOS add-on](https://github.com/laris-co/hermes-haos-addons/blob/7b26c481a31a19e7e6c6178ff4bfa63f0b2e03a3/hermes-agent/rootfs/etc/nginx/hermes-ingress.conf) | `7b26c481a31a19e7e6c6178ff4bfa63f0b2e03a3` | `718d35d8f816e73a3b08eb008dcccd37a54339c88553b7f4484305384846608b` |
| `hermes_cli/dashboard_auth/ws_tickets.py` | [NousResearch Hermes Agent](https://github.com/NousResearch/hermes-agent/blob/v2026.8.19/hermes_cli/dashboard_auth/ws_tickets.py) | `v2026.8.19` (0.20.5 source tag) | `b66e29a067002ad8a345b49281d30c75d6ec2bb177d58214611db66925bb4429` |
| `hermes_cli/dashboard_auth/audit.py` | [NousResearch Hermes Agent](https://github.com/NousResearch/hermes-agent/blob/v2026.8.19/hermes_cli/dashboard_auth/audit.py) | `v2026.8.19` (0.20.5 source tag) | `c566a10a6c18b27debd3787e0072e1b25fc661d0c55cda0ffcb098ae02d35690` |
| `hermes_cli/web_server.py` (20-line excerpt) | [NousResearch Hermes Agent](https://github.com/NousResearch/hermes-agent/blob/v2026.8.19/hermes_cli/web_server.py#L19029) | `v2026.8.19` (0.20.5 source tag) | `c0a22eba905783574a3048c9629a7954fbffd97560c1dd8962bf15bb7d001ab2` |

The laris-co repository's current `main` commit was confirmed as the same
`7b26c481…` snapshot during this review. This confirms source identity only;
it does not prove the installed FinestraMiner image or its build provenance.
