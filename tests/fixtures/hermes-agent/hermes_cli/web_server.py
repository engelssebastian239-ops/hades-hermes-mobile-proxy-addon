    _is_loopback = host in ("127.0.0.1", "localhost", "::1")
    config = uvicorn.Config(
        app, host=host, port=port, log_level="warning",
        # proxy_headers defaults to False so _ws_client_is_allowed sees
        # the real connection peer rather than X-Forwarded-For's rewritten
        # value (which would defeat the loopback gate when behind a reverse
        # proxy).  When the OAuth gate is active we are explicitly running
        # behind a TLS terminator (Fly.io) and need X-Forwarded-Proto to
        # decide cookie Secure flags, so we flip proxy_headers on for that
        # mode.
        proxy_headers=bool(app.state.auth_required),
        # Half-open detection for public binds only (see above). Loopback
        # disables the protocol ping (None) so an event-loop stall can never
        # trigger a false disconnect; a genuinely dead local client is still
        # reaped via the WebSocketDisconnect → disconnect/reap path.
        ws_ping_interval=None if _is_loopback else 20.0,
        ws_ping_timeout=None if _is_loopback else 20.0,
        ws_max_size=_DESKTOP_ATTACHMENT_WS_MAX_BYTES,
    )
    server = uvicorn.Server(config)
