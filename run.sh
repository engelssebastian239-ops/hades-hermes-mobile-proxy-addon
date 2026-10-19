#!/bin/sh
# Write default options.json if HA hasn't written one yet
if [ ! -f /data/options.json ]; then
  mkdir -p /data
  cat > /data/options.json << 'EOF'
{"enabled":false,"preflight_only":false,"allow_token_only":false,"public_host":""}
EOF
fi
exec node /opt/hades-hermes-mobile-proxy/server.mjs
