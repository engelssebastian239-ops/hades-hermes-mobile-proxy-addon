# Changelog

## 0.1.0-m5.78
- Fix: wait for HA to write options.json instead of overwriting it
- Remove shell wrapper, bootstrap fully in server.mjs

## 0.1.0-m5.77
- Fix: write safe defaults in JS if options.json missing

## 0.1.0-m5.76
- Cache-bust after deinstall

## 0.1.0-m5.75
- Add run.sh shell wrapper for options.json bootstrap

## 0.1.0-m5.74
- Make public_host optional (str?)
- Add retry logic for reading options.json
