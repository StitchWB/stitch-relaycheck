# RelayCheck (stitch-relaycheck)

Open-core **service plugin** for [Stitch Manager](https://github.com/StitchWB/Stitch-Manager):
a **local auditor for AI providers and relay stations** — the «hvoyai.com, but local
and deeper» idea. You paste a base URL + API key; RelayCheck tells you what is really
behind that endpoint.

- **Kind:** `service` (plugin id `stitch-relaycheck`, service `relaycheck`)
- **Runtime:** spawned by the Stitch `ServicePluginHost` as `python -m stitch_relaycheck`,
  speaks JSON-RPC 2.0 (vendored `RpcPluginServer`)
- **Self-contained:** no `stitch_backend` imports; stdlib + `httpx` + `cryptography`
- **Privacy by default:** every probe goes directly from your machine to the endpoint
  you typed. Keys are Fernet-encrypted at rest and never logged, never reported, never
  sent anywhere except the target endpoint. Ad-hoc checks are use-and-burn (the key is
  never persisted).

## Roadmap / features

| # | Feature | Status |
|--- | --- | --- |
| 1 | Quick endpoint check: connectivity, protocol detect, model list, latency | ✅ v0.1.0 |
| 2 | Saved targets with encrypted keys + check history + markdown reports | ✅ v0.1.0 |
| 3 | Model authenticity fingerprint (tokenizer/capability/metadata probes, verdict + score) | ✅ v0.2.0 |
| 4 | Watering detection (heuristics + optional reference-endpoint comparison) | ✅ v0.3.0 |
| 5 | Balance/quota lookup (one-api/new-api, LiteLLM) — read-only | ✅ v0.3.0 |
| 6 | Security scan: canary probes, unsolicited `tool_use`, HoloNe-rule engine, IOC/TLS | ✅ v0.4.0 |
| 7 | Performance measurement (latency/TTFT/TPS/error rate) | ✅ v0.5.0 |
| 8 | Full audit jobs (background), trust score A–F, target comparison | ✅ v0.5.0 |
| 9 | External `holone scan` deep mode (sha256-verified download) + holone proxy guidance | ✅ v0.6.0 |

## Commands

`health_check`, `check_endpoint`, `save_target`, `list_targets`, `check_target`,
`verify_model`, `detect_watering`, `get_balance`, `scan_security`, `measure_performance`,
`start_audit_job`, `run_full_audit`, `get_job`, `list_jobs`, `compare_targets`,
`holone_deep_scan`, `delete_target`, `list_reports`, `get_report`,
`get_report_markdown`, `refresh`, `get_settings`, `set_settings`.

## Layout

```
plugin.json                 manifest (schema v2, declarative UI + i18n + commands)
data/fingerprints.json      model fingerprint profile DB (tokenizer deltas, capabilities)
stitch_relaycheck/
  __main__.py               JSON-RPC entry point (RpcPluginServer)
  service.py                command logic (thin orchestration, security contract)
  client.py                 HTTP layer: protocol detect, model list, chat completions, balance parsers
  fingerprint.py            model authenticity probes + verdict aggregation
  watering.py               answer-dilution heuristics + reference comparison
  security.py               security scan: canary/injection probes, IOC, TLS
  holone_bridge.py          external `holone scan` deep mode (PATH lookup / sha256 download)
  holone_rules/             vendored HoloNe rules.json + blocklist.json
                            (sync: python scripts/sync_holone_rules.py)
scripts/sync_holone_rules.py  re-vendor HoloNe rules from upstream (--check for CI)
  storage.py                SQLite (targets, reports, settings)
  crypto.py                 Fernet at-rest encryption (same scheme as core / stitch-totp)
  _vendor/rpc_server.py     vendored RpcPluginServer (regenerated; do not edit)
tests/                      protocol + unit + e2e (mock relay on 127.0.0.1, no network)
```

## Development

```bash
# from the Stitch-Manager repo root (or with python/ on sys.path):
python -m stitch_plugin_tools run .        # interactive REPL, no host boot
python -m stitch_plugin_tools test .       # pytest suite
python -m stitch_plugin_tools dev-install .
STITCH_DEV_MODE=1 python -m stitch_backend # plugin appears as an AI Hub tab
```

## Holone integration

RelayCheck bundles the HoloNe rule engine (vendored `holone_rules/`, sync via
`python scripts/sync_holone_rules.py`) for its built-in `scan_security`.

Two optional bridges to the standalone [holone](https://github.com/vanndh/holone):

- **Deep scan:** the `holone_deep_scan` command runs the real
  `holone scan <url> --key <key> --model <m> --json` (finds the binary in PATH or
  downloads the release asset verified against `SHA256SUMS.txt`).  Note: the key is
  passed as a CLI argument — visible in the process list for a moment.
- **Continuous protection:** point your AI client at `holone proxy
  --upstream <provider>` (listens on `127.0.0.1:8787`) — holone inspects traffic and
  blocks/alerts on injections.  Stitch AI Hub also has a built-in HoloNe
  (AI Hub → Tools → HoloNe) that protects traffic through the hub.

## Distribution

This plugin is **signed and distributed via the Stitch gated server** — the signing key
lives in the private hub, never in this repo.

```bash
# release flow (maintainer):
python -m stitch_plugin_tools keygen --out keys/
python -m stitch_plugin_tools upgrade . --apply   # refresh scaffold regions
python -m stitch_plugin_tools sign . --key keys/private.key
python -m stitch_plugin_tools dev-install .       # smoke in STITCH_DEV_MODE=1
python -m stitch_plugin_tools publish . --server-url <hub> --admin-key <key> --key keys/private.key
```

## Contributing

External contributions are welcome — open a PR against this repo. Keep changes within
the plugin (no new `stitch_backend` imports, keep the package self-contained). The
vendored `_vendor/rpc_server.py` is regenerated from the core SDK — do not edit it by
hand.

## Disclaimer

RelayCheck is an audit helper, not a guarantee. A clean scan does not prove a provider
is honest (passive prompt exfiltration is structurally undetectable); a suspicious
verdict is a strong signal, not a proof. The safest option is always the official
endpoint.
