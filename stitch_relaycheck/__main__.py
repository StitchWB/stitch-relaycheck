"""RPC entry point for the stitch-relaycheck service plugin.

Spawned by ``ServicePluginHost`` as ``python -m stitch_relaycheck``.
Implements the JSON-RPC 2.0 line protocol via ``RpcPluginServer``.

Protocol methods handled automatically by ``RpcPluginServer``:
  - ``plugin.init``    -> stores handshake params via ``_Ctx``.
  - ``plugin.ping``    -> returns ``"pong"``.
  - ``plugin.shutdown``-> returns ``None`` and exits.

``plugin.call`` dispatches to registered handlers.  ``_migrate_db``
is a reserved call name used by the host after init to create SQLite
tables (``contributions.storage.migrations = "raw_sql"``).

Standalone: tries to import ``RpcPluginServer`` from
``autoreg.plugin.rpc`` (available when ``autoreg`` is on ``sys.path``).
If the import fails (standalone plugin without the host's python tree),
a vendored equivalent is loaded from ``._vendor.rpc_server``.
"""

# _generated_by: stitch_plugin_tools scaffold v3

from __future__ import annotations

from typing import Any

from . import crypto, service, storage

try:
    from autoreg.plugin.rpc import RpcPluginServer
except ImportError:
    from ._vendor.rpc_server import RpcPluginServer

try:
    from autoreg.plugin.helpers import resolve_owner_id
except ImportError:
    from ._vendor.plugin_helpers import resolve_owner_id


# ── State received in plugin.init handshake ───────────────────────────────


class _Ctx:
    """Mutable container for plugin.init handshake state."""

    db_path: str = ""
    data_dir: str = ""
    supported: list[str] = []


ctx = _Ctx()


def _handle_init(params: dict[str, Any]) -> dict[str, Any]:
    """Store handshake params, resolve the Fernet key, return the result.

    ``supported`` lists the optional host features available in this
    session (e.g. ``reverse_rpc``, ``caller_identity``).  RelayCheck uses
    neither today — ``capabilities`` stays ``[]``.
    """
    ctx.db_path = str(params.get("db_path", ""))
    ctx.data_dir = str(params.get("data_dir", ""))
    supported = params.get("supported")
    ctx.supported = list(supported) if isinstance(supported, list) else []
    if ctx.data_dir:
        # Resolve the at-rest encryption key before any command handler runs
        # (targets store Fernet-encrypted API keys).
        crypto.init_crypto(ctx.data_dir)
    return {
        "plugin_id": params.get("plugin_id", ""),
        "db_path": ctx.db_path,
        "data_dir": ctx.data_dir,
        "capabilities": [],
    }


def _handle_migrate_db(params: dict[str, Any]) -> dict[str, Any]:
    """Create SQLite tables (raw_sql migration)."""
    if ctx.db_path:
        storage.migrate(ctx.db_path)
    return {
        "from_version": params.get("from_version", 0),
        "to_version": params.get("to_version", 1),
    }


def _handle_health_check(params: dict[str, Any]) -> dict[str, Any]:
    """Health-check command — returns pong."""
    return service.health_check()


def _handle_check_endpoint(params: dict[str, Any]) -> dict[str, Any]:
    """Ad-hoc quick check of an endpoint (key is never persisted)."""
    resolve_owner_id(params)  # caller identity available for per-user logic
    base_url = str(params.get("baseUrl", params.get("base_url", "")))
    api_key = str(params.get("apiKey", params.get("api_key", "")))
    model = str(params.get("model", "") or "")
    if not base_url or not api_key:
        raise ValueError("baseUrl and apiKey are required")
    return service.quick_check(ctx.db_path, base_url, api_key, model=model)


def _handle_save_target(params: dict[str, Any]) -> dict[str, Any]:
    """Save a relay target (key is Fernet-encrypted before storage)."""
    name = str(params.get("name", ""))
    base_url = str(params.get("baseUrl", params.get("base_url", "")))
    api_key = str(params.get("apiKey", params.get("api_key", "")))
    note = str(params.get("note", "") or "")
    model = str(params.get("model", "") or "")
    persist_key = params.get("persistKey", params.get("persist_key", True))
    return service.save_target(
        ctx.db_path,
        name=name,
        base_url=base_url,
        api_key=api_key,
        note=note,
        model=model,
        persist_key=bool(persist_key),
    )


def _handle_list_targets(params: dict[str, Any]) -> dict[str, Any]:
    """List saved targets."""
    return service.list_targets(ctx.db_path)


def _handle_check_target(params: dict[str, Any]) -> dict[str, Any]:
    """Run a quick check against a saved target."""
    target_id = str(params.get("id", ""))
    return service.check_target(ctx.db_path, target_id)


def _handle_delete_target(params: dict[str, Any]) -> dict[str, Any]:
    """Delete a saved target."""
    target_id = str(params.get("id", ""))
    return service.delete_target(ctx.db_path, target_id)


def _handle_list_reports(params: dict[str, Any]) -> dict[str, Any]:
    """List recent reports."""
    limit = params.get("limit", 50)
    try:
        limit = int(limit)
    except (TypeError, ValueError):
        limit = 50
    return service.list_reports(ctx.db_path, limit=limit)


def _handle_get_report(params: dict[str, Any]) -> dict[str, Any]:
    """Get one report by id (or ``latest``)."""
    report_id = str(params.get("reportId", params.get("report_id", "latest")))
    return service.get_report(ctx.db_path, report_id)


def _handle_get_report_markdown(params: dict[str, Any]) -> dict[str, Any]:
    """Render a report as markdown."""
    report_id = str(params.get("reportId", params.get("report_id", "latest")))
    return service.get_report_markdown(ctx.db_path, report_id)


def _handle_refresh(params: dict[str, Any]) -> dict[str, Any]:
    """No-op used by table rowActions to force a refetch."""
    return service.refresh(ctx.db_path)


def _handle_verify_model(params: dict[str, Any]) -> dict[str, Any]:
    """Fingerprint a model behind a relay (saved target or ad-hoc endpoint)."""
    model = str(params.get("model", "") or "")
    target_id = str(params.get("targetId", params.get("target_id", "")) or "")
    base_url = str(params.get("baseUrl", params.get("base_url", "")))
    api_key = str(params.get("apiKey", params.get("api_key", "")))
    return service.verify_model(
        ctx.db_path,
        model=model,
        target_id=target_id,
        base_url=base_url,
        api_key=api_key,
    )


def _handle_measure_performance(params: dict[str, Any]) -> dict[str, Any]:
    """Measure latency / TTFT / TPS / error rate."""
    return service.measure_performance(
        ctx.db_path,
        model=str(params.get("model", "") or ""),
        target_id=str(params.get("targetId", params.get("target_id", "")) or ""),
        base_url=str(params.get("baseUrl", params.get("base_url", ""))),
        api_key=str(params.get("apiKey", params.get("api_key", ""))),
        repeats=params.get("repeats", 5),
    )


def _handle_start_audit_job(params: dict[str, Any]) -> dict[str, Any]:
    """Start a full audit in the background; returns job_id immediately."""
    layers = params.get("layers")
    if layers is not None and not isinstance(layers, list):
        raise ValueError("layers must be a list")
    return service.start_audit_job(
        ctx.db_path,
        model=str(params.get("model", "") or ""),
        target_id=str(params.get("targetId", params.get("target_id", "")) or ""),
        base_url=str(params.get("baseUrl", params.get("base_url", ""))),
        api_key=str(params.get("apiKey", params.get("api_key", ""))),
        layers=layers,
    )


def _handle_run_full_audit(params: dict[str, Any]) -> dict[str, Any]:
    """Synchronous full audit (start + block until done)."""
    layers = params.get("layers")
    if layers is not None and not isinstance(layers, list):
        raise ValueError("layers must be a list")
    return service.run_full_audit(
        ctx.db_path,
        model=str(params.get("model", "") or ""),
        target_id=str(params.get("targetId", params.get("target_id", "")) or ""),
        base_url=str(params.get("baseUrl", params.get("base_url", ""))),
        api_key=str(params.get("apiKey", params.get("api_key", ""))),
        layers=layers,
        wait_seconds=float(params.get("waitSeconds", params.get("wait_seconds", 120))),
    )


def _handle_get_job(params: dict[str, Any]) -> dict[str, Any]:
    """Get one audit job by id."""
    return service.get_job(
        ctx.db_path, str(params.get("jobId", params.get("job_id", "")))
    )


def _handle_list_jobs(params: dict[str, Any]) -> dict[str, Any]:
    """List recent audit jobs."""
    return service.list_jobs(ctx.db_path, limit=params.get("limit", 30))


def _handle_compare_targets(params: dict[str, Any]) -> dict[str, Any]:
    """Side-by-side comparison of two saved targets."""
    return service.compare_targets(
        ctx.db_path,
        target_id_a=str(params.get("targetIdA", params.get("target_id_a", ""))),
        target_id_b=str(params.get("targetIdB", params.get("target_id_b", ""))),
    )


def _handle_holone_deep_scan(params: dict[str, Any]) -> dict[str, Any]:
    """Deep security scan via the external holone binary (optional)."""
    return service.holone_deep_scan(
        ctx.db_path,
        model=str(params.get("model", "") or ""),
        target_id=str(params.get("targetId", params.get("target_id", "")) or ""),
        base_url=str(params.get("baseUrl", params.get("base_url", ""))),
        api_key=str(params.get("apiKey", params.get("api_key", ""))),
    )


def _handle_get_settings(params: dict[str, Any]) -> dict[str, Any]:
    """Return effective plugin settings."""
    return {"success": True, "settings": service.get_settings(ctx.db_path)}


def _handle_detect_watering(params: dict[str, Any]) -> dict[str, Any]:
    """Watering check: diluted/rewritten answers (optional reference compare)."""
    return service.detect_watering(
        ctx.db_path,
        model=str(params.get("model", "") or ""),
        target_id=str(params.get("targetId", params.get("target_id", "")) or ""),
        base_url=str(params.get("baseUrl", params.get("base_url", ""))),
        api_key=str(params.get("apiKey", params.get("api_key", ""))),
        reference_base_url=str(
            params.get("referenceBaseUrl", params.get("reference_base_url", "")) or ""
        ),
        reference_api_key=str(
            params.get("referenceApiKey", params.get("reference_api_key", "")) or ""
        ),
        reference_model=str(
            params.get("referenceModel", params.get("reference_model", "")) or ""
        ),
    )


def _handle_get_balance(params: dict[str, Any]) -> dict[str, Any]:
    """Read-only balance/quota lookup against the relay dashboard."""
    return service.get_balance(
        ctx.db_path,
        target_id=str(params.get("targetId", params.get("target_id", "")) or ""),
        base_url=str(params.get("baseUrl", params.get("base_url", ""))),
        api_key=str(params.get("apiKey", params.get("api_key", ""))),
    )


def _handle_scan_security(params: dict[str, Any]) -> dict[str, Any]:
    """Security scan: canary, injection probes, IOC, TLS (HoloNe rules)."""
    return service.scan_security(
        ctx.db_path,
        model=str(params.get("model", "") or ""),
        target_id=str(params.get("targetId", params.get("target_id", "")) or ""),
        base_url=str(params.get("baseUrl", params.get("base_url", ""))),
        api_key=str(params.get("apiKey", params.get("api_key", ""))),
    )


def _handle_set_settings(params: dict[str, Any]) -> dict[str, Any]:
    """Merge a settings patch."""
    patch = params.get("settings", params.get("patch"))
    if not isinstance(patch, dict):
        # Allow flat params: {timeoutSeconds: 20} directly.
        patch = {
            k: v
            for k, v in params.items()
            if k in service.DEFAULT_SETTINGS
        }
    settings = service.set_settings(ctx.db_path, patch)
    return {"success": True, "settings": settings}


# ── Server entry point ────────────────────────────────────────────────────


def main() -> None:
    """Register handlers and serve the JSON-RPC loop."""
    server = RpcPluginServer()
    server.set_init_handler(_handle_init)
    server.register("_migrate_db", _handle_migrate_db)
    server.register("health_check", _handle_health_check)
    server.register("check_endpoint", _handle_check_endpoint)
    server.register("save_target", _handle_save_target)
    server.register("list_targets", _handle_list_targets)
    server.register("check_target", _handle_check_target)
    server.register("delete_target", _handle_delete_target)
    server.register("list_reports", _handle_list_reports)
    server.register("get_report", _handle_get_report)
    server.register("get_report_markdown", _handle_get_report_markdown)
    server.register("verify_model", _handle_verify_model)
    server.register("detect_watering", _handle_detect_watering)
    server.register("get_balance", _handle_get_balance)
    server.register("scan_security", _handle_scan_security)
    server.register("measure_performance", _handle_measure_performance)
    server.register("start_audit_job", _handle_start_audit_job)
    server.register("run_full_audit", _handle_run_full_audit)
    server.register("get_job", _handle_get_job)
    server.register("list_jobs", _handle_list_jobs)
    server.register("compare_targets", _handle_compare_targets)
    server.register("holone_deep_scan", _handle_holone_deep_scan)
    server.register("refresh", _handle_refresh)
    server.register("get_settings", _handle_get_settings)
    server.register("set_settings", _handle_set_settings)
    server.serve()


if __name__ == "__main__":
    main()
