"""Scan worker used by the web UI (app.py): one process per scan.

Scans run in separate processes, not threads: androguard is pure-Python and
CPU-bound, so a scan thread holds the GIL and starves the web server — uploads
crawl and progress polls stall. A process per scan keeps the UI responsive,
lets concurrent scans use separate cores, frees androguard's memory when the
scan ends, and can be killed if it overruns the time limit.

Everything goes back to the web process over a queue as (kind, payload):
("progress", {stage, step, total}), then ("result", report) or ("error", msg).
"""
from __future__ import annotations


def main(path: str, platform: str, queue) -> None:
    try:
        from .ai import default_ai_layer
        from .analyzer import analyze

        def progress(stage: str, step: int, total: int) -> None:
            queue.put(("progress", {"stage": stage, "step": step,
                                    "total": total}))

        db = analyze(path, platform=platform, ai_layer=default_ai_layer,
                     progress=progress)
        queue.put(("result", db.to_dict()))
    except BaseException as exc:  # noqa: BLE001 - always answer the parent
        queue.put(("error", f"{type(exc).__name__}: {exc}"))
