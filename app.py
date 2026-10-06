"""MobSentry web UI — cross-platform (Windows / Linux) Flask app.

Run:  python app.py   then open http://127.0.0.1:5000
Accounts (username = password):
  android / android  -> analyzes Android .apk
  ios     / ios      -> analyzes iOS .ipa
Override passwords with env ANDROID_PASS / IOS_PASS.
"""
from __future__ import annotations

import functools
import io
import multiprocessing
import os
import queue
import tempfile
import threading
import time
import uuid

from flask import (Flask, abort, jsonify, redirect, render_template, request,
                   send_file, session, url_for)
from werkzeug.utils import secure_filename

from core import worker

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 1024 * 1024 * 1024  # 1 GB (IPAs are large)
app.config["SEND_FILE_MAX_AGE_DEFAULT"] = 0            # never cache static assets
app.secret_key = os.environ.get("MOBSENTRY_SECRET", os.urandom(24).hex())

# username -> (password, platform)
ACCOUNTS = {
    "android": (os.environ.get("ANDROID_PASS", "android"), "android"),
    "ios": (os.environ.get("IOS_PASS", "ios"), "ios"),
}
EXT = {"android": ".apk", "ios": ".ipa"}

# cache-busting token for static assets (changes each process start)
ASSET_VER = uuid.uuid4().hex[:8]

UPLOAD_DIR = os.path.join(tempfile.gettempdir(), "mobsentry_uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)
REPORTS: dict[str, dict] = {}

# Analysis runs off the request: a large APK takes minutes, far longer than a
# browser will hold an upload request open. The upload returns at once, the
# scan runs in its own process (see core/worker.py for why not a thread) and
# the report page polls JOBS for progress.
JOBS: dict[str, dict] = {}
_JOBS_LOCK = threading.Lock()
WORKERS = max(1, int(os.environ.get("MOBSENTRY_WORKERS", "2")))
_SLOTS = threading.Semaphore(WORKERS)
# hard limit per scan; a scan stuck past it is killed and reported, never an
# endless spinner
TIMEOUT = max(60, int(os.environ.get("MOBSENTRY_TIMEOUT", "900")))

STAGE_LABELS = {
    "queued": "Waiting for a free analysis slot",
    "parse": "Parsing app (dex / manifest / cross-references)",
}


def _set_job(rid: str, **kw) -> None:
    with _JOBS_LOCK:
        JOBS.setdefault(rid, {}).update(kw)


def _failed(platform: str, title: str, msg: str) -> dict:
    return {"meta": {"parse_failed": True, "platform": platform,
                     "failure": title},
            "errors": [msg]}


def _scan(rid: str, dest: str, platform: str) -> dict:
    ctx = multiprocessing.get_context("spawn")
    q = ctx.Queue()
    p = ctx.Process(target=worker.main, args=(dest, platform, q), daemon=True,
                    name=f"mobsentry-scan-{rid}")
    p.start()
    deadline = time.time() + TIMEOUT
    try:
        while True:
            try:
                kind, payload = q.get(timeout=1)
            except queue.Empty:
                if not p.is_alive():
                    return _failed(platform, "Analysis crashed",
                                   f"analysis: worker exited unexpectedly "
                                   f"(exit code {p.exitcode})")
                if time.time() > deadline:
                    p.kill()
                    stage = JOBS.get(rid, {}).get("stage", "?")
                    return _failed(platform, "Analysis timed out",
                                   f"analysis: stopped after {TIMEOUT // 60} min "
                                   f"in the '{stage}' stage. Raise the limit "
                                   f"with env MOBSENTRY_TIMEOUT (seconds).")
                continue
            if kind == "progress":
                payload["label"] = STAGE_LABELS.get(
                    payload["stage"], f"Running {payload['stage']} checks")
                _set_job(rid, **payload)
            elif kind == "result":
                return payload
            else:
                return _failed(platform, "Analysis failed", f"analysis: {payload}")
    finally:
        p.join(timeout=10)
        if p.is_alive():
            p.kill()


def _run_job(rid: str, dest: str, platform: str, filename: str) -> None:
    try:
        with _SLOTS:
            _set_job(rid, started=time.time())  # elapsed counts from the scan
            data = _scan(rid, dest, platform)
    except Exception as exc:  # noqa: BLE001 - never leave a job hanging
        data = _failed(platform, "Analysis failed",
                       f"analysis: {type(exc).__name__}: {exc}")
    finally:
        try:
            os.remove(dest)
        except OSError:
            pass
    data["filename"] = filename
    REPORTS[rid] = data
    _set_job(rid, status="done", finished=time.time())


def _start_job(rid: str, dest: str, platform: str, filename: str) -> None:
    threading.Thread(target=_run_job, args=(rid, dest, platform, filename),
                     daemon=True, name=f"mobsentry-job-{rid}").start()


@app.context_processor
def _inject():
    return {"asset_ver": ASSET_VER, "platform": session.get("platform")}


def login_required(fn):
    @functools.wraps(fn)
    def wrapper(*a, **kw):
        if not session.get("user"):
            return redirect(url_for("login", next=request.path))
        return fn(*a, **kw)
    return wrapper


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        u = (request.form.get("username") or "").strip().lower()
        p = request.form.get("password") or ""
        acct = ACCOUNTS.get(u)
        if acct and p == acct[0]:
            session["user"] = u
            session["platform"] = acct[1]
            return redirect(request.args.get("next") or url_for("index"))
        error = "Invalid username or password."
    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/")
@login_required
def index():
    return render_template("index.html", user=session.get("user"),
                           platform=session.get("platform"))


@app.route("/analyze", methods=["POST"])
@login_required
def do_analyze():
    platform = session.get("platform", "android")
    want_ext = EXT[platform]
    f = request.files.get("apk")
    if not f or not f.filename:
        return redirect(url_for("index"))
    safe = secure_filename(f.filename) or ("upload" + want_ext)
    if not safe.lower().endswith(want_ext):
        if _wants_json():
            return jsonify({"error": f"This account analyzes {want_ext} files. "
                                     f"You uploaded {safe}."}), 400
        return render_template("index.html", user=session.get("user"),
                               platform=platform,
                               wrong_ext=f"This account analyzes {want_ext} files. "
                                         f"You uploaded {safe}.")
    rid = uuid.uuid4().hex[:12]
    dest = os.path.join(UPLOAD_DIR, f"{rid}_{safe}")
    f.save(dest)
    _set_job(rid, status="running", stage="queued", step=0, total=1,
             label=STAGE_LABELS["queued"], filename=safe,
             size=os.path.getsize(dest), started=time.time())
    _start_job(rid, dest, platform, safe)
    url = url_for("report", rid=rid)
    if _wants_json():
        return jsonify({"rid": rid, "url": url})
    return redirect(url)


def _wants_json() -> bool:
    return request.headers.get("X-Requested-With") == "fetch"


@app.route("/report/<rid>")
@login_required
def report(rid: str):
    if rid not in REPORTS and rid not in JOBS:
        abort(404)
    filename = (REPORTS.get(rid) or JOBS.get(rid) or {}).get("filename", "app")
    return render_template("report.html", rid=rid, filename=filename,
                           user=session.get("user"))


@app.route("/api/report/<rid>")
@login_required
def api_report(rid: str):
    if rid in REPORTS:
        return jsonify(REPORTS[rid])
    job = JOBS.get(rid)
    if not job:
        abort(404)
    # still running: 202 + progress, the page polls until it gets the report
    with _JOBS_LOCK:
        body = dict(job)
    body["elapsed"] = round(time.time() - body.get("started", time.time()))
    return jsonify(body), 202


@app.route("/report/<rid>/pdf")
@login_required
def report_pdf(rid: str):
    if rid not in REPORTS:
        abort(404)
    try:
        from core.report_pdf import build_pdf
        pdf = build_pdf(REPORTS[rid])
    except ModuleNotFoundError:
        return ("PDF export needs reportlab. Install it:  pip install reportlab",
                500)
    name = (REPORTS[rid].get("meta", {}).get("package")
            or REPORTS[rid].get("filename", "report")) + "_mobsentry.pdf"
    return send_file(io.BytesIO(pdf), mimetype="application/pdf",
                     as_attachment=True, download_name=name)


def _port_in_use(host: str, port: int) -> bool:
    import socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.5)
        try:
            return s.connect_ex((host, port)) == 0
        except OSError:
            return False


def main():
    import sys
    import webbrowser
    port = int(os.environ.get("PORT", "5000"))
    host = os.environ.get("HOST", "127.0.0.1")
    url = f"http://{host}:{port}"
    if _port_in_use(host, port):
        print(f"\n  ERROR: port {port} is already in use.")
        print("  Another MobSentry/Flask server is probably still running.")
        print("  Close that terminal (or press Ctrl+C in it), then run again —")
        print(f"  or use another port:  set PORT=5001  (then python app.py)\n")
        sys.exit(1)
    if os.environ.get("MOBSENTRY_OPEN", "1") == "1":
        try:
            webbrowser.open(url)
        except Exception:
            pass
    print(f"\n  MobSentry running on {url}")
    print(f"  Login: android/android (APK)  or  ios/ios (IPA)   (Ctrl+C to stop)\n")
    try:
        from waitress import serve
        serve(app, host=host, port=port, _quiet=True)
    except ModuleNotFoundError:
        import logging
        logging.getLogger("werkzeug").setLevel(logging.ERROR)
        try:
            import flask.cli
            flask.cli.show_server_banner = lambda *a, **k: None
        except Exception:
            pass
        app.run(host=host, port=port,
                debug=bool(os.environ.get("MOBSENTRY_DEBUG")))


if __name__ == "__main__":
    main()
