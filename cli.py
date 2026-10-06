"""MobSentry CLI — analyze an APK and print/save JSON without the web UI.

Usage:
  python cli.py path/to/app.apk                 # summary to stdout
  python cli.py path/to/app.apk -o report.json  # full JSON to file
"""
from __future__ import annotations

import argparse
import json
import sys

from core.ai import default_ai_layer
from core.analyzer import analyze


def main() -> int:
    ap = argparse.ArgumentParser(description="MobSentry APK security analyzer")
    ap.add_argument("apk", help="path to .apk")
    ap.add_argument("-o", "--out", help="write full JSON report here")
    ap.add_argument("--no-ai", action="store_true",
                    help="skip the correlation/AI layer")
    args = ap.parse_args()

    db = analyze(args.apk, ai_layer=None if args.no_ai else default_ai_layer)
    data = db.to_dict()

    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, ensure_ascii=False)
        print(f"wrote {args.out}")

    m = data["meta"]
    c = data["counts"]
    print(f"\n{m.get('app_name')}  ({m.get('package')})  v{m.get('version_name')}")
    print(f"min/target SDK: {m.get('min_sdk')}/{m.get('target_sdk')}  "
          f"time: {m.get('analysis_seconds')}s")
    print(f"findings: {c['high']} high, {c['medium']} medium, "
          f"{c['low']} low, {c['info']} info")
    print("-" * 60)
    for f in data["findings"]:
        print(f"[{f['severity'].upper():5}] {f['title']}  ({f['category']})")
    if data["errors"]:
        print("-" * 60)
        print("analyzer notes:")
        for e in data["errors"]:
            print(" ", e)
    return 0


if __name__ == "__main__":
    sys.exit(main())
