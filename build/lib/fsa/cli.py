"""Command line entry point."""
import argparse
import json
from pathlib import Path
from .analyzer import scan_file
from .reporting import write_json, write_html

def build_parser():
    parser = argparse.ArgumentParser(prog="fsa", description="Defensive firmware static analyzer")
    sub = parser.add_subparsers(dest="command", required=True)
    scan = sub.add_parser("scan", help="Analyze a firmware image without executing it")
    scan.add_argument("image")
    scan.add_argument("--out", default="report.json")
    scan.add_argument("--html", default=None)
    scan.add_argument("--max-strings", type=int, default=20000)
    scan.add_argument("--max-file-size-mib", type=int, default=512, help="Reject images larger than this size")
    scan.add_argument("--cve-feed", default=None, help="Path to normalized offline CVE JSON feed")
    info = sub.add_parser("info", help="Show basic file metadata")
    info.add_argument("image")
    serve = sub.add_parser("serve", help="Start optional local web interface")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8000)
    return parser

def _ensure_safe_report_paths(image: str, json_path: str, html_path: str | None) -> None:
    source = Path(image).resolve()
    targets = [Path(json_path), *([Path(html_path)] if html_path else [])]
    resolved = [target.resolve() for target in targets]
    if len(set(resolved)) != len(resolved):
        raise SystemExit("JSON and HTML report paths must be different")
    for target in targets:
        if target.resolve() == source:
            raise SystemExit("Refusing to overwrite the input firmware image")
        if target.exists() and source.exists():
            try:
                if target.samefile(source):
                    raise SystemExit("Refusing to overwrite the input firmware image")
            except OSError:
                pass

def main():
    args = build_parser().parse_args()
    if args.command == "scan":
        _ensure_safe_report_paths(args.image, args.out, args.html)
        if args.max_file_size_mib <= 0:
            raise SystemExit("--max-file-size-mib must be positive")
        report = scan_file(args.image, args.max_strings, args.cve_feed, args.max_file_size_mib * 1024 * 1024)
        write_json(report, args.out)
        if args.html:
            write_html(report, args.html)
        print(json.dumps({"json_report": str(Path(args.out)), "html_report": args.html,
                          "sha256": report["input"]["sha256"],
                          "findings": len(report["analysis"]["heuristic_findings"])},
                         indent=2))
    elif args.command == "info":
        path = Path(args.image)
        import hashlib
        if not path.is_file():
            raise SystemExit(f"Not a file: {path}")
        digest = hashlib.sha256()
        size = 0
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                size += len(chunk)
                digest.update(chunk)
        print(json.dumps({"name": path.name, "size_bytes": size,
                          "sha256": digest.hexdigest()}, indent=2))
    elif args.command == "serve":
        try:
            import uvicorn
            from .webapp import app
        except ImportError as exc:
            raise SystemExit("Install web extras: python -m pip install -e '.[web]'") from exc
        uvicorn.run(app, host=args.host, port=args.port)
