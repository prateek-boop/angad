"""ShieldNet command-line entry point."""

from __future__ import annotations

import argparse
import json


def _print_json(value) -> None:
    print(json.dumps(value, indent=2, sort_keys=False, default=str))


def cmd_train(args) -> None:
    from ml_engine.train_model import train

    _print_json(
        train(dataset_mode=args.dataset, n_samples=args.samples, epochs=args.epochs)
    )


def cmd_scan(args) -> None:
    from pipeline.orchestrator import ScanOrchestrator

    result = ScanOrchestrator(persist=not args.no_persist).scan(
        args.url, depth=args.depth, timeout_ms=args.timeout_ms
    )
    _print_json(result)


def cmd_serve(args) -> None:
    import uvicorn

    if args.reload and args.workers != 1:
        raise SystemExit("--reload and --workers cannot be used together")
    uvicorn.run(
        "api.server:app",
        host=args.host,
        port=args.port,
        reload=args.reload,
        workers=args.workers,
        access_log=not args.no_access_log,
    )


def cmd_refresh_feeds(args) -> None:
    from ml_engine.real_data_loader import fetch_feed, load_feed

    results = {}
    for name in args.feeds:
        path = fetch_feed(name, ttl_s=0 if args.force else None)
        rows = load_feed(name, source=path, limit=args.limit)
        results[name] = {"path": path, "records_validated": len(rows)}
    _print_json(results)


def cmd_quantize(_args) -> None:
    from ml_engine.quantize_model import quantize

    quantize()


def cmd_drift(_args) -> None:
    from ml_engine.tier5.drift import DriftMonitor

    _print_json(DriftMonitor().report())


def cmd_feedback_summary(_args) -> None:
    from ml_engine.tier5.feedback import FeedbackStore

    _print_json(FeedbackStore().summary())


def cmd_add_visual_reference(args) -> None:
    from ml_engine.visual.perceptual_hash import hash_image_bytes
    from ml_engine.visual.reference_store import ReferenceStore
    from ml_engine.visual.screenshotter import capture

    screenshot = capture(args.url, timeout_s=args.timeout)
    store = ReferenceStore()
    store.add(args.brand_domain, hash_image_bytes(screenshot))
    store.save()
    _print_json(
        {"brand_domain": args.brand_domain, "references": len(store), "saved": True}
    )


def cmd_remove_visual_reference(args) -> None:
    from ml_engine.visual.reference_store import ReferenceStore

    store = ReferenceStore()
    removed = store.remove(args.brand_domain)
    if removed:
        store.save()
    _print_json({"brand_domain": args.brand_domain, "removed": removed})


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="shieldnet")
    subparsers = parser.add_subparsers(dest="command", required=True)

    train_parser = subparsers.add_parser(
        "train", help="train and calibrate the URL model"
    )
    train_parser.add_argument(
        "--dataset", choices=["synthetic", "real", "combined"], default="synthetic"
    )
    train_parser.add_argument("--samples", type=int, default=5000)
    train_parser.add_argument("--epochs", type=int, default=None)
    train_parser.set_defaults(func=cmd_train)

    for command in ("scan", "test"):
        scan_parser = subparsers.add_parser(command, help="scan one URL")
        scan_parser.add_argument("url")
        scan_parser.add_argument(
            "--depth",
            choices=["tier0", "tier1", "tier2", "tier3", "tier4"],
            default="tier0",
        )
        scan_parser.add_argument("--timeout-ms", type=int, default=None)
        scan_parser.add_argument("--no-persist", action="store_true")
        scan_parser.set_defaults(func=cmd_scan)

    serve_parser = subparsers.add_parser("serve", help="run the FastAPI service")
    serve_parser.add_argument("--host", default="127.0.0.1")
    serve_parser.add_argument("--port", type=int, default=8000)
    serve_parser.add_argument("--workers", type=int, default=1)
    serve_parser.add_argument("--reload", action="store_true")
    serve_parser.add_argument("--no-access-log", action="store_true")
    serve_parser.set_defaults(func=cmd_serve)

    feeds_parser = subparsers.add_parser(
        "refresh-feeds", help="download and validate intelligence feeds"
    )
    feeds_parser.add_argument(
        "--feeds",
        nargs="+",
        choices=["urlhaus", "openphish", "tranco"],
        default=["urlhaus", "openphish"],
    )
    feeds_parser.add_argument("--force", action="store_true")
    feeds_parser.add_argument("--limit", type=int, default=100_000)
    feeds_parser.set_defaults(func=cmd_refresh_feeds)

    quantize_parser = subparsers.add_parser(
        "quantize", help="export the trained model to TFLite"
    )
    quantize_parser.set_defaults(func=cmd_quantize)

    drift_parser = subparsers.add_parser("drift", help="print the rolling drift report")
    drift_parser.set_defaults(func=cmd_drift)

    feedback_parser = subparsers.add_parser(
        "feedback-summary", help="print correction counts"
    )
    feedback_parser.set_defaults(func=cmd_feedback_summary)

    visual_add = subparsers.add_parser(
        "add-visual-reference", help="capture a known-good brand page"
    )
    visual_add.add_argument("brand_domain")
    visual_add.add_argument("url")
    visual_add.add_argument("--timeout", type=float, default=None)
    visual_add.set_defaults(func=cmd_add_visual_reference)

    visual_remove = subparsers.add_parser(
        "remove-visual-reference", help="remove a brand reference"
    )
    visual_remove.add_argument("brand_domain")
    visual_remove.set_defaults(func=cmd_remove_visual_reference)
    return parser


def main() -> None:
    args = build_parser().parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
