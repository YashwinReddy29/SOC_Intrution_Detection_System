"""Benchmark end-to-end ML event ingestion and Socket.IO alert latency.

Run the Flask application first, then execute:
    python scripts/benchmark_event_latency.py

The benchmark measures:
- HTTP latency: POST /api/ml/events request/response time.
- Socket latency: time from POST start until the matching detection_event
  is received by a Socket.IO client.
- Server ML latency: latency_ms returned by DetectionService.

Events are generated in chronological order from the same synthetic stream
used by the ML experiment. A warm-up period populates rolling feature state
before measured events are sent.
"""

from __future__ import annotations

import argparse
import json
import statistics
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import requests
import socketio

from ml.synthetic_data_generator import GeneratorConfig, generate_dataset


@dataclass
class Measurement:
    label: int
    attack_type: str
    http_ms: float
    socket_ms: float | None
    server_ml_ms: float
    detected: bool


def percentile(values: list[float], p: float) -> float:
    if not values:
        return float("nan")
    ordered = sorted(values)
    index = (len(ordered) - 1) * p / 100.0
    low = int(index)
    high = min(low + 1, len(ordered) - 1)
    weight = index - low
    return ordered[low] * (1.0 - weight) + ordered[high] * weight


class SocketTracker:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._received: dict[str, float] = {}

    def add(self, event_key: str) -> None:
        with self._lock:
            self._received[event_key] = time.perf_counter()

    def pop(self, event_key: str) -> float | None:
        with self._lock:
            return self._received.pop(event_key, None)


def event_key(event: dict[str, Any]) -> str:
    # The event itself is echoed in detection_event, so this is stable without
    # changing the application contract just for benchmarking.
    return json.dumps(
        {
            "timestamp": str(event["timestamp"]),
            "source_ip": str(event["source_ip"]),
            "destination_port": int(event["destination_port"]),
            "bytes_in": int(event["bytes_in"]),
            "bytes_out": int(event["bytes_out"]),
            "failed_logins": int(event["failed_logins"]),
        },
        sort_keys=True,
    )


def prepare_event(row: Any) -> dict[str, Any]:
    """Convert a pandas row into JSON-safe API input."""
    event = row.to_dict()
    if hasattr(event.get("timestamp"), "isoformat"):
        event["timestamp"] = event["timestamp"].isoformat()
    return event


def wait_for_socket_event(
    tracker: SocketTracker,
    key: str,
    timeout: float,
) -> float | None:
    deadline = time.perf_counter() + timeout
    while time.perf_counter() < deadline:
        received = tracker.pop(key)
        if received is not None:
            return received
        time.sleep(0.001)
    return None


def summarize(name: str, values: list[float]) -> None:
    if not values:
        print(f"{name}: no samples")
        return
    print(
        f"{name}: mean={statistics.mean(values):.2f} ms | "
        f"p50={percentile(values, 50):.2f} ms | "
        f"p95={percentile(values, 95):.2f} ms | "
        f"p99={percentile(values, 99):.2f} ms | "
        f"max={max(values):.2f} ms"
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default="http://127.0.0.1:5000")
    parser.add_argument("--samples", type=int, default=200)
    parser.add_argument("--warmup", type=int, default=100)
    parser.add_argument("--socket-timeout", type=float, default=2.0)
    args = parser.parse_args()

    if args.samples < 10:
        raise SystemExit("--samples must be at least 10")
    if args.warmup < 0:
        raise SystemExit("--warmup cannot be negative")

    session = requests.Session()
    health_url = f"{args.base_url.rstrip('/')}/api/ml/health"
    events_url = f"{args.base_url.rstrip('/')}/api/ml/events"

    try:
        health = session.get(health_url, timeout=5)
        health.raise_for_status()
    except Exception as exc:
        raise SystemExit(
            f"Could not reach {health_url}. Start Flask first. Error: {exc}"
        ) from exc

    health_payload = health.json()
    print("ML health:")
    print(json.dumps(health_payload, indent=2))

    tracker = SocketTracker()
    sio = socketio.Client(logger=False, engineio_logger=False)

    @sio.on("detection_event")
    def on_detection_event(payload: dict[str, Any]) -> None:
        event = payload.get("event")
        if isinstance(event, dict):
            try:
                tracker.add(event_key(event))
            except (KeyError, TypeError, ValueError):
                return

    try:
        socket_url = args.base_url.rstrip("/")
        sio.connect(socket_url, wait_timeout=5)
    except Exception as exc:
        raise SystemExit(
            "Could not connect to Socket.IO. Confirm the Flask app is running "
            f"with Flask-SocketIO. Error: {exc}"
        ) from exc

    print(f"Generating {args.warmup + args.samples} chronological events...")
    df = generate_dataset(
        GeneratorConfig(total_events=max(args.warmup + args.samples + 100, 1000))
    )

    if args.warmup + args.samples > len(df):
        sio.disconnect()
        raise SystemExit("Not enough generated events for the requested sample size")

    print(f"Warming up with {args.warmup} events...")
    for _, row in df.iloc[: args.warmup].iterrows():
        event = prepare_event(row)
        response = session.post(events_url, json=event, timeout=5)
        response.raise_for_status()

    measurements: list[Measurement] = []
    print(f"Measuring {args.samples} events...")

    measured = df.iloc[args.warmup : args.warmup + args.samples]
    for index, (_, row) in enumerate(measured.iterrows(), start=1):
        event = prepare_event(row)
        key = event_key(event)
        started = time.perf_counter()

        response = session.post(events_url, json=event, timeout=5)
        http_done = time.perf_counter()
        response.raise_for_status()
        payload = response.json()

        socket_received = wait_for_socket_event(
            tracker,
            key,
            timeout=args.socket_timeout,
        )

        detection = payload.get("detection", {})
        measurement = Measurement(
            label=int(event.get("label", 0)),
            attack_type=str(event.get("attack_type", "unknown")),
            http_ms=(http_done - started) * 1000.0,
            socket_ms=(
                (socket_received - started) * 1000.0
                if socket_received is not None
                else None
            ),
            server_ml_ms=float(detection.get("latency_ms", float("nan"))),
            detected=bool(detection.get("detected", False)),
        )
        measurements.append(measurement)

        if index % 25 == 0 or index == args.samples:
            print(f"  completed {index}/{args.samples}")

    sio.disconnect()
    session.close()

    http_values = [m.http_ms for m in measurements]
    socket_values = [m.socket_ms for m in measurements if m.socket_ms is not None]
    server_values = [m.server_ml_ms for m in measurements]

    print("\n=== End-to-End Latency Results ===")
    print(f"samples: {len(measurements)}")
    print(f"socket_matches: {len(socket_values)}/{len(measurements)}")
    summarize("HTTP ingest latency", http_values)
    summarize("Socket.IO delivery latency", socket_values)
    summarize("Server ML latency", server_values)

    attacks = [m for m in measurements if m.label == 1]
    normals = [m for m in measurements if m.label == 0]
    print(
        f"classification samples: attack={len(attacks)} | normal={len(normals)} | "
        f"detected={sum(m.detected for m in measurements)}"
    )

    by_type: dict[str, list[float]] = {}
    for measurement in attacks:
        by_type.setdefault(measurement.attack_type, []).append(measurement.http_ms)

    print("\nAttack-family HTTP latency:")
    for attack_type, values in sorted(by_type.items()):
        print(
            f"  {attack_type}: n={len(values)} | "
            f"mean={statistics.mean(values):.2f} ms | "
            f"p95={percentile(values, 95):.2f} ms"
        )

    report_dir = Path("ml/reports")
    report_dir.mkdir(parents=True, exist_ok=True)
    report_path = report_dir / "event_latency_report.json"
    report = {
        "base_url": args.base_url,
        "samples": len(measurements),
        "warmup": args.warmup,
        "socket_matches": len(socket_values),
        "http_ms": {
            "mean": statistics.mean(http_values),
            "p50": percentile(http_values, 50),
            "p95": percentile(http_values, 95),
            "p99": percentile(http_values, 99),
        },
        "socket_ms": {
            "mean": statistics.mean(socket_values) if socket_values else None,
            "p50": percentile(socket_values, 50) if socket_values else None,
            "p95": percentile(socket_values, 95) if socket_values else None,
            "p99": percentile(socket_values, 99) if socket_values else None,
        },
        "server_ml_ms": {
            "mean": statistics.mean(server_values),
            "p50": percentile(server_values, 50),
            "p95": percentile(server_values, 95),
            "p99": percentile(server_values, 99),
        },
        "health": health_payload,
    }
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"\nSaved report: {report_path}")


if __name__ == "__main__":
    main()
