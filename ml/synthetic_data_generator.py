"""Generate reproducible, session-based synthetic SOC events.

The generator creates a realistic 30-day event stream in which normal traffic
and attack sessions are interleaved across time. This makes chronological
train/validation/test evaluation meaningful while preserving rolling behavioral
signals for the seven ML features.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import List
import random

import numpy as np
import pandas as pd


@dataclass(frozen=True)
class GeneratorConfig:
    total_events: int = 10_000
    attack_fraction: float = 0.20
    seed: int = 42
    start: datetime = datetime(2026, 1, 1, tzinfo=timezone.utc)
    duration_days: int = 30


NORMAL_PROTOCOLS = ["TCP", "UDP", "ICMP", "HTTPS"]
ATTACK_TYPES = [
    "brute_force",
    "port_scan",
    "data_exfiltration",
    "ddos",
    "credential_stuffing",
]


def _private_ip(rng: random.Random) -> str:
    return f"10.{rng.randint(0, 30)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"


def _normal_event(rng: random.Random, timestamp: datetime, source_ip: str) -> dict:
    rng_np = np.random.default_rng(rng.randint(0, 2**31 - 1))
    bytes_in = int(rng_np.lognormal(8.0, 0.8))
    bytes_out = int(rng_np.lognormal(7.5, 0.7))

    # Keep normal geolocation clustered to plausible regions.
    latitude = rng.gauss(39.5, 6.0)
    longitude = rng.gauss(-98.5, 15.0)

    return {
        "timestamp": timestamp,
        "source_ip": source_ip,
        "destination_ip": f"192.0.2.{rng.randint(1, 254)}",
        "source_port": rng.randint(1024, 65535),
        "destination_port": rng.choice([53, 80, 123, 443, 22]),
        "protocol": rng.choice(NORMAL_PROTOCOLS),
        "bytes_in": bytes_in,
        "bytes_out": bytes_out,
        "failed_logins": 0,
        "country": rng.choice(["US", "CA", "GB", "DE"]),
        "latitude": latitude,
        "longitude": longitude,
        "label": 0,
        "attack_type": "normal",
    }


def _attack_session(
    rng: random.Random,
    start: datetime,
    attack_type: str,
    count: int,
) -> List[dict]:
    """Create a temporally correlated attack session."""
    primary_source = _private_ip(rng)
    events: List[dict] = []

    # DDoS is intentionally multi-source; the other attack types use a stable
    # source identity so rolling source-level features can detect the behavior.
    sources = [
        _private_ip(rng) for _ in range(min(12, max(3, count // 8)))
    ] if attack_type == "ddos" else [primary_source]

    elapsed = 0.0
    for i in range(count):
        # Fast bursts make rolling-window behavior visible without requiring
        # unrealistically identical timestamps.
        elapsed += rng.uniform(0.25, 3.5)
        ts = start + timedelta(seconds=elapsed)
        source_ip = rng.choice(sources)
        event = _normal_event(rng, ts, source_ip)
        event["label"] = 1
        event["attack_type"] = attack_type

        if attack_type == "brute_force":
            event.update({
                "destination_port": 22,
                "protocol": "TCP",
                "failed_logins": rng.randint(1, 4),
                "bytes_in": rng.randint(150, 700),
                "bytes_out": rng.randint(50, 400),
            })

        elif attack_type == "credential_stuffing":
            event.update({
                "destination_port": 443,
                "protocol": "HTTPS",
                "failed_logins": rng.randint(1, 3),
                "bytes_in": rng.randint(300, 1200),
                "bytes_out": rng.randint(100, 600),
            })

        elif attack_type == "port_scan":
            event.update({
                "destination_port": rng.choice(
                    list(range(1, 1024))
                    + [1433, 1521, 3306, 3389, 5432, 6379, 8080]
                ),
                "protocol": "TCP",
                "bytes_in": rng.randint(40, 150),
                "bytes_out": rng.randint(40, 150),
            })

        elif attack_type == "data_exfiltration":
            event.update({
                "destination_port": rng.choice([443, 8443, 22]),
                "protocol": "HTTPS",
                "bytes_in": rng.randint(100, 1500),
                "bytes_out": rng.randint(500_000, 8_000_000),
                # Exfiltration to a geographically different region.
                "latitude": rng.uniform(-35, 35),
                "longitude": rng.uniform(110, 150),
                "country": rng.choice(["AU", "SG"]),
            })

        elif attack_type == "ddos":
            event.update({
                "destination_port": rng.choice([80, 443]),
                "protocol": rng.choice(["TCP", "UDP"]),
                "bytes_in": rng.randint(500, 5000),
                "bytes_out": rng.randint(50, 500),
            })

        events.append(event)

    return events


def generate_dataset(config: GeneratorConfig | None = None) -> pd.DataFrame:
    """Generate a reproducible, interleaved 30-day SOC dataset."""
    config = config or GeneratorConfig()

    if config.total_events < 100:
        raise ValueError("total_events must be at least 100")
    if not 0 < config.attack_fraction < 1:
        raise ValueError("attack_fraction must be between 0 and 1")
    if config.duration_days < 3:
        raise ValueError("duration_days must be at least 3")

    rng = random.Random(config.seed)
    attack_count = int(round(config.total_events * config.attack_fraction))
    normal_count = config.total_events - attack_count

    end = config.start + timedelta(days=config.duration_days)
    total_seconds = int((end - config.start).total_seconds())

    # Stable normal identities make normal rolling behavior consistent.
    normal_sources = [
        _private_ip(rng) for _ in range(max(150, normal_count // 30))
    ]

    events: List[dict] = []

    # Normal traffic is distributed uniformly over the full period rather than
    # occupying only the beginning of the dataset.
    for _ in range(normal_count):
        offset = rng.uniform(0, total_seconds - 1)
        timestamp = config.start + timedelta(seconds=offset)
        events.append(
            _normal_event(rng, timestamp, rng.choice(normal_sources))
        )

    # Attack sessions are also distributed across the full period. Session
    # starts are restricted away from the final minute so every session fits.
    remaining = attack_count
    attack_index = 0
    while remaining > 0:
        attack_type = ATTACK_TYPES[attack_index % len(ATTACK_TYPES)]
        session_size = min(remaining, rng.randint(18, 65))
        start_offset = rng.uniform(0, total_seconds - 600)
        session_start = config.start + timedelta(seconds=start_offset)
        events.extend(
            _attack_session(rng, session_start, attack_type, session_size)
        )
        remaining -= session_size
        attack_index += 1

    df = (
        pd.DataFrame(events)
        .sort_values("timestamp")
        .reset_index(drop=True)
    )

    return df


def save_dataset(df: pd.DataFrame, path: str) -> None:
    """Persist generated events as CSV, creating parent directories if needed."""
    from pathlib import Path

    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)

    frame = df.copy()
    frame["timestamp"] = pd.to_datetime(
        frame["timestamp"], utc=True
    ).astype(str)
    frame.to_csv(output, index=False)


if __name__ == "__main__":
    df = generate_dataset()
    save_dataset(df, "ml/data/soc_events_v2.csv")
    print(df["label"].value_counts().sort_index().to_dict())
    print(df["attack_type"].value_counts().to_dict())
