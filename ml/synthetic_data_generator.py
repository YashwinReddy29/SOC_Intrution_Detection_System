"""Generate reproducible, session-based synthetic SOC events.

The generator creates a realistic 30-day event stream in which normal traffic
and attack sessions are interleaved across time. Each chronological evaluation
period receives the same attack-family mix so model evaluation measures
performance over time rather than accidental attack-type composition drift.
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


def _normal_event(
    rng: random.Random,
    timestamp: datetime,
    source_ip: str,
    latitude: float,
    longitude: float,
    country: str,
) -> dict:
    rng_np = np.random.default_rng(rng.randint(0, 2**31 - 1))
    bytes_in = int(rng_np.lognormal(8.0, 0.8))
    bytes_out = int(rng_np.lognormal(7.5, 0.7))

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
        "country": country,
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
    """Create one temporally correlated attack session."""
    primary_source = _private_ip(rng)

    # DDoS uses multiple stable source identities. Other attacks use one source
    # so source-level rolling behavior is meaningful.
    sources = (
        [_private_ip(rng) for _ in range(min(12, max(3, count // 8)))]
        if attack_type == "ddos"
        else [primary_source]
    )

    # Stable source geolocation for ordinary traffic. Exfiltration deliberately
    # shifts location after the first event to create a geographic-anomaly signal.
    source_latitude = rng.gauss(39.5, 3.0)
    source_longitude = rng.gauss(-98.5, 8.0)

    events: List[dict] = []
    elapsed = 0.0

    for i in range(count):
        elapsed += rng.uniform(0.25, 3.5)
        ts = start + timedelta(seconds=elapsed)
        source_ip = rng.choice(sources)

        event = _normal_event(
            rng,
            ts,
            source_ip,
            source_latitude,
            source_longitude,
            "US",
        )
        event["label"] = 1
        event["attack_type"] = attack_type

        if attack_type == "brute_force":
            event.update(
                {
                    "destination_port": 22,
                    "protocol": "TCP",
                    "failed_logins": rng.randint(1, 4),
                    "bytes_in": rng.randint(150, 700),
                    "bytes_out": rng.randint(50, 400),
                }
            )

        elif attack_type == "credential_stuffing":
            event.update(
                {
                    "destination_port": 443,
                    "protocol": "HTTPS",
                    "failed_logins": rng.randint(1, 3),
                    "bytes_in": rng.randint(300, 1200),
                    "bytes_out": rng.randint(100, 600),
                }
            )

        elif attack_type == "port_scan":
            event.update(
                {
                    "destination_port": rng.choice(
                        list(range(1, 1024))
                        + [1433, 1521, 3306, 3389, 5432, 6379, 8080]
                    ),
                    "protocol": "TCP",
                    "bytes_in": rng.randint(40, 150),
                    "bytes_out": rng.randint(40, 150),
                }
            )

        elif attack_type == "data_exfiltration":
            event.update(
                {
                    "destination_port": rng.choice([443, 8443, 22]),
                    "protocol": "HTTPS",
                    "bytes_in": rng.randint(100, 1500),
                    "bytes_out": rng.randint(500_000, 8_000_000),
                    "country": rng.choice(["AU", "SG"]),
                }
            )
            if i > 0:
                event["latitude"] = rng.uniform(-35, 35)
                event["longitude"] = rng.uniform(110, 150)

        elif attack_type == "ddos":
            event.update(
                {
                    "destination_port": rng.choice([80, 443]),
                    "protocol": rng.choice(["TCP", "UDP"]),
                    "bytes_in": rng.randint(500, 5000),
                    "bytes_out": rng.randint(50, 500),
                }
            )

        events.append(event)

    return events


def _distribute_counts(total: int, buckets: int) -> List[int]:
    """Split a count as evenly as possible across buckets."""
    base, remainder = divmod(total, buckets)
    return [base + (1 if i < remainder else 0) for i in range(buckets)]


def generate_dataset(config: GeneratorConfig | None = None) -> pd.DataFrame:
    """Generate a reproducible 30-day SOC dataset with stable temporal splits."""
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

    start = config.start
    end = start + timedelta(days=config.duration_days)
    total_seconds = (end - start).total_seconds()

    # Use the exact same event-count proportions as the 70/15/15 chronological
    # evaluator, preventing a class-composition artifact at split boundaries.
    split_total = _distribute_counts(config.total_events, 100)
    train_events = int(config.total_events * 0.70)
    val_events = int(config.total_events * 0.15)
    test_events = config.total_events - train_events - val_events
    period_sizes = [train_events, val_events, test_events]

    split_attack_counts = _distribute_counts(attack_count, 3)
    split_normal_counts = [
        period_sizes[i] - split_attack_counts[i] for i in range(3)
    ]

    normal_sources = [_private_ip(rng) for _ in range(max(150, normal_count // 30))]
    normal_profiles = {
        source: (
            rng.gauss(39.5, 3.0),
            rng.gauss(-98.5, 8.0),
            rng.choice(["US", "CA", "GB", "DE"]),
        )
        for source in normal_sources
    }

    events: List[dict] = []

    period_starts = [start]
    period_starts.append(start + timedelta(seconds=total_seconds * 0.70))
    period_starts.append(start + timedelta(seconds=total_seconds * 0.85))
    period_ends = [
        period_starts[1],
        period_starts[2],
        end,
    ]

    # Normal behavior is present throughout all three chronological periods.
    for period_index in range(3):
        period_start = period_starts[period_index]
        period_end = period_ends[period_index]
        period_seconds = max((period_end - period_start).total_seconds(), 1.0)

        for _ in range(split_normal_counts[period_index]):
            offset = rng.uniform(0, period_seconds - 1)
            timestamp = period_start + timedelta(seconds=offset)
            source_ip = rng.choice(normal_sources)
            lat, lon, country = normal_profiles[source_ip]
            events.append(
                _normal_event(
                    rng,
                    timestamp,
                    source_ip,
                    lat + rng.gauss(0, 0.15),
                    lon + rng.gauss(0, 0.15),
                    country,
                )
            )

        # Every chronological period receives every attack family in an even
        # mix. This avoids validation/test drift caused by session ordering.
        for attack_type, type_count in zip(
            ATTACK_TYPES,
            _distribute_counts(split_attack_counts[period_index], len(ATTACK_TYPES)),
        ):
            remaining = type_count
            session_index = 0
            while remaining > 0:
                session_size = min(remaining, rng.randint(20, 50))
                # Leave enough room for the complete burst within the period.
                latest_offset = max(period_seconds - 600, 1.0)
                offset = rng.uniform(0, latest_offset)
                session_start = period_start + timedelta(seconds=offset)

                events.extend(
                    _attack_session(
                        rng,
                        session_start,
                        attack_type,
                        session_size,
                    )
                )
                remaining -= session_size
                session_index += 1

    df = (
        pd.DataFrame(events)
        .sort_values("timestamp")
        .reset_index(drop=True)
    )

    if len(df) != config.total_events:
        raise RuntimeError(
            f"Generated {len(df)} events; expected {config.total_events}"
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
