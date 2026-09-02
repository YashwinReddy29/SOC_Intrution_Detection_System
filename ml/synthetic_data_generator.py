"""Generate reproducible, session-based synthetic SOC events.

The generator intentionally creates temporal behavior so rolling features such as
port diversity and failed-login rate contain meaningful attack signals.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import List
import ipaddress
import random

import numpy as np
import pandas as pd


@dataclass(frozen=True)
class GeneratorConfig:
    total_events: int = 10_000
    attack_fraction: float = 0.20
    seed: int = 42
    start: datetime = datetime(2026, 1, 1, tzinfo=timezone.utc)


NORMAL_PROTOCOLS = ["TCP", "UDP", "ICMP", "HTTPS"]
ATTACK_TYPES = ["brute_force", "port_scan", "data_exfiltration", "ddos", "credential_stuffing"]


def _private_ip(rng: random.Random) -> str:
    return f"10.{rng.randint(0, 30)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"


def _normal_event(rng: random.Random, timestamp: datetime, source_ip: str) -> dict:
    bytes_in = int(np.random.default_rng(rng.randint(0, 2**31 - 1)).lognormal(8.0, 0.8))
    bytes_out = int(np.random.default_rng(rng.randint(0, 2**31 - 1)).lognormal(7.5, 0.7))
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
        "latitude": rng.uniform(35, 55),
        "longitude": rng.uniform(-125, -70),
        "label": 0,
        "attack_type": "normal",
    }


def _attack_session(rng: random.Random, start: datetime, attack_type: str, count: int) -> List[dict]:
    source_ip = _private_ip(rng)
    events = []

    for i in range(count):
        ts = start + timedelta(seconds=i * rng.uniform(0.2, 4.0))
        event = _normal_event(rng, ts, source_ip)
        event["label"] = 1
        event["attack_type"] = attack_type

        if attack_type == "brute_force":
            event["destination_port"] = 22
            event["protocol"] = "TCP"
            event["failed_logins"] = rng.randint(1, 4)
            event["bytes_in"] = rng.randint(150, 700)
            event["bytes_out"] = rng.randint(50, 400)

        elif attack_type == "credential_stuffing":
            event["destination_port"] = 443
            event["protocol"] = "HTTPS"
            event["failed_logins"] = rng.randint(1, 3)
            event["bytes_in"] = rng.randint(300, 1200)
            event["bytes_out"] = rng.randint(100, 600)

        elif attack_type == "port_scan":
            event["destination_port"] = rng.choice(
                list(range(1, 1024)) + [1433, 1521, 3306, 3389, 5432, 6379, 8080]
            )
            event["protocol"] = "TCP"
            event["bytes_in"] = rng.randint(40, 150)
            event["bytes_out"] = rng.randint(40, 150)

        elif attack_type == "data_exfiltration":
            event["destination_port"] = rng.choice([443, 8443, 22])
            event["protocol"] = "HTTPS"
            event["bytes_in"] = rng.randint(100, 1500)
            event["bytes_out"] = rng.randint(500_000, 8_000_000)

        elif attack_type == "ddos":
            event["destination_port"] = rng.choice([80, 443])
            event["protocol"] = rng.choice(["TCP", "UDP"])
            event["bytes_in"] = rng.randint(500, 5000)
            event["bytes_out"] = rng.randint(50, 500)

        events.append(event)

    return events


def generate_dataset(config: GeneratorConfig | None = None) -> pd.DataFrame:
    """Generate a balanced-by-design temporal dataset with reproducible labels."""
    config = config or GeneratorConfig()
    if config.total_events < 100:
        raise ValueError("total_events must be at least 100")
    if not 0 < config.attack_fraction < 1:
        raise ValueError("attack_fraction must be between 0 and 1")

    rng = random.Random(config.seed)
    np.random.seed(config.seed)

    attack_count = int(round(config.total_events * config.attack_fraction))
    normal_count = config.total_events - attack_count

    normal_sources = [_private_ip(rng) for _ in range(max(100, normal_count // 20))]
    events = []

    for i in range(normal_count):
        timestamp = config.start + timedelta(seconds=i * 30)
        events.append(_normal_event(rng, timestamp, rng.choice(normal_sources)))

    remaining = attack_count
    attack_index = 0
    while remaining > 0:
        attack_type = ATTACK_TYPES[attack_index % len(ATTACK_TYPES)]
        session_size = min(remaining, rng.randint(15, 80))
        session_start = config.start + timedelta(days=22, minutes=attack_index * 5)
        events.extend(_attack_session(rng, session_start, attack_type, session_size))
        remaining -= session_size
        attack_index += 1

    df = pd.DataFrame(events).sort_values("timestamp").reset_index(drop=True)
    return df


def save_dataset(df: pd.DataFrame, path: str) -> None:
    """Persist generated events as CSV."""
    df = df.copy()
    df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True).astype(str)
    df.to_csv(path, index=False)


if __name__ == "__main__":
    df = generate_dataset()
    save_dataset(df, "ml/data/soc_events.csv")
    print(df["label"].value_counts().to_dict())
    print(df["attack_type"].value_counts().to_dict())
