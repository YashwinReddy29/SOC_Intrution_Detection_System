"""Behavioral feature extraction for SOC events.

Features are computed from rolling source/global state so they represent behavior
across a time window rather than isolated log-row values.
"""

from __future__ import annotations

from collections import Counter, defaultdict, deque
from math import log2, radians, sin, cos, asin, sqrt
from typing import Iterable

import numpy as np
import pandas as pd


FEATURE_COLUMNS = [
    "source_entropy",
    "port_diversity",
    "failed_login_rate",
    "bytes_in_out_ratio",
    "time_of_day_zscore",
    "protocol_count",
    "geographic_distance",
]


class RollingFeatureExtractor:
    """Extract seven behavioral features using a configurable rolling window."""

    def __init__(self, window_seconds: int = 300):
        if window_seconds <= 0:
            raise ValueError("window_seconds must be positive")

        self.window_seconds = window_seconds
        self.source_events = defaultdict(deque)
        self.global_events = deque()
        self.last_location = {}
        self.time_mean = 12.0
        self.time_std = 4.0

    @staticmethod
    def _entropy(values: Iterable[str]) -> float:
        values = list(values)
        if not values:
            return 0.0
        counts = Counter(values)
        total = len(values)
        return float(
            -sum((n / total) * log2(n / total) for n in counts.values())
        )

    @staticmethod
    def _distance(lat1, lon1, lat2, lon2) -> float:
        if any(pd.isna(v) for v in [lat1, lon1, lat2, lon2]):
            return 0.0
        lat1, lon1, lat2, lon2 = map(radians, [lat1, lon1, lat2, lon2])
        dlat = lat2 - lat1
        dlon = lon2 - lon1
        a = sin(dlat / 2) ** 2 + cos(lat1) * cos(lat2) * sin(dlon / 2) ** 2
        return float(6371.0 * 2 * asin(sqrt(min(1.0, a))))

    def fit_time_statistics(self, timestamps: pd.Series) -> None:
        parsed = pd.to_datetime(timestamps, utc=True)
        hours = parsed.dt.hour + parsed.dt.minute / 60.0
        self.time_mean = float(hours.mean())
        self.time_std = float(hours.std(ddof=0)) or 1.0

    def _purge(self, timestamp: pd.Timestamp) -> None:
        """Remove rolling-window entries older than the current event."""
        cutoff = timestamp.timestamp() - self.window_seconds

        while self.global_events and self.global_events[0][0] < cutoff:
            self.global_events.popleft()

        for source, events in list(self.source_events.items()):
            # Timestamps are stored as Unix floats for efficient comparison.
            while events and events[0][0] < cutoff:
                events.popleft()
            if not events:
                del self.source_events[source]

    def transform_event(self, event: dict) -> dict:
        timestamp = pd.to_datetime(event["timestamp"], utc=True)
        if not isinstance(timestamp, pd.Timestamp):
            timestamp = pd.Timestamp(timestamp)

        source = str(event["source_ip"])
        self._purge(timestamp)

        source_history = self.source_events[source]
        global_sources = [item[1]["source_ip"] for item in self.global_events]

        # Store timestamps consistently as Unix floats in both rolling queues.
        event_timestamp = timestamp.timestamp()
        source_history.append((event_timestamp, event))
        self.global_events.append((event_timestamp, event))

        source_events = [item[1] for item in source_history]
        total_source = max(len(source_events), 1)

        ports = {e["destination_port"] for e in source_events}
        protocols = {e["protocol"] for e in source_events}
        failed = sum(int(e.get("failed_logins", 0)) for e in source_events)
        auth_events = sum(
            1 for e in source_events if int(e.get("failed_logins", 0)) > 0
        )
        bytes_in = sum(max(0, int(e.get("bytes_in", 0))) for e in source_events)
        bytes_out = sum(max(0, int(e.get("bytes_out", 0))) for e in source_events)

        hour = timestamp.hour + timestamp.minute / 60.0
        time_z = abs((hour - self.time_mean) / self.time_std)

        previous = self.last_location.get(source)
        distance = 0.0
        if previous:
            distance = self._distance(
                previous[0],
                previous[1],
                event.get("latitude"),
                event.get("longitude"),
            )
        self.last_location[source] = (
            event.get("latitude"),
            event.get("longitude"),
        )

        # Normalize source entropy by the maximum entropy in the current window.
        entropy = self._entropy(global_sources + [source])
        unique_sources = max(len(set(global_sources + [source])), 1)
        max_entropy = max(log2(unique_sources), 1.0)

        return {
            "source_entropy": entropy / max_entropy,
            "port_diversity": len(ports) / total_source,
            "failed_login_rate": failed / max(auth_events, 1),
            "bytes_in_out_ratio": np.log1p(bytes_out) - np.log1p(bytes_in),
            "time_of_day_zscore": time_z,
            "protocol_count": float(len(protocols)),
            "geographic_distance": distance,
        }

    def transform(self, df: pd.DataFrame, reset: bool = True) -> pd.DataFrame:
        if reset:
            self.source_events.clear()
            self.global_events.clear()
            self.last_location.clear()

        frame = df.copy()
        frame["timestamp"] = pd.to_datetime(frame["timestamp"], utc=True)
        frame = frame.sort_values("timestamp").reset_index(drop=True)

        features = [
            self.transform_event(row.to_dict())
            for _, row in frame.iterrows()
        ]
        return pd.DataFrame(features, columns=FEATURE_COLUMNS)
