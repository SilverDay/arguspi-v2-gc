"""USB device reputation tracking."""
from __future__ import annotations

from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Dict, Optional, Callable

import json
import logging
import sqlite3
import threading
import time


logger = logging.getLogger(__name__)


@dataclass
class ReputationRecord:
    """Summarises stored reputation details for a USB device."""

    device_key: str
    first_seen: float
    last_seen: float
    observation_count: int
    warning_count: int
    status: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class DeviceReputationStore:
    """Persists observations of USB devices across sessions."""

    def __init__(
        self,
        config: Any,
        *,
        clock: Callable[[], float] = time.time,
    ) -> None:
        settings = config.get("security.reputation", {}) if config else {}
        self.enabled: bool = bool(settings.get("enabled", False))
        db_path = settings.get("database_path", "data/device_reputation.sqlite")
        self.db_path = Path(db_path)
        self._clock = clock
        self._lock = threading.Lock()
        self._conn: Optional[sqlite3.Connection] = None

        if not self.enabled:
            return

        try:
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
            self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS devices (
                    device_key TEXT PRIMARY KEY,
                    first_seen REAL NOT NULL,
                    last_seen REAL NOT NULL,
                    observation_count INTEGER NOT NULL,
                    warning_count INTEGER NOT NULL,
                    metadata_snapshot TEXT
                )
                """
            )
            self._conn.commit()
        except Exception as exc:  # pragma: no cover - database access issues
            logger.error("Failed to initialise reputation database at %s: %s", self.db_path, exc)
            self.enabled = False
            if self._conn is not None:
                self._conn.close()
                self._conn = None

    def close(self) -> None:
        if self._conn is not None:
            self._conn.close()
            self._conn = None

    def record_observation(self, metadata: Any) -> Optional[ReputationRecord]:
        if not self.enabled or self._conn is None:
            return None

        device_key = self._device_key(metadata)
        if not device_key:
            logger.debug("Skipping reputation update; insufficient identifiers for %s", metadata)
            return None

        timestamp = self._clock()
        warning_increment = len(getattr(metadata, "warnings", []) or [])
        metadata_json = self._metadata_snapshot(metadata)

        with self._lock:
            cur = self._conn.cursor()
            cur.execute(
                "SELECT first_seen, last_seen, observation_count, warning_count FROM devices WHERE device_key=?",
                (device_key,),
            )
            row = cur.fetchone()
            if row is None:
                first_seen = timestamp
                observation_count = 1
                warning_count = warning_increment
                status = "first_seen"
                cur.execute(
                    "INSERT INTO devices (device_key, first_seen, last_seen, observation_count, warning_count, metadata_snapshot)"
                    " VALUES (?, ?, ?, ?, ?, ?)",
                    (device_key, first_seen, timestamp, observation_count, warning_count, metadata_json),
                )
            else:
                first_seen, _last_seen, observation_count, prior_warnings = row
                observation_count += 1
                warning_count = prior_warnings + warning_increment
                status = "repeat"
                if warning_count > 0:
                    status = "flagged"
                cur.execute(
                    "UPDATE devices SET last_seen=?, observation_count=?, warning_count=?, metadata_snapshot=? WHERE device_key=?",
                    (timestamp, observation_count, warning_count, metadata_json, device_key),
                )
            self._conn.commit()

        return ReputationRecord(
            device_key=device_key,
            first_seen=first_seen,
            last_seen=timestamp,
            observation_count=observation_count,
            warning_count=warning_count,
            status=status,
        )

    def _device_key(self, metadata: Any) -> str:
        components = [
            getattr(metadata, "id_vendor", None) or getattr(metadata, "vendor", ""),
            getattr(metadata, "id_product", None) or getattr(metadata, "product", ""),
            getattr(metadata, "serial", None) or getattr(metadata, "dev_node", ""),
        ]
        key = "|".join(component.strip() for component in components if component)
        return key

    def _metadata_snapshot(self, metadata: Any) -> str:
        snapshot = {
            "vendor": getattr(metadata, "vendor", None),
            "product": getattr(metadata, "product", None),
            "serial": getattr(metadata, "serial", None),
            "id_vendor": getattr(metadata, "id_vendor", None),
            "id_product": getattr(metadata, "id_product", None),
            "dev_node": getattr(metadata, "dev_node", None),
            "warnings": list(getattr(metadata, "warnings", []) or []),
        }
        return json.dumps(snapshot, sort_keys=True)
