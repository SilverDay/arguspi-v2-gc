"""Device quarantine utilities for ArgusPI."""
from __future__ import annotations

from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Dict, Optional, Callable

import json
import logging
import shutil
import time
import uuid
import hashlib


logger = logging.getLogger(__name__)


@dataclass
class QuarantineRecord:
    """Describes a quarantined file and its associated metadata."""

    record_id: str
    original_path: str
    quarantined_path: str
    created_at: float
    threat_name: str
    engine: str
    checksum_sha256: Optional[str]
    metadata: Optional[Dict[str, Any]]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class QuarantineManager:
    """Handles movement of suspect files into a quarantine area."""

    def __init__(
        self,
        config: Any,
        *,
        clock: Callable[[], float] = time.time,
        uuid_factory: Callable[[], uuid.UUID] = uuid.uuid4,
    ) -> None:
        settings = config.get("security.quarantine", {}) if config else {}
        self.enabled: bool = bool(settings.get("enabled", False))
        self.root: Path = Path(settings.get("path", "quarantine"))
        self.report_format: str = str(settings.get("report_format", "json")).lower()
        self.max_records: int = int(settings.get("max_records", 500) or 0)
        self._clock = clock
        self._uuid_factory = uuid_factory

        try:
            self.root.mkdir(parents=True, exist_ok=True)
        except Exception as exc:  # pragma: no cover - filesystem issues
            logger.error("Unable to initialize quarantine directory %s: %s", self.root, exc)
            self.enabled = False

    def quarantine(
        self,
        file_path: str,
        *,
        threat_name: str,
        engine: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Optional[QuarantineRecord]:
        if not self.enabled:
            return None

        source = Path(file_path)
        if not source.is_file():
            logger.debug("Quarantine skipped; file missing: %s", source)
            return None

        timestamp = self._clock()
        record_id = f"{int(timestamp)}-{self._uuid_factory()}"
        target_dir = self.root / record_id
        try:
            target_dir.mkdir(parents=True, exist_ok=False)
        except FileExistsError:  # pragma: no cover - extremely unlikely
            logger.debug("Quarantine record already exists for %s", record_id)
        except Exception as exc:  # pragma: no cover - filesystem issues
            logger.error("Failed to create quarantine record directory %s: %s", target_dir, exc)
            return None

        target_path = target_dir / source.name
        checksum = self._copy_with_hash(source, target_path)

        record = QuarantineRecord(
            record_id=record_id,
            original_path=str(source),
            quarantined_path=str(target_path),
            created_at=timestamp,
            threat_name=threat_name,
            engine=engine,
            checksum_sha256=checksum,
            metadata=metadata,
        )

        try:
            self._write_report(target_dir, record)
        except Exception as exc:  # pragma: no cover - logging only
            logger.warning("Failed to write quarantine report for %s: %s", record_id, exc)

        self._enforce_limit()
        logger.info("Quarantined file %s -> %s", source, target_path)
        return record

    def _copy_with_hash(self, source: Path, target: Path) -> Optional[str]:
        hasher = hashlib.sha256()
        try:
            with source.open("rb") as src, target.open("wb") as dst:
                while True:
                    chunk = src.read(1024 * 1024)
                    if not chunk:
                        break
                    dst.write(chunk)
                    hasher.update(chunk)
            shutil.copystat(source, target, follow_symlinks=False)
            return hasher.hexdigest()
        except Exception as exc:
            logger.error("Failed to copy %s to quarantine: %s", source, exc)
            try:
                target.unlink(missing_ok=True)
            except Exception:  # pragma: no cover - best effort cleanup
                pass
            return None

    def _write_report(self, target_dir: Path, record: QuarantineRecord) -> None:
        if self.report_format == "json":
            (target_dir / "report.json").write_text(
                json.dumps(record.to_dict(), indent=2, sort_keys=True),
                encoding="utf-8",
            )
        else:  # future formats could be added here
            (target_dir / "report.txt").write_text(str(record.to_dict()), encoding="utf-8")

    def _enforce_limit(self) -> None:
        if self.max_records <= 0:
            return
        try:
            records = sorted(
                (p for p in self.root.iterdir() if p.is_dir()),
                key=lambda path: path.stat().st_mtime,
            )
        except FileNotFoundError:  # pragma: no cover - root deleted externally
            return
        except Exception as exc:  # pragma: no cover - filesystem issues
            logger.debug("Unable to enforce quarantine limit: %s", exc)
            return

        excess = max(0, len(records) - self.max_records)
        for obsolete in records[:excess]:
            try:
                shutil.rmtree(obsolete)
            except Exception as exc:  # pragma: no cover - logging only
                logger.debug("Failed to prune quarantine record %s: %s", obsolete, exc)
