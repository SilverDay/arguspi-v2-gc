"""Policy-based USB device rule evaluation."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional, Callable, cast

import json
import logging
import time


logger = logging.getLogger(__name__)


@dataclass
class RuleMatch:
    rule_type: str
    message: str
    reason: Optional[str]
    severity: str = "warning"


class USBDeviceRuleManager:
    """Applies local and remotely-synchronised rules to USB metadata."""

    def __init__(
        self,
        config: Any,
        *,
        clock: Callable[[], float] = time.time,
        fetcher: Optional[Callable[[str, bool], Optional[str]]] = None,
    ) -> None:
        settings = config.get("security.rules", {}) if config else {}
        self._local_rules = settings.get("local", {})
        self._sync_settings = settings.get("sync", {})
        self._clock = clock
        self._fetcher = fetcher or self._default_fetcher

        self._sync_enabled = bool(self._sync_settings.get("enabled", False))
        self._sync_url = self._sync_settings.get("url", "")
        self._sync_interval = max(1, int(self._sync_settings.get("interval_hours", 12) or 12)) * 3600
        self._verify_tls = bool(self._sync_settings.get("verify_tls", True))
        cache_path = self._sync_settings.get("cache_path", "config/rules_cache.json")
        self._cache_path = Path(cache_path)
        self._cached_remote_rules: Dict[str, Any] = {}
        self._last_sync: float = 0.0

        if self._sync_enabled:
            self._load_cached_rules()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def evaluate(self, metadata: Any) -> List[RuleMatch]:
        self._refresh_remote_rules()
        matches: List[RuleMatch] = []
        matches.extend(self._check_blocked_devices(metadata))
        matches.extend(self._check_serial_prefixes(metadata))
        matches.extend(self._check_interfaces(metadata))
        return matches

    # ------------------------------------------------------------------
    # Rule evaluation helpers
    # ------------------------------------------------------------------
    def _check_blocked_devices(self, metadata: Any) -> List[RuleMatch]:
        matches: List[RuleMatch] = []
        vid = (getattr(metadata, "id_vendor", None) or "").lower()
        pid = (getattr(metadata, "id_product", None) or "").lower()
        local_rules = self._local_rules.get("blocked_devices", [])
        remote_rules = self._cached_remote_rules.get("blocked_devices", [])
        for rule in self._iter_rules(local_rules, remote_rules):
            rule_vid = str(rule.get("vid", "")).lower()
            rule_pid = str(rule.get("pid", "")).lower()
            if rule_vid and vid != rule_vid:
                continue
            if rule_pid and pid != rule_pid:
                continue
            reason = rule.get("reason")
            message = f"Device VID:PID {vid or '?'}:{pid or '?'} matches blocked list"
            matches.append(RuleMatch("blocked_device", message, reason))
        return matches

    def _check_serial_prefixes(self, metadata: Any) -> List[RuleMatch]:
        matches: List[RuleMatch] = []
        serial = getattr(metadata, "serial", None) or ""
        if not serial:
            return matches

        local_rules = self._local_rules.get("blocked_serial_prefixes", [])
        remote_rules = self._cached_remote_rules.get("blocked_serial_prefixes", [])
        serial_lower = serial.lower()
        for rule in self._iter_rules(local_rules, remote_rules):
            prefix = str(rule.get("prefix", "")).lower()
            if not prefix:
                continue
            if serial_lower.startswith(prefix):
                reason = rule.get("reason")
                message = f"Serial '{serial}' matches blocked prefix '{prefix}'"
                matches.append(RuleMatch("blocked_serial", message, reason))
        return matches

    def _check_interfaces(self, metadata: Any) -> List[RuleMatch]:
        matches: List[RuleMatch] = []
        interfaces = getattr(metadata, "interfaces", None) or []
        if not interfaces:
            return matches

        local_rules = self._local_rules.get("blocked_interfaces", [])
        remote_rules = self._cached_remote_rules.get("blocked_interfaces", [])
        for rule in self._iter_rules(local_rules, remote_rules):
            cls = str(rule.get("class", "")).lower()
            subclass = str(rule.get("subclass", "")).lower()
            protocol = str(rule.get("protocol", "")).lower()
            for interface in interfaces:
                iface = str(interface).lower()
                if cls and not iface.startswith(cls):
                    continue
                if subclass and (len(iface) < 4 or iface[2:4] != subclass):
                    continue
                if protocol and (len(iface) < 6 or iface[4:6] != protocol):
                    continue
                reason = rule.get("reason")
                message = f"Interface {iface} matches blocked class rule"
                matches.append(RuleMatch("blocked_interface", message, reason))
                break
        return matches

    # ------------------------------------------------------------------
    # Rule combination/sync helpers
    # ------------------------------------------------------------------
    def _iter_rules(self, *groups: Iterable[Iterable[Dict[str, Any]]]) -> Iterator[Dict[str, Any]]:
        for group in groups:
            for rule in group or []:
                if isinstance(rule, dict):
                    yield cast(Dict[str, Any], rule)

    def _refresh_remote_rules(self) -> None:
        if not self._sync_enabled or not self._sync_url:
            return
        now = self._clock()
        if now - self._last_sync < self._sync_interval:
            return
        try:
            payload = self._fetcher(self._sync_url, self._verify_tls)
        except Exception as exc:  # pragma: no cover - network errors
            logger.debug("Rule sync fetch failed: %s", exc)
            return
        if payload is None:
            return
        try:
            data = json.loads(payload)
        except json.JSONDecodeError as exc:
            logger.warning("Rule sync payload was not valid JSON: %s", exc)
            return
        if not isinstance(data, dict):
            logger.warning("Rule sync payload ignored because it was not an object")
            return
        self._cached_remote_rules = data
        self._last_sync = now
        self._save_cached_rules()
        logger.info("Updated remote USB device rules from %s", self._sync_url)

    def _load_cached_rules(self) -> None:
        if not self._cache_path.exists():
            return
        try:
            cached = json.loads(self._cache_path.read_text(encoding="utf-8"))
            if isinstance(cached, dict):
                self._cached_remote_rules = cached
        except Exception as exc:  # pragma: no cover - IO issues
            logger.debug("Failed to load cached rules: %s", exc)

    def _save_cached_rules(self) -> None:
        try:
            self._cache_path.parent.mkdir(parents=True, exist_ok=True)
            self._cache_path.write_text(json.dumps(self._cached_remote_rules, indent=2, sort_keys=True), encoding="utf-8")
        except Exception as exc:  # pragma: no cover - IO issues
            logger.debug("Failed to persist cached rules: %s", exc)

    def _default_fetcher(self, url: str, verify: bool) -> Optional[str]:
        try:
            import requests  # type: ignore
        except ImportError:  # pragma: no cover - optional dependency
            logger.warning("USB rule sync enabled but 'requests' is not installed")
            return None
        response = requests.get(url, timeout=10, verify=verify)
        if response.status_code != 200:
            logger.warning("USB rule sync request to %s returned %s", url, response.status_code)
            return None
        return response.text
