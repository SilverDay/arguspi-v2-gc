# Copilot Instructions for ArgusPI v2 GC

## Quick overview

- ArgusPI v2 is a USB malware scanning appliance: `main.py` parses CLI flags, configures logging, and instantiates `core/application.ArgusApplication`.
- `ArgusApplication` wires together configuration, USB detection, scanning engines, GUI front ends, and SIEM forwarding; callbacks (`on_scan_request`, `on_usb_connected`, etc.) are the primary integration points.
- YAML configuration under `config/default.yaml` drives nearly every subsystem; environment variables prefixed with `ARGUS_` override individual keys.

## Key modules & patterns

- `config/manager.Config` handles YAML load/save plus env overrides; use `Config.set` before saving to persist nested values.
- `config/terminal_editor.TerminalConfigEditor` provides the interactive TUI (launched via `python main.py --config-editor`). It auto-offers choice menus for booleans, logging levels, GUI backends, SIEM protocol/format, etc.—mirror that pattern when adding new enumerated settings.
- `usb/detector.USBDetector` relies on `pyudev` monitors and `lsblk`; when running on non-Linux systems (e.g., tests on Windows), stub `pyudev`, `fcntl`, and related calls.
- `scanner/engine.ScanEngine` orchestrates ClamAV (`pyclamd` or `clamdscan`) and optional VirusTotal lookups. It keeps timezone-aware counters (`datetime.now(timezone.utc)`) for daily API limits—follow that convention for date math.
- GUI surfaces (`gui/main_window.py`, `gui/kiosk_window.py`, `gui/qt_window.py`) expose identical callbacks; they don’t own scanning logic, so new UI code should call into `ArgusApplication` handlers rather than touching engines directly.
- Logging setup lives in `argus_logging/logger.py`; it reads the same YAML config, uses rotating file handlers, and prefers `colorlog` when available.

## External deps & integration

- ClamAV is expected to be available either through the Python client or the `clamdscan` CLI; keep CLI arguments deduplicated as shown in `_clamdscan_extra_args` to avoid duplicates when merging defaults with config.
- VirusTotal integration is optional; guard code paths on both `requests` import success and the configured API key.
- SIEM traffic is emitted via `siem.SIEMClient` which supports syslog, HTTP, and TCP; ensure new event types respect the offline cache (`_cache_offline_message`, `_flush_offline_cache`).

## Development workflow

- Activate the virtualenv (`.venv`) before running commands. Primary test command: `python -m pytest` (repository already uses this in CI/local scripts).
- Tests live in `tests/` and often monkeypatch heavy dependencies. For example, `tests/test_application_init.py` injects fake `pyudev` and `syslog`; replicate that approach for new components that depend on OS-only libraries.
- When adding CLIs or services, document them in `README.md` and ensure they’re discoverable from `main.py --help`.

## Conventions & gotchas

- Many modules assume POSIX paths (e.g., `/proc/mounts`, `/dev/*`); provide fallbacks or guards when adding new functionality so Windows-based tests keep passing.
- Stick to dependency-injection via constructor parameters or monkeypatching for global services—`ArgusApplication` swaps implementations during tests, so new components should remain swappable via attributes.
- Preserve the current logging and callback wiring when extending GUI or detector logic; tests assert that handlers remain bound to `ArgusApplication` methods.
- Reuse helper utilities (`TerminalConfigEditor.parse_any_value`, `ScanEngine.coerce_value` patterns) when interpreting user input to keep behaviour consistent between UI layers.
