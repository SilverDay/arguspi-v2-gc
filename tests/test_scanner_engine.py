import sys
from pathlib import Path
from types import SimpleNamespace

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_PATH = PROJECT_ROOT / "src"
if str(SRC_PATH) not in sys.path:
    sys.path.insert(0, str(SRC_PATH))

import scanner.engine as engine_module
from scanner.engine import ScanEngine


class DummyConfig:
    def __init__(self, data=None):
        self.data = data or {}

    def get(self, key, default=None):
        return self.data.get(key, default)

    def set(self, key, value):  # pragma: no cover - not used but keeps API parity
        self.data[key] = value


def _patch_clamdscan(monkeypatch, path="/usr/bin/clamdscan"):
    def fake_which(candidate):
        if candidate == "clamdscan":
            return path
        return None

    monkeypatch.setattr(engine_module.shutil, "which", fake_which)


def test_scan_engine_prefers_cli(monkeypatch):
    config = DummyConfig(
        {
            "scanner.engines.clamav.enabled": True,
            "scanner.engines.clamav.prefer_cli": True,
            "scanner.engines.clamav.cli_args": ["--foo"],
            "scanner.engines.clamav.cli_path": "clamdscan",
        }
    )

    _patch_clamdscan(monkeypatch)

    engine = ScanEngine(config)

    assert engine._clamdscan_path == "/usr/bin/clamdscan"
    assert engine._clamav_client is None
    assert engine._clamav_enabled is True
    assert set(["--fdpass", "--infected", "--foo"]).issubset(set(engine._clamdscan_extra_args))


def test_scan_engine_clamdscan_detection(monkeypatch):
    config = DummyConfig({"scanner.engines.clamav.enabled": True})

    monkeypatch.setattr(engine_module, "pyclamd", None, raising=False)
    monkeypatch.setattr(engine_module, "pyclamd_import_error", ImportError("missing"), raising=False)
    _patch_clamdscan(monkeypatch)

    engine = ScanEngine(config)
    engine._clamav_enabled = True  # ensure CLI path stays active

    file_path = "/tmp/testfile"

    def fake_run(cmd, stdout, stderr, text, check):
        return SimpleNamespace(
            stdout=f"{file_path}: Eicar-Test-Signature FOUND\n",
            stderr="",
            returncode=1,
        )

    monkeypatch.setattr(engine_module.subprocess, "run", fake_run)

    engine._scan_with_clamdscan(file_path)

    assert engine.current_scan.clamav_files_scanned == 1
    assert engine.current_scan.infected_files == 1
    assert engine.current_scan.threats[0]["threat"] == "Eicar-Test-Signature"


def test_scan_engine_cli_missing_binary(monkeypatch):
    config = DummyConfig({
        "scanner.engines.clamav.enabled": True,
        "scanner.engines.clamav.prefer_cli": True,
    })

    monkeypatch.setattr(engine_module, "pyclamd", None, raising=False)
    monkeypatch.setattr(engine_module, "pyclamd_import_error", ImportError("missing"), raising=False)
    monkeypatch.setattr(engine_module.shutil, "which", lambda *_args, **_kwargs: None)

    engine = ScanEngine(config)

    assert engine._clamav_enabled is False
    assert engine._clamdscan_path is None


def test_record_threat_invokes_callback_and_tracks_quarantine(monkeypatch):
    config = DummyConfig()
    engine = ScanEngine(config)

    captured = {}

    def fake_callback(info):
        captured.update(info)
        scan_result = info.get('scan_result')
        if hasattr(scan_result, 'add_quarantined_file'):
            scan_result.add_quarantined_file({'record_id': 'abc', 'file': info['file']})

    engine.on_threat_detected = fake_callback
    engine._record_threat('/tmp/eicar.txt', 'EICAR-Test-Signature', 'builtin')

    assert captured['file'] == '/tmp/eicar.txt'
    assert captured['threat'] == 'EICAR-Test-Signature'
    assert captured['engine'] == 'builtin'
    assert engine.current_scan.infected_files == 1
    assert engine.current_scan.quarantined_files[0]['record_id'] == 'abc'
