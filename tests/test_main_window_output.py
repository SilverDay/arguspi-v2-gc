import io
import sys
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_PATH = PROJECT_ROOT / "src"
if str(SRC_PATH) not in sys.path:
    sys.path.insert(0, str(SRC_PATH))

from gui.main_window import MainWindow
from scanner.engine import ScanResult


class _StubConfig:
    _defaults = {
        "station.name": "Test Station",
        "station.location": "",
        "app.name": "ArgusPI v2",
        "app.version": "2.0.0",
    }

    def get(self, key: str, default: Any = None) -> Any:
        return self._defaults.get(key, default)


class _StubScanEngine:  # pragma: no cover - only used for interface compatibility
    pass


class MainWindowOutputTests(unittest.TestCase):
    def setUp(self) -> None:
        self.window = MainWindow(_StubConfig(), _StubScanEngine())

    def test_on_scan_complete_renders_clean_output(self) -> None:
        scan_result = ScanResult()
        scan_result.scanned_files = 5
        scan_result.infected_files = 1
        scan_result.scan_time = 2.5
        scan_result.completed = True
        scan_result.threats = [
            {"file": "autorun.inf", "threat": "Suspicious filename", "engine": "builtin"}
        ]
        scan_result.device_path = "/dev/sdb1"

        captured = io.StringIO()

        original_input = __builtins__["input"]  # type: ignore[index]
        __builtins__["input"] = lambda prompt="": ""  # type: ignore[assignment]
        try:
            with redirect_stdout(captured):
                self.window.on_scan_complete(scan_result)
        finally:
            __builtins__["input"] = original_input  # type: ignore[assignment]

        output = captured.getvalue()
        self.assertIn("\n\nScan completed!", output)
        self.assertIn("Threats detected:", output)
        self.assertIn("Device path: /dev/sdb1", output)
        self.assertIn("Suspicious filename", output)
        self.assertNotIn("\\nScan completed!", output)

    def test_scan_result_device_path_persists(self) -> None:
        scan_result = ScanResult()
        scan_result.device_path = "/media/test"
        scan_result.completed = True
        self.assertEqual(scan_result.device_path, "/media/test")


if __name__ == "__main__":
    unittest.main()