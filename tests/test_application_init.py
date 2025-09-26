import importlib
import sys
import types
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_PATH = PROJECT_ROOT / "src"
if str(SRC_PATH) not in sys.path:
    sys.path.insert(0, str(SRC_PATH))

class DummyConfig:
    def __init__(self, initial=None):
        base = {
            "kiosk.enabled": False,
            "gui.backend": "console",
            "station.name": "Test Station",
            "app.name": "Argus",
            "app.version": "2.0",
            "usb.mount_point": "/tmp",
            "usb.read_only": True,
            "usb.supported_filesystems": ["vfat"],
        }
        if initial:
            base.update(initial)
        self.store = base

    def get(self, key, default=None):
        return self.store.get(key, default)

    def set(self, key, value):
        self.store[key] = value


class DummyUSBDetector:
    def __init__(self, config):
        self.config = config
        self.on_device_connected = None
        self.on_device_disconnected = None

    def start_monitoring(self):  # pragma: no cover - not exercised
        self.start_called = True

    def stop_monitoring(self):  # pragma: no cover - not exercised
        self.stop_called = True


class DummyScanEngine:
    def __init__(self, config):
        self.config = config
        self.requests = []
        self.stopped = False

    def scan_device(self, device_path, progress_callback=None, completion_callback=None):
        self.requests.append((device_path, progress_callback, completion_callback))

    def stop_scan(self):
        self.stopped = True


class DummyGUIBase:
    def __init__(self, config, scan_engine):
        self.config = config
        self.scan_engine = scan_engine
        self.on_scan_request = None
        self.on_stop_request = None

    def run(self):  # pragma: no cover - not exercised
        pass


class DummyMainWindow(DummyGUIBase):
    pass


class DummyKioskWindow(DummyGUIBase):
    pass


class DummySIEMClient:
    def __init__(self, config):
        self.config = config
        self.events = []
        self.shutdown_called = False

    def send_event(self, *args, **kwargs):
        self.events.append((args, kwargs))

    def shutdown(self):
        self.shutdown_called = True


@pytest.fixture
def application_module(monkeypatch):
    if "core.application" in sys.modules:
        return sys.modules["core.application"]

    import importlib.util

    class FakeContext:
        def device_from_device_file(self, *_args, **_kwargs):
            return {}

    class FakeMonitor:
        def __init__(self, _context):
            pass

        @classmethod
        def from_netlink(cls, context):
            return cls(context)

        def filter_by(self, *_args, **_kwargs):
            pass

    class FakeMonitorObserver:
        def __init__(self, _monitor, callback, name=None, daemon=False):
            self.callback = callback

        def start(self):
            pass

        def stop(self):
            pass

        def join(self, timeout=None):
            pass

    fake_pyudev = types.SimpleNamespace(
        DeviceNotFoundError=Exception,
        Context=lambda: FakeContext(),
        Monitor=FakeMonitor,
        MonitorObserver=FakeMonitorObserver,
    )

    monkeypatch.setitem(sys.modules, "pyudev", fake_pyudev)
    monkeypatch.setitem(
        sys.modules,
        "syslog",
        types.SimpleNamespace(openlog=lambda *args, **kwargs: None, syslog=lambda *args, **kwargs: None, closelog=lambda: None),
    )

    find_spec = importlib.util.find_spec

    def fake_find_spec(name, *args, **kwargs):
        if name == "pyudev":
            return types.SimpleNamespace()
        return find_spec(name, *args, **kwargs)

    monkeypatch.setattr(importlib.util, "find_spec", fake_find_spec)

    return importlib.import_module("core.application")


def test_application_initializes_console_gui(application_module, monkeypatch):
    monkeypatch.setattr(application_module, "Config", lambda _cfg=None: DummyConfig())
    monkeypatch.setattr(application_module, "USBDetector", DummyUSBDetector)
    monkeypatch.setattr(application_module, "ScanEngine", DummyScanEngine)
    monkeypatch.setattr(application_module, "MainWindow", DummyMainWindow)
    monkeypatch.setattr(application_module, "KioskWindow", DummyKioskWindow)
    monkeypatch.setattr(application_module, "SIEMClient", DummySIEMClient)

    app = application_module.ArgusApplication(kiosk_mode=False)
    app.initialize()

    assert isinstance(app.gui, DummyMainWindow)
    assert isinstance(app.usb_detector, DummyUSBDetector)
    assert isinstance(app.scan_engine, DummyScanEngine)
    gui_scan_handler = app.gui.on_scan_request
    usb_connect_handler = app.usb_detector.on_device_connected
    assert gui_scan_handler is not None
    assert usb_connect_handler is not None
    assert getattr(gui_scan_handler, "__self__", None) is app
    assert getattr(gui_scan_handler, "__func__", None) is application_module.ArgusApplication._handle_scan_request
    assert getattr(usb_connect_handler, "__self__", None) is app
    assert getattr(usb_connect_handler, "__func__", None) is application_module.ArgusApplication._handle_usb_connected


def test_application_initializes_kiosk_gui(application_module, monkeypatch):
    monkeypatch.setattr(application_module, "Config", lambda _cfg=None: DummyConfig())
    monkeypatch.setattr(application_module, "USBDetector", DummyUSBDetector)
    monkeypatch.setattr(application_module, "ScanEngine", DummyScanEngine)
    monkeypatch.setattr(application_module, "MainWindow", DummyMainWindow)
    monkeypatch.setattr(application_module, "KioskWindow", DummyKioskWindow)
    monkeypatch.setattr(application_module, "SIEMClient", DummySIEMClient)

    app = application_module.ArgusApplication(kiosk_mode=True)
    app.initialize()

    assert isinstance(app.gui, DummyKioskWindow)
    assert app.config.get("kiosk.enabled") is True
    gui_scan_handler = app.gui.on_scan_request
    usb_connect_handler = app.usb_detector.on_device_connected
    assert gui_scan_handler is not None
    assert usb_connect_handler is not None
    assert getattr(gui_scan_handler, "__self__", None) is app
    assert getattr(gui_scan_handler, "__func__", None) is application_module.ArgusApplication._handle_scan_request
    assert getattr(usb_connect_handler, "__self__", None) is app
    assert getattr(usb_connect_handler, "__func__", None) is application_module.ArgusApplication._handle_usb_connected
