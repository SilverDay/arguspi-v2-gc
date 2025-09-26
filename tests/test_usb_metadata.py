import importlib
import importlib.util
import sys
import types
import time

import pytest


@pytest.fixture(scope="module")
def usb_detector_module():
    if "usb.detector" in sys.modules:
        return sys.modules["usb.detector"]

    class FakeContext:
        def device_from_device_file(self, *_args, **_kwargs):
            return None

        def list_devices(self, *args, **kwargs):
            return []

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

    fake_pyudev = types.ModuleType("pyudev")
    setattr(fake_pyudev, "DeviceNotFoundError", Exception)
    setattr(fake_pyudev, "Context", lambda: FakeContext())
    setattr(fake_pyudev, "Monitor", FakeMonitor)
    setattr(fake_pyudev, "MonitorObserver", FakeMonitorObserver)

    original_find_spec = importlib.util.find_spec

    def fake_find_spec(name, *args, **kwargs):
        if name == "pyudev":
            return types.SimpleNamespace()
        return original_find_spec(name, *args, **kwargs)

    sys.modules["pyudev"] = fake_pyudev  # type: ignore[assignment]

    importlib.util.find_spec = fake_find_spec
    try:
        return importlib.import_module("usb.detector")
    finally:
        importlib.util.find_spec = original_find_spec


def test_usb_device_metadata_classification(usb_detector_module):
    USBDeviceMetadata = usb_detector_module.USBDeviceMetadata

    mass_storage = USBDeviceMetadata(dev_node="1-1", usb_class="08")
    assert mass_storage.is_mass_storage is True
    assert mass_storage.exposes_hid is False

    interface_mass_storage = USBDeviceMetadata(dev_node="1-2", interfaces=["080650"], usb_class="0200")
    assert interface_mass_storage.is_mass_storage is True

    hid_combo = USBDeviceMetadata(dev_node="1-3", interfaces=["030102", "080650"])
    assert hid_combo.is_mass_storage is True
    assert hid_combo.exposes_hid is True

    non_storage = USBDeviceMetadata(dev_node="1-4", interfaces=["030102"])
    assert non_storage.is_mass_storage is False
    assert non_storage.exposes_hid is True


def test_emit_metadata_triggers_callbacks(usb_detector_module):
    USBDeviceMetadata = usb_detector_module.USBDeviceMetadata
    USBDetector = usb_detector_module.USBDetector

    metadata = USBDeviceMetadata(
        dev_node="1-9",
        manufacturer="Acme",
        product="Elite",
        warnings=["Device is not a USB mass-storage class peripheral."],
    )

    detector = object.__new__(USBDetector)
    detector._metadata_seen = {}
    captured = []
    warning_captured = []
    detector.on_device_metadata = captured.append
    detector.on_device_warning = warning_captured.append

    detector._emit_metadata(metadata)

    assert captured == [metadata]
    assert warning_captured == [metadata]
    assert metadata.dev_node in detector._metadata_seen

    detector._emit_metadata(metadata)
    assert captured == [metadata]
    assert warning_captured == [metadata]

    time.sleep(0.6)
    detector._emit_metadata(metadata)
    assert len(captured) == 2
    assert len(warning_captured) == 2


def test_usb_device_metadata_summary_includes_warnings(usb_detector_module):
    USBDeviceMetadata = usb_detector_module.USBDeviceMetadata

    metadata = USBDeviceMetadata(
        dev_node="1-10",
        manufacturer="Acme",
        product="Drive",
        id_vendor="1234",
        id_product="ABCD",
        serial="SN001",
        warnings=["Test warning"],
    )

    summary = metadata.summary()
    assert "Acme Drive" in summary
    assert "[1234:ABCD]" in summary
    assert "serial=SN001" in summary
    assert "warnings=Test warning" in summary


def test_usb_device_info_str_prefers_metadata_name(usb_detector_module):
    USBDeviceMetadata = usb_detector_module.USBDeviceMetadata
    USBDeviceInfo = usb_detector_module.USBDeviceInfo

    metadata = USBDeviceMetadata(dev_node="1-11", manufacturer="Vendor", product="Flash")
    info = USBDeviceInfo(
        device_path="/dev/sdb1",
        filesystem="vfat",
        size=1024,
        metadata=metadata,
    )

    rendered = str(info)
    assert "Vendor Flash" in rendered
    assert "/dev/sdb1" in rendered
