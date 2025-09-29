import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_PATH = PROJECT_ROOT / "src"
if str(SRC_PATH) not in sys.path:
    sys.path.insert(0, str(SRC_PATH))

from config.manager import Config


def test_config_env_override(monkeypatch, tmp_path):
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        """
foo:
  bar: 5
  flag: false
        """.strip()
    )

    cfg = Config(config_path)
    assert cfg.get("foo.bar") == 5
    assert cfg.get("foo.flag") is False

    monkeypatch.setenv("ARGUS_FOO_BAR", "7")
    monkeypatch.setenv("ARGUS_FOO_FLAG", "true")

    assert cfg.get("foo.bar") == 7
    assert cfg.get("foo.flag") is True


def test_config_env_override_double_underscore(monkeypatch, tmp_path):
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        """
foo:
  bar: kiosk
        """.strip()
    )

    cfg = Config(config_path)
    assert cfg.get("foo.bar") == "kiosk"

    monkeypatch.setenv("ARGUS_FOO__BAR", "qt")
    assert cfg.get("foo.bar") == "qt"


def test_get_with_override_reports_source(monkeypatch, tmp_path):
    config_path = tmp_path / "config.yaml"
    config_path.write_text("foo: {bar: console}\n")

    cfg = Config(config_path)
    value, overridden = cfg.get_with_override("foo.bar")
    assert value == "console"
    assert overridden is False

    monkeypatch.setenv("ARGUS_FOO__BAR", "kiosk")
    value, overridden = cfg.get_with_override("foo.bar")
    assert value == "kiosk"
    assert overridden is True
    assert cfg.get("foo.bar") == "kiosk"


def test_config_set_and_save(tmp_path):
    config_path = tmp_path / "source.yaml"
    config_path.write_text("root: {}\n")

    cfg = Config(config_path)
    cfg.set("root.child", "value")

    output_path = tmp_path / "saved.yaml"
    cfg.save(output_path)

    reloaded = Config(output_path)
    assert reloaded.get("root.child") == "value"
