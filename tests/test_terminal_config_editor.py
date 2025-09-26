import io
from contextlib import redirect_stdout

import pytest

from src.config.terminal_editor import TerminalConfigEditor


def test_coerce_value_boolean():
    assert TerminalConfigEditor.coerce_value(True, "no") is False
    assert TerminalConfigEditor.coerce_value(False, "Yes") is True


def test_coerce_value_integer():
    assert TerminalConfigEditor.coerce_value(10, "42") == 42
    assert TerminalConfigEditor.coerce_value(10, "0x2a") == 42
    assert TerminalConfigEditor.coerce_value(10, "-0x2a") == -42


def test_coerce_value_float():
    assert TerminalConfigEditor.coerce_value(1.5, "3.25") == pytest.approx(3.25)


def test_coerce_value_list_parsing_success():
    result = TerminalConfigEditor.coerce_value(["a"], "[1, 2, 3]")
    assert result == [1, 2, 3]


def test_coerce_value_list_parsing_failure():
    with pytest.raises(ValueError):
        TerminalConfigEditor.coerce_value(["a"], "not a list")


def test_parse_any_value_blank_returns_empty_string():
    assert TerminalConfigEditor.parse_any_value("   ") == ""


def test_parse_any_value_yaml():
    assert TerminalConfigEditor.parse_any_value("{foo: 1, bar: true}") == {"foo": 1, "bar": True}


def test_summarize_value_truncation():
    long_text = "a" * 80
    summary = TerminalConfigEditor.summarize_value(long_text, max_length=20)
    assert summary.endswith("...")
    assert "a" in summary


def test_handle_quit_prompt_save(monkeypatch):
    editor = TerminalConfigEditor(clear_screen=False)
    editor.dirty = True

    inputs = iter(["y"])

    def fake_input(prompt):
        return next(inputs)

    monkeypatch.setattr("builtins.input", fake_input)
    monkeypatch.setattr(editor.config, "save", lambda path=None: None)

    stdout = io.StringIO()
    with redirect_stdout(stdout):
        result = editor._handle_quit()

    assert result is False
    assert "Exiting configuration editor" in stdout.getvalue()
    assert editor.dirty is False


def test_handle_quit_without_changes(monkeypatch):
    editor = TerminalConfigEditor(clear_screen=False)
    editor.dirty = False

    stdout = io.StringIO()
    with redirect_stdout(stdout):
        result = editor._handle_quit()

    assert result is False
    assert "Exiting configuration editor" in stdout.getvalue()


def test_edit_entry_boolean_offers_choices(monkeypatch):
    editor = TerminalConfigEditor(clear_screen=False)
    editor.current_path = ["app"]
    container = editor.config.data["app"]
    editor._build_entries(container)

    display_index = next(e["display_index"] for e in editor._current_entries if e["key"] == "debug")
    inputs = iter(["1"])  # choose True

    monkeypatch.setattr("builtins.input", lambda prompt: next(inputs))

    stdout = io.StringIO()
    with redirect_stdout(stdout):
        editor._edit_entry(display_index, container)

    assert container["debug"] is True
    assert editor.dirty is True


def test_edit_entry_with_predefined_choices(monkeypatch):
    editor = TerminalConfigEditor(clear_screen=False)
    editor.current_path = ["logging"]
    container = editor.config.data["logging"]
    editor._build_entries(container)

    display_index = next(e["display_index"] for e in editor._current_entries if e["key"] == "level")
    inputs = iter(["5"])  # select DEBUG

    monkeypatch.setattr("builtins.input", lambda prompt: next(inputs))

    stdout = io.StringIO()
    with redirect_stdout(stdout):
        editor._edit_entry(display_index, container)

    assert container["level"] == "DEBUG"
