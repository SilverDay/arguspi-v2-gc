"""Terminal-based configuration editor for ArgusPI v2."""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union

import yaml

from .manager import Config


class TerminalConfigEditor:
    """Interactive terminal user interface for editing configuration files."""

    CHOICE_MAP: Dict[Tuple[str, ...], List[Any]] = {
        ("gui", "backend"): ["console", "qt", "kiosk"],
        ("gui", "mode"): ["simple", "expert"],
        ("gui", "theme"): ["light", "dark"],
        ("gui", "orientation"): ["auto", "portrait", "landscape"],
        ("siem", "protocol"): ["syslog", "http", "tcp"],
        ("siem", "format"): ["json", "cef", "leef"],
        ("siem", "severity"): [
            "emergency",
            "alert",
            "critical",
            "error",
            "warning",
            "notice",
            "info",
            "debug",
        ],
        ("siem", "facility"): [
            "kern",
            "user",
            "mail",
            "daemon",
            "auth",
            "syslog",
            "lpr",
            "news",
            "uucp",
            "cron",
            "authpriv",
            "ftp",
            "local0",
            "local1",
            "local2",
            "local3",
            "local4",
            "local5",
            "local6",
            "local7",
        ],
        ("logging", "level"): ["CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG", "NOTSET"],
        ("kiosk", "watchdog", "action"): ["restart-service", "exit"],
        ("security", "quarantine", "report_format"): ["json", "text"],
    }

    TRUE_VALUES = {"true", "t", "yes", "y", "1", "on"}
    FALSE_VALUES = {"false", "f", "no", "n", "0", "off"}

    def __init__(self, config_path: Optional[Union[str, os.PathLike]] = None, *, clear_screen: bool = True) -> None:
        self.config = Config(config_path)
        self.clear_screen = clear_screen
        self.current_path: List[Union[str, int]] = []
        self.dirty = False
        self.status_message = ""
        self.config_file = Path(self.config.config_file)
        self._current_entries: List[Dict[str, Any]] = []

    # ------------------------------------------------------------------
    # Rendering helpers
    # ------------------------------------------------------------------
    def run(self) -> None:
        """Run the interactive editor loop."""
        while True:
            container = self._resolve_current_container()
            self._render(container)
            command = input("\nCommand (? for help): ").strip()
            if not command:
                self.status_message = ""
                continue
            if not self._handle_command(command, container):
                break

    def _render(self, container: Any) -> None:
        if self.clear_screen:
            self._clear_screen()
        self._render_header()
        self._build_entries(container)
        self._render_entries()
        self._render_footer(container)

    def _render_header(self) -> None:
        width = 80
        path_display = " / ".join(["root"] + [str(part) for part in self.current_path]) or "root"
        status = "unsaved changes" if self.dirty else "clean"
        print("=" * width)
        print("ArgusPI Configuration Editor".center(width))
        print("=" * width)
        print(f"File   : {self.config_file}")
        print(f"Path   : {path_display}")
        print(f"Status : {status}")
        if self.status_message:
            print(f"Note   : {self.status_message}")
        print("-" * width)

    def _build_entries(self, container: Any) -> None:
        entries: List[Dict[str, Any]] = []
        if isinstance(container, dict):
            for display_index, key in enumerate(container.keys(), start=1):
                value = container[key]
                openable = isinstance(value, (dict, list))
                display_value = value
                from_env = False
                if not openable:
                    path_key = ".".join(self._path_tuple(key))
                    display_value, from_env = self.config.get_with_override(path_key, value)
                entries.append(
                    {
                        "display_index": display_index,
                        "key": key,
                        "label": str(key),
                        "value": value,
                        "display_value": display_value,
                        "from_env": from_env,
                        "container_type": "dict",
                        "openable": openable,
                    }
                )
        elif isinstance(container, list):
            for display_index, value in enumerate(container, start=1):
                entries.append(
                    {
                        "display_index": display_index,
                        "key": display_index - 1,
                        "label": f"[{display_index - 1}]",
                        "value": value,
                        "display_value": value,
                        "from_env": False,
                        "container_type": "list",
                        "openable": isinstance(value, (dict, list)),
                    }
                )
        else:
            entries = []
        self._current_entries = entries

    def _render_entries(self) -> None:
        if not self._current_entries:
            print("(No entries in this section)")
            return

        for entry in self._current_entries:
            arrow = "➜" if entry["openable"] else " "
            display_value = entry.get("display_value", entry["value"])
            summary = self.summarize_value(display_value)
            if entry.get("from_env"):
                summary += "  (env override)"
            print(f"{entry['display_index']:>2}. {arrow} {entry['label']:<24} {summary}")

    def _render_footer(self, container: Any) -> None:
        commands = [
            "number=open/edit",
            "o <n>=open",
            "e <n>=edit",
            "d <n>=delete",
            "a=add",
            "b=back",
            "s=save",
            "r=reload",
            "q=quit",
            "?=help",
        ]
        container_hint = "dict" if isinstance(container, dict) else "list" if isinstance(container, list) else "value"
        print("\nCurrent container type:", container_hint)
        print("Commands: " + ", ".join(commands))

    def _clear_screen(self) -> None:
        if os.name == "nt":
            os.system("cls")
        else:
            print("\033c", end="")

    # ------------------------------------------------------------------
    # Command handling
    # ------------------------------------------------------------------
    def _handle_command(self, command: str, container: Any) -> bool:
        tokens = command.split()
        primary = tokens[0].lower()

        if command.isdigit():
            return self._handle_numeric_selection(int(command), container)

        if primary in {"q", "quit", "exit"}:
            return self._handle_quit()

        if primary in {"b", "back", "up"}:
            if self.current_path:
                self.current_path.pop()
                self.status_message = "Moved up one level."
            else:
                self.status_message = "Already at root."
            return True

        if primary in {"s", "save"}:
            path_arg = tokens[1] if len(tokens) > 1 else None
            self._handle_save(path_arg)
            return True

        if primary in {"r", "reload"}:
            self._handle_reload()
            return True

        if primary in {"?", "h", "help"}:
            self._show_help()
            return True

        if primary in {"o", "open"}:
            if len(tokens) < 2 or not tokens[1].isdigit():
                self.status_message = "Provide an entry number to open (e.g., o 2)."
                return True
            return self._open_entry(int(tokens[1]))

        if primary in {"e", "edit"}:
            if len(tokens) < 2 or not tokens[1].isdigit():
                self.status_message = "Provide an entry number to edit (e.g., e 1)."
                return True
            return self._edit_entry(int(tokens[1]), container)

        if primary in {"d", "del", "delete"}:
            if len(tokens) < 2 or not tokens[1].isdigit():
                self.status_message = "Provide an entry number to delete (e.g., d 3)."
                return True
            return self._delete_entry(int(tokens[1]), container)

        if primary in {"a", "add", "new"}:
            self._add_entry(container)
            return True

        self.status_message = f"Unknown command: {command}"
        return True

    def _handle_numeric_selection(self, display_index: int, container: Any) -> bool:
        entry = self._get_entry(display_index)
        if entry is None:
            self.status_message = "Invalid selection."
            return True
        if entry["openable"]:
            self.current_path.append(entry["key"])
            self.status_message = ""
        else:
            self._edit_entry(display_index, container)
        return True

    def _handle_quit(self) -> bool:
        if self.dirty:
            answer = input("You have unsaved changes. Save before exit? [y/N]: ").strip().lower()
            if answer in self.TRUE_VALUES:
                self._handle_save(None)
        print("Exiting configuration editor.")
        return False

    def _handle_save(self, path_arg: Optional[str]) -> None:
        path: Optional[Union[str, os.PathLike]] = path_arg
        if path_arg:
            path = Path(path_arg).expanduser()
        try:
            self.config.save(path)
            self.dirty = False
            self.status_message = f"Configuration saved to {path or self.config_file}."
        except Exception as exc:  # pragma: no cover - passes through Config.save errors
            self.status_message = f"Failed to save configuration: {exc}"

    def _handle_reload(self) -> None:
        if self.dirty:
            answer = input("Discard unsaved changes and reload from disk? [y/N]: ").strip().lower()
            if answer not in self.TRUE_VALUES:
                self.status_message = "Reload cancelled."
                return
        self.config.load()
        self.current_path = []
        self.dirty = False
        self.status_message = "Configuration reloaded from disk."

    def _open_entry(self, display_index: int) -> bool:
        entry = self._get_entry(display_index)
        if entry is None:
            self.status_message = "Invalid selection."
            return True
        if not entry["openable"]:
            self.status_message = "Entry is not a container; use edit command instead."
            return True
        self.current_path.append(entry["key"])
        self.status_message = ""
        return True

    def _edit_entry(self, display_index: int, container: Any) -> bool:
        entry = self._get_entry(display_index)
        if entry is None:
            self.status_message = "Invalid selection."
            return True
        value = entry["value"]
        display_value = entry.get("display_value", value)
        if isinstance(value, (dict, list)):
            self.status_message = "Cannot edit a nested structure directly; open it first."
            return True

        label = entry["label"]
        type_name = type(value).__name__
        choices = self._choices_for_entry(entry)
        if choices:
            self._present_choices(choices, display_value)
        if entry.get("from_env"):
            print(
                "Note: This value is currently overridden by an environment variable. "
                "File changes will take effect once the override is removed."
            )
        while True:
            user_input = input(f"New value for {label} ({type_name}) [blank to cancel]: ")
            if user_input == "":
                self.status_message = "Edit cancelled."
                return True
            if choices:
                matched = self._interpret_choice_input(user_input, choices)
                if matched is not None:
                    new_value = matched
                    break
            try:
                new_value = self.coerce_value(value, user_input)
            except ValueError as exc:
                print(f"Invalid input: {exc}")
                continue
            break

        if entry["container_type"] == "dict":
            assert isinstance(container, dict)
            container[entry["key"]] = new_value
        elif entry["container_type"] == "list":
            assert isinstance(container, list)
            container[entry["key"]] = new_value
        else:  # pragma: no cover - defensive
            self.status_message = "Unable to edit this entry."
            return True

        self.dirty = True
        self.status_message = f"Updated {label}."
        return True

    def _delete_entry(self, display_index: int, container: Any) -> bool:
        entry = self._get_entry(display_index)
        if entry is None:
            self.status_message = "Invalid selection."
            return True

        label = entry["label"]
        confirm = input(f"Delete {label}? This cannot be undone. [y/N]: ").strip().lower()
        if confirm not in self.TRUE_VALUES:
            self.status_message = "Deletion cancelled."
            return True

        if entry["container_type"] == "dict":
            assert isinstance(container, dict)
            container.pop(entry["key"], None)
        elif entry["container_type"] == "list":
            assert isinstance(container, list)
            container.pop(entry["key"])
        else:  # pragma: no cover - defensive
            self.status_message = "Unable to delete this entry."
            return True

        self.dirty = True
        self.status_message = f"Deleted {label}."
        return True

    def _add_entry(self, container: Any) -> None:
        if isinstance(container, dict):
            key = input("New key name: ").strip()
            if not key:
                self.status_message = "Key cannot be empty."
                return
            if key in container:
                self.status_message = "Key already exists."
                return
            value_text = input("Enter value (YAML, blank for empty string): ")
            if value_text.strip() == "":
                new_value: Any = ""
            else:
                try:
                    new_value = self.parse_any_value(value_text)
                except ValueError as exc:
                    self.status_message = f"Failed to parse value: {exc}"
                    return
            container[key] = new_value
            self.dirty = True
            self.status_message = f"Added key '{key}'."
        elif isinstance(container, list):
            value_text = input("Enter value for new item (YAML, blank for empty string): ")
            if value_text.strip() == "":
                new_value = ""
            else:
                try:
                    new_value = self.parse_any_value(value_text)
                except ValueError as exc:
                    self.status_message = f"Failed to parse value: {exc}"
                    return
            container.append(new_value)
            self.dirty = True
            self.status_message = "Added new list item."
        else:
            self.status_message = "Cannot add items to this value."

    def _get_entry(self, display_index: int) -> Optional[Dict[str, Any]]:
        for entry in self._current_entries:
            if entry["display_index"] == display_index:
                return entry
        return None

    def _show_help(self) -> None:
        if self.clear_screen:
            self._clear_screen()
        print("""
ArgusPI Configuration Editor Help
================================
- Use the entry numbers to open nested sections or edit values.
- Enter YAML snippets when prompted for values (examples: true, 42, "text", [1, 2], {key: value}).
- Commands:
  number          Open or edit an entry depending on its type
  o <number>      Explicitly open a nested section
  e <number>      Edit an entry's value
  d <number>      Delete an entry from the current container
  a               Add a new key (dict) or append to the list
  b               Go back to the parent container
  s [path]        Save changes (optional custom path)
  r               Reload configuration from disk (discard changes)
  q               Quit the editor (prompts to save if needed)
  ?               Show this help screen
""")
        input("Press Enter to return to the editor...")
        self.status_message = ""

    # ------------------------------------------------------------------
    # Data helpers
    # ------------------------------------------------------------------
    def _resolve_current_container(self) -> Any:
        node: Any = self.config.data
        if not self.current_path:
            return node
        try:
            for part in self.current_path:
                node = node[part]
        except (KeyError, IndexError, TypeError):
            self.current_path = []
            node = self.config.data
            self.status_message = "Current path became invalid; returned to root."
        return node

    @staticmethod
    def summarize_value(value: Any, max_length: int = 48) -> str:
        if isinstance(value, dict):
            return f"<dict> ({len(value)} keys)"
        if isinstance(value, list):
            return f"<list> ({len(value)} items)"
        if isinstance(value, bool):
            return f"bool = {str(value).lower()}"
        if value is None:
            return "None"
        text = repr(value)
        if len(text) > max_length:
            text = text[: max_length - 3] + "..."
        return f"{type(value).__name__} = {text}"

    @classmethod
    def coerce_value(cls, current_value: Any, new_text: str) -> Any:
        stripped = new_text.strip()
        if isinstance(current_value, bool):
            lowered = stripped.lower()
            if lowered in cls.TRUE_VALUES:
                return True
            if lowered in cls.FALSE_VALUES:
                return False
            raise ValueError("Enter true/false (or yes/no, 1/0).")

        if isinstance(current_value, int) and not isinstance(current_value, bool):
            lowered = stripped.lower()
            unsigned = lowered[1:] if lowered[:1] in {"+", "-"} else lowered
            base = 10
            if unsigned.startswith("0x"):
                base = 16
            elif unsigned.startswith("0o"):
                base = 8
            elif unsigned.startswith("0b"):
                base = 2
            return int(lowered, base)

        if isinstance(current_value, float):
            return float(stripped)

        if isinstance(current_value, list):
            parsed = cls.parse_any_value(new_text)
            if not isinstance(parsed, list):
                raise ValueError("Provide a YAML list, e.g., [item1, item2].")
            return parsed

        if isinstance(current_value, dict):
            parsed = cls.parse_any_value(new_text)
            if not isinstance(parsed, dict):
                raise ValueError("Provide a YAML mapping, e.g., {key: value}.")
            return parsed

        if current_value is None:
            return cls.parse_any_value(new_text)

        return new_text

    @staticmethod
    def parse_any_value(text: str) -> Any:
        stripped = text.strip()
        if stripped == "":
            return ""
        try:
            return yaml.safe_load(text)
        except yaml.YAMLError as exc:
            raise ValueError(str(exc)) from exc

    # ------------------------------------------------------------------
    # Choice helpers
    # ------------------------------------------------------------------
    def _path_tuple(self, key: Union[str, int]) -> Tuple[str, ...]:
        parts = [str(part) for part in self.current_path]
        parts.append(str(key))
        return tuple(parts)

    def _choices_for_entry(self, entry: Dict[str, Any]) -> Optional[List[Any]]:
        value = entry["value"]
        # Prioritize boolean shortcuts
        if isinstance(value, bool):
            return [True, False]

        path = self._path_tuple(entry["key"])
        choices = self.CHOICE_MAP.get(path)
        if choices is not None:
            return choices
        return None

    def _present_choices(self, choices: Sequence[Any], current_value: Any) -> None:
        print("Available choices:")
        for index, option in enumerate(choices, start=1):
            marker = " (current)" if option == current_value else ""
            print(f"  {index}. {self._format_choice(option)}{marker}")

    def _interpret_choice_input(self, user_input: str, choices: Sequence[Any]) -> Optional[Any]:
        stripped = user_input.strip()
        if stripped.isdigit():
            index = int(stripped)
            if 1 <= index <= len(choices):
                return choices[index - 1]

        lowered = stripped.lower()
        for option in choices:
            if isinstance(option, bool):
                if lowered in self.TRUE_VALUES and option is True:
                    return True
                if lowered in self.FALSE_VALUES and option is False:
                    return False
            if str(option).lower() == lowered:
                return option
        return None

    @staticmethod
    def _format_choice(choice: Any) -> str:
        if isinstance(choice, bool):
            return str(choice).lower()
        return str(choice)


__all__ = ["TerminalConfigEditor"]
