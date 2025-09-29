# ArgusPI v2 Test Plan

This checklist-driven plan exercises every operating mode and security feature with minimal duplication. Execute the sections most relevant to the change under test, but run the full suite before major releases.

---

## 1. Prerequisites & Baseline

- [ ] **Workstation**: Raspberry Pi (or equivalent Linux test host) with ArgusPI v2 installed from `main`.
- [ ] **Software**: ClamAV daemon active, latest virus definitions, optional VirusTotal API key if testing VT paths.
- [ ] **Accounts**: Runtime user added to `plugdev`, `clamav`, and has passwordless sudo for prescribed commands when required.
- [ ] **USB Media**: Two thumb drives — one clean, one seeded with the `test_mount/test_usb` sample set (contains benign + flagged files).
- [ ] **Networking**: Internet access for VirusTotal and remote rule sync tests; SIEM endpoint reachable when applicable.
- [ ] **Logs Cleared**: Optionally rotate or archive `logs/arguspi.log` and SIEM offline cache for easier diffing.

---

## 2. Configuration Management

### 2.1 Terminal Config Editor

- [ ] Launch editor: `python main.py --config-editor`.
- [ ] Navigate to `security.rules.local` and toggle a value using pick lists; confirm type-aware prompts.
- [ ] Save to a temporary file; reopen to confirm persisted changes.
- [ ] Restore defaults afterward (either discard or reload baseline config).

### 2.2 Environment Overrides

- [ ] Set GUI backend override (`export ARGUS_GUI__BACKEND=kiosk` on bash/zsh, `$env:ARGUS_GUI__BACKEND = "kiosk"` in PowerShell) and run `python main.py --config-editor` to verify the value updates to `kiosk` with an `(env override)` badge. Single-underscore names such as `ARGUS_GUI_BACKEND` are also accepted.
- [ ] Unset the variable (`unset ARGUS_GUI__BACKEND` / `Remove-Item Env:ARGUS_GUI__BACKEND`) and confirm the base value returns.

---

## 3. Console Mode Verification (`gui.backend: console`)

- [ ] Activate venv and start console UI: `python main.py`.
- [ ] **USB Insert** (clean stick): insert device, expect metadata banner, auto-read-only mount, and idle state without warnings.
- [ ] Trigger manual scan; observe progress, zero threats, and completion SIEM event (if enabled).
- [ ] **USB Remove**: remove stick, confirm unmount notice and UI resets.
- [ ] **USB Insert** (test stick): expect immediate warning for suspicious files, scan kicks off, threats logged/quarantined when enabled.
- [ ] Exit with `Ctrl+C`; ensure graceful shutdown with no tracebacks.

---

## 4. Kiosk Mode Smoke (`python main.py --kiosk`)

- [ ] Enable fullscreen behavior; on boot, verify welcome screen.
- [ ] Insert clean stick: interface should show metadata summary, auto-scan result card, and remain onscreen until removal.
- [ ] Remove stick: display clears to welcome after timeout.
- [ ] Insert test stick: expect red threat banner, blocked device notice if rules match, and SIEM `usb_warning` event.
- [ ] Attempt to exit kiosk using keyboard shortcuts; confirm locked down (no terminal escape).

---

## 5. Qt Desktop Mode (`gui.backend: qt`)

- [ ] Launch `python main.py` within X11/Wayland session.
- [ ] Verify device list populates with inserted USB.
- [ ] Start/stop scan via GUI button; observe progress bar and log panel updates.
- [ ] Confirm threat notifications surface in dedicated pane and mirror console logs.

---

## 6. Security Modules

### 6.1 Quarantine Manager (`security.quarantine.enabled: true`)

- [ ] Clear `quarantine/` directory.
- [ ] Scan test stick containing infected sample.
- [ ] Verify quarantined copy created, metadata JSON alongside, and retention counter respected.
- [ ] Toggle `keep_original: false` (if available) and confirm source file removal on next scan.

### 6.2 Reputation Store (`security.reputation.enabled: true`)

- [ ] Connect the same USB twice in a row.
- [ ] After first warning, check `logs/arguspi.log` and GUI for reputation entry (warning count = 1).
- [ ] On second insert, ensure warning escalates (e.g., “repeat offender”).
- [ ] Inspect SQLite DB (typically `data/reputation.db`) for accurate records.

### 6.3 USB Rules Engine (`security.rules`)

- [ ] **Inline Rule**: add test VID/PID under `security.rules.local.blocked_devices`; restart app, insert matching device, expect immediate block.
- [ ] **External YAML**: populate `config/rules.local.yaml` with a serial prefix; validate merge behavior and warning text.
- [ ] **Remote Sync**: point `security.rules.sync.url` to mock server returning JSON rule. Force refresh (set interval to 1 minute, restart) and confirm rules apply even after clearing local lists.
- [ ] Disable syncing afterward to restore baseline.

---

## 7. Scanner Engine

- [ ] Simulate ClamAV socket outage (stop `clamav-daemon`); run scan and ensure CLI fallback engages when `prefer_cli: false`.
- [ ] Re-enable daemon and verify Python client path resumes without errors.
- [ ] If VirusTotal enabled, submit hash-only lookup (ensuring daily quota respected), confirm API warnings handled when quota exceeded.

---

## 8. SIEM & Offline Cache

- [ ] With SIEM enabled, monitor remote system for `usb_connected`, `scan_start`, `scan_complete`, and `threat_detected` events during a full scan cycle.
- [ ] Disconnect network; trigger events and confirm they accumulate in `logs/siem_offline_cache.jsonl` without raising exceptions.
- [ ] Reconnect network; observe automatic flush and SIEM receipt.

---

## 9. Service & Watchdog Operations

- [ ] Install service via `sudo ./install.sh` (if not already).
- [ ] `sudo systemctl start arguspi` and confirm logs show startup sequence.
- [ ] Insert USB to ensure daemon mode mirrors console behavior.
- [ ] Trigger kiosk watchdog by forcibly killing UI process; verify auto-restart action (`restart-service` or `exit`) fires within configured timeout.
- [ ] Reboot host, ensure services auto-start according to `auto_start` configuration.

---

## 10. Regression & Edge Cases

- [ ] Plug non-storage USB (e.g., keyboard); confirm warning without mounting.
- [ ] Insert USB with unsupported filesystem; verify graceful failure message and SIEM event.
- [ ] Attempt scanning > configured `max_file_size`; confirm skip with logged reason.
- [ ] Run `python main.py --version` and `--help` to ensure CLI metadata up to date.
- [ ] Execute `python -m pytest`; ensure all automated tests pass (baseline regression guard).

---

## Sign-Off

Capture evidence (screenshots, logs, SIEM extracts) for each major section and archive alongside the build artifact. A release is ready when all mandatory checklists are complete and any deviations are documented with risk rationale and follow-up actions.
