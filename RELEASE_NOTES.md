# CSec Release Notes

---

## 0.0.1c Alpha — 2026-04-13

Bug fix: Change Password dialog.

### Fixed
- Clicking an input field in the Change Password dialog incorrectly
  triggered the OK or Cancel action, making the dialog unusable
- Root cause: edit control IDs 1 and 2 collided with IDOK and IDCANCEL —
  Win32 sends WM_COMMAND for both button clicks and edit notifications
  using the same control ID field
- Fixed by moving edit control IDs to 201–203 and adding a BN_CLICKED
  check so only actual button clicks trigger OK/Cancel

---

## 0.0.1b Alpha — 2026-04-13

Layout and security fixes.

### Fixed
- Window widened (530 → 640px) — hint label and controls were clipping
- All controls repositioned to fit the new width
- Uninstall Service now requires admin login — students cannot disable
  the filter without knowing the password

---

## 0.0.1a Alpha — 2026-04-13

First working build.

### What's included
- Single `csec.exe` — service, admin GUI, and installer in one binary
- Win32 GUI admin interface (no console, no separate admin tool)
- Windows Service proxy on `127.0.0.1:8080` — blocks all sites not on
  the allowlist, survives reboot, starts automatically with Windows
- Login-protected admin panel: add/remove domains, import/export JSON
- Batch domain removal — tick checkboxes, click Remove selected
- URL normalization — paste any format (`https://`, `www.`, `/path`),
  CSec extracts the domain automatically
- Domain bundles — adding `google.com`, `youtube.com`, `microsoft.com`,
  or `office.com` auto-adds the CDN and auth domains those sites need
- Install/Uninstall Service buttons in the GUI — triggers UAC elevation,
  no command prompt needed
- Change Password dialog
- Forgot password: `csec.exe --reset-password` resets to `123456`
- Onboarding/help dialog (`?` button) — covers setup, usage, security
  limitations, and emergency recovery steps. Auto-shown on first run
- Service status indicator — shows running / stopped / not installed
- Import/Export via standard file open/save dialogs
- GPL v3 license

### Known limitations
- Firefox ignores the Windows system proxy — it must be configured
  separately or removed from student machines
- Students with local Administrator rights can bypass the filter
- No network-level blocking — phone hotspots and VPNs are not blocked
- HTTPS blocked sites show a generic browser error (no custom page)
- No per-user rules, no schedules, no logging

### Requirements
- Windows 7 SP1 or later (32-bit or 64-bit)
- Administrator rights to install/uninstall the service
