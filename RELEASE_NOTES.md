# CSec Release Notes

---

## 0.0.5 Alpha — 2026-04-24

Progressive list loading — popular sites blocked instantly on startup.

### Added
- **`_priority.txt`** — a small curated list (~67 domains) of the most
  commonly known blocked sites (pornhub, xvideos, facebook, instagram,
  tiktok, bet365, thepiratebay, etc.). Loads first, unconditionally,
  in every mode
- **Progressive background loading** — on startup the service hot-loads
  the first 500 entries from each enabled list (popular domains first),
  starts accepting connections immediately, then expands coverage in
  background batches: 1,500 → 5,000 → full list. Popular sites are
  blocked before the "starting..." status clears
- **`sort_lists.py`** — utility script that reorders each `.txt` list file
  so the most commonly known domains in that category appear at the top.
  Run after downloading updated list files

### Changed
- List loading is now asynchronous — the proxy starts in <100 ms regardless
  of how large the enabled lists are
- `_priority.txt` shows correct domain count (67) in the Block Lists dialog

---

## 0.0.4 Alpha — 2026-04-23

Proxy settings lock — students cannot bypass the filter by changing proxy settings.

### Added
- **Proxy settings lock** — when the service is installed, the Windows proxy
  settings panel (Settings → Network & Internet → Proxy, and Internet Options)
  is grayed out and inaccessible to users
- The lock is applied to every user account on the machine: the current user,
  all other loaded user profiles, and the `.DEFAULT` hive (new accounts)
- Implemented via the Group Policy registry key
  `HKCU\Software\Policies\Microsoft\Internet Explorer\Control Panel\Proxy = 1`
  written under `HKEY_USERS` for each profile

### Changed
- Lock is removed automatically when the service is uninstalled — proxy access
  is fully restored alongside internet access

---

## 0.0.3 Alpha — 2026-04-23

Real block lists from The Block List Project.

### Added
- **Block Lists dialog** — click **Block Lists** after login to enable or
  disable any `.txt` file from the `Lists\` folder. Domain counts and
  category names are read from each file's header automatically
- **18 list files included** — gambling (2,500), porn (500,282), tiktok
  (3,699), facebook (22,459), twitter (1,193), ads (154,554), tracking
  (15,070), malware (435,220), phishing (190,222), fraud (196,082),
  scam (1,274), drugs (26,031), crypto (23,761), piracy (2,153),
  torrent (2,624), ransomware (1,904), redirect (108,684), abuse (435,155)
- **Fast lookup** — each enabled list is loaded into a sorted array at
  service startup; domain checks use binary search (O(log n)), so even a
  500K-domain list costs ~19 string comparisons per request
- **Drop-in extensible** — place any additional `.txt` file in the
  `Lists\` folder using the standard hosts format (`0.0.0.0 domain.com`)
  and it appears in the dialog without any code changes

### Changed
- Block Lists are only active in **Blacklist mode** (in Whitelist mode
  everything is already blocked by default)
- Service reloads list files on startup and whenever the admin saves
  changes via the GUI
- `MAX_DOMAINS` raised from 512 to 1024

### Source
Lists from [The Block List Project](https://github.com/blocklistproject/Lists) — MIT License

---

## 0.0.2 Alpha — 2026-04-23

Whitelist / Blacklist mode toggle.

### Added
- **Filter mode radio buttons** — choose between Whitelist (block all
  except your list) or Blacklist (allow all except your list) directly
  from the main window, no restart required
- The domain list column header updates to "Allowed URLs" or "Blocked URLs"
  to reflect the active mode
- Mode is saved to config and applied immediately by the running service

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
