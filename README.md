<img width="823" height="651" alt="εικόνα" src="https://github.com/user-attachments/assets/a56a9f6d-cea7-47b2-a1bf-b86ae4571381" />

<img width="623" height="563" alt="εικόνα" src="https://github.com/user-attachments/assets/e45eff18-2334-4e25-a64b-866319d59071" />

<img width="704" height="687" alt="εικόνα" src="https://github.com/user-attachments/assets/6767e550-238d-4fae-9a44-e2cd32a52f16" />



# CSec — Classroom Web Filter

Blocks all websites except the ones you allow, or allows everything except
the sites you block. Runs as a Windows Service. Survives reboot.
No internet connection required.

**Version:** 0.0.9 Alpha

---

## What it does

- **Whitelist mode** (default): every site is blocked unless it is on your list
- **Blacklist mode**: every site is allowed unless it is on your list
- One entry covers the domain and all subdomains: `code.org` covers
  `studio.code.org`, `www.code.org`, etc.
- The filter stays active through reboot — students cannot escape by restarting
- Managed through a password-protected GUI (`csec.exe`)
- Lists are plain JSON files — easy to share via USB or a shared folder
- 18 ready-made block lists included (gambling, adult, social media, malware, …)

---

## Requirements

**Windows**
- Windows 7 SP1 or later (32-bit or 64-bit)
- Administrator rights to install and uninstall

**Linux** (tested target: Fedora KDE, Linux Mint)
- systemd, a C toolchain (`cc`/gcc), and `make`
- `root` (sudo) to install/uninstall
- `gsettings` (GNOME/Cinnamon) and/or `kwriteconfig5`/`kwriteconfig6` (KDE) for
  desktop-proxy enforcement — both are present by default on the target distros

> Windows and Linux share one codebase. The filtering proxy engine (`proxy.c`)
> is identical on both; only the frontend differs — a Win32 service + GUI on
> Windows (`csec.c`), a systemd daemon + CLI on Linux (`csec_posix.c`).

---

## What's in the package

```
csec.exe          — the filter service, proxy, and admin GUI in one binary
csec-config.json  — your settings (created on first run)
Lists\            — block list files (The Block List Project, MIT License)
  gambling.txt      2,500 domains
  porn.txt        500,282 domains
  tiktok.txt        3,699 domains
  facebook.txt     22,459 domains
  twitter.txt       1,193 domains
  ads.txt         154,554 domains
  tracking.txt     15,070 domains
  malware.txt     435,220 domains
  phishing.txt    190,222 domains
  fraud.txt       196,082 domains
  scam.txt          1,274 domains
  drugs.txt        26,031 domains
  crypto.txt       23,761 domains
  piracy.txt        2,153 domains
  torrent.txt       2,624 domains
  ransomware.txt    1,904 domains
  redirect.txt    108,684 domains
  abuse.txt       435,155 domains
```

---

## Setup

1. Copy the entire `CSec` folder (exe + config + Lists\) to the target machine
2. Open `csec.exe`
3. Click **Install Service** at the bottom of the window
4. Approve the Administrator prompt
5. The filter is now active
6. Log in with the default password `123456` and configure your list

---

## Admin interface

Open `csec.exe` and log in to manage the filter.

```
┌─ CSec 0.0.7 Alpha — Classroom Web Filter ────────────────────────────┐
│  Admin Access  [_________password_________]  [Login]             [?] │
│  Filter mode:  ● Whitelist — block all except list                    │
│                ○ Blacklist — allow all except list                    │
│  Safe Search:  ☑ Force SafeSearch on Google search (recommended)      │
│  YouTube:      ○ Off    ○ Moderate    ● Strict (recommended)           │
│  URL           [_________domain____________]  [Add]                   │
│                Enter domain only — e.g. code.org                      │
│ ┌───────────────────────────────────────────────────────────────────┐ │
│ │ Allowed URLs                                                      │ │
│ │ ☐  code.org                                                       │ │
│ │ ☐  googleapis.com                                                 │ │
│ └───────────────────────────────────────────────────────────────────┘ │
│  [Remove sel.] [Import JSON] [Export JSON] [Block Lists] [Chg Pwd]    │
│ ──────────────────────────────────────────────────────────────────── │
│  Service: running        [Install Service]  [Uninstall Service]       │
└───────────────────────────────────────────────────────────────────────┘
```

---

## Filter mode

After logging in, select how the list is applied:

| Mode | Behaviour |
|---|---|
| **Whitelist** (default) | Every site is blocked **unless** it is on the list |
| **Blacklist** | Every site is allowed **unless** it is on the list |

Switching mode saves immediately — no service restart needed.

**Recommended for most classrooms:** Whitelist — add only the sites students
need, everything else is blocked by default.

**For labs or BYOD environments:** Blacklist — allow everything and use the
block lists to ban specific categories.

---

## Block Lists

Click **Block Lists** (log in first) to enable or disable the included
category lists. A dialog shows every `.txt` file found in the `Lists\` folder:

| List file | Domains | What it blocks |
|---|---|---|
| `gambling.txt` | 2,500 | Online betting and casino sites |
| `porn.txt` | 500,282 | Adult and explicit content |
| `tiktok.txt` | 3,699 | TikTok and related infrastructure |
| `facebook.txt` | 22,459 | Facebook and Instagram infrastructure |
| `twitter.txt` | 1,193 | Twitter / X infrastructure |
| `ads.txt` | 154,554 | Advertising networks |
| `tracking.txt` | 15,070 | Analytics and tracking services |
| `malware.txt` | 435,220 | Known malware distribution sites |
| `phishing.txt` | 190,222 | Phishing and credential harvesting |
| `fraud.txt` | 196,082 | Fraud and scam infrastructure |
| `scam.txt` | 1,274 | Scam sites |
| `drugs.txt` | 26,031 | Drug-related sites |
| `crypto.txt` | 23,761 | Cryptocurrency and mining sites |
| `piracy.txt` | 2,153 | Piracy and illegal download sites |
| `torrent.txt` | 2,624 | Torrent sites |
| `ransomware.txt` | 1,904 | Known ransomware distribution |
| `redirect.txt` | 108,684 | Malicious redirect services |
| `abuse.txt` | 435,155 | Abuse and spam infrastructure |

Tick the lists you want and click **OK** — the service reloads and starts
blocking those domains immediately.

> **Block Lists only work in Blacklist mode.** In Whitelist mode everything
> is already blocked by default so the lists have no effect.

To add your own list: drop any `.txt` file in the `Lists\` folder using the
same hosts format (`0.0.0.0 domain.com`) and it will appear in the dialog
automatically.

Lists sourced from [The Block List Project](https://github.com/blocklistproject/Lists) — MIT License.

---

## Adding domains manually

Type the domain — no `http://`, no `www.`, no path:

```
code.org
wordwall.net
khanacademy.org
```

You can also paste a full URL — CSec strips everything down to the domain
automatically.

---

## Known sites — automatic extras

Adding these domains also adds the supporting CDN and auth domains they need:

| You add | Also added automatically |
|---|---|
| `google.com` | googleapis.com, gstatic.com, googleusercontent.com, … |
| `youtube.com` | ytimg.com, googlevideo.com, youtu.be, … |
| `microsoft.com` | microsoftonline.com, live.com, windowsupdate.com, … |
| `office.com` | microsoft.com, microsoftonline.com, sharepoint.com, … |

---

## Removing domains

Tick the checkbox next to each domain you want to remove, then click
**Remove selected**.

---

## Sharing your list

Build your list on the teacher machine, click **Export to JSON**, copy the
file to each student machine via USB or shared folder, then open `csec.exe`
on each and click **Import from JSON**.

---

## Password

Default password: `123456` — change it after first login (Change Password button).

Forgot the password? Open CMD as Administrator in the CSec folder and run:

```
csec.exe --reset-password
```

This resets the password back to `123456`.

---

## Uninstalling

Open `csec.exe`, log in, then click **Uninstall Service**.

Or from CMD as Administrator:

```
csec.exe --uninstall
```

---

## Security limitations

CSec sets the Windows system proxy. It is a deterrent, not a full lockdown.

| Bypass | Risk | Mitigation |
|---|---|---|
| Firefox (own proxy settings) | High | Remove Firefox or lock via Firefox admin policy |
| Local Administrator account | High | Student accounts must not have admin rights |
| Phone hotspot / USB tethering | Medium | Disable USB ports or use a router-level filter |
| VPN app | Medium | Restrict software installs with a limited user account |

---

## Linux (Fedora KDE / Linux Mint)

On Linux the filter runs as a **systemd service** and is managed from the
command line. The proxy is enforced through the desktop proxy settings
(GNOME/Cinnamon `gsettings`, KDE `kioslaverc`) plus `/etc/environment`.

### Install

```
make                 # builds ./csec
sudo ./csec install  # installs to /usr/local/bin, starts the service, turns on the proxy
```

On first install this launches a **guided setup wizard** — pick one of four
presets or answer a few questions to choose the mode, SafeSearch/YouTube,
category block lists, allowed sites, and an admin password. Re-run it anytime:

```
sudo csec setup
```

The four presets:

| # | Preset | Mode | Category lists |
|---|---|---|---|
| 1 | Locked down | whitelist | all blocked |
| 2 | Block bad categories | blacklist | all blocked |
| 3 | Locked down, allow ads | whitelist | all except ads |
| 4 | Block bad categories, allow ads | blacklist | all except ads |

(All presets force Google SafeSearch and YouTube strict mode.)

Log out and back in so every app picks up the new proxy. Config and lists are
stored under `/etc/csec/`.

### Manage

```
csec help                         # full, explained command reference
csec status                       # service + filter status
sudo csec add code.org            # allow a site (adds known CDN/auth extras too)
sudo csec remove code.org
csec list                         # show the current site list
sudo csec mode whitelist          # or: blacklist
sudo csec safesearch on           # force Google SafeSearch
sudo csec youtube strict          # off | moderate | strict
csec lists                        # show categories and what's blocked
sudo csec block gambling          # block a whole category (blacklist mode only)
sudo csec unblock gambling        # stop blocking it
sudo csec passwd                  # change admin password
sudo csec import list.json        # import / export a config
csec export list.json
sudo csec uninstall               # remove the service, restore the proxy
```

> On Linux the admin gate is `sudo` (config lives in root-owned `/etc/csec/`).
> The password is kept for parity and used by `csec passwd` / list import-export.

### Enforcement modes (Linux)

CSec can enforce the filter two ways — choose in `csec setup` or switch anytime:

```
sudo csec enforcement transparent   # recommended: can't be bypassed
sudo csec enforcement proxy          # desktop/system proxy only (a deterrent)
```

| Mode | How it works | Bypassable? |
|---|---|---|
| **transparent** | `nftables` redirects all outbound :80/:443 through the proxy; hostname is read from the HTTP `Host:` header / TLS **SNI**. The browser's own proxy setting is irrelevant. | No (short of root / a VPN / another network) |
| **proxy** | Sets the GNOME/KDE/`/etc/environment` system proxy. | Yes — a student can change their browser's proxy, `unset http_proxy`, etc. |

Transparent mode skips traffic owned by **root** (so the proxy never loops, and
system services stay direct) and **rejects IPv6** :80/:443 so it can't be used
to slip past the IPv4 redirect. It needs the `nftables` package. Students must
not have `sudo`/root, or they can remove the rules.

> Even transparent mode is host-based (HTTP Host / TLS SNI), not a full MITM —
> it does not decrypt HTTPS. A VPN, a phone hotspot, or a direct IP with a
> spoofed SNI can still get around it. For a hardened network, combine it with
> router-level filtering.

### Packages (.deb / .rpm)

Native packages are the supported way to deploy to many machines:

| Distro | Package | Install | Remove |
|---|---|---|---|
| **Linux Mint** (Debian/Ubuntu) | `.deb` | `sudo apt install ./csec_*.deb` | `sudo apt remove csec` |
| **Fedora KDE** | `.rpm` | `sudo dnf install ./csec-*.rpm` | `sudo dnf remove csec` |

Both are produced from a single [`packaging/nfpm.yaml`](packaging/nfpm.yaml)
with [nfpm](https://nfpm.goreleaser.com):

```
make            # build ./csec first
make deb        # -> dist/csec_<ver>_amd64.deb
make rpm        # -> dist/csec-<ver>.x86_64.rpm
make package    # both
```

The package lays down the binary (`/usr/bin/csec`), the block lists
(`/usr/share/csec/lists/`) and the systemd unit, but does **not** turn the
filter on. After installing the package, activate it (this enables the service
and sets the proxy):

```
sudo csec install
```

To switch the filter off again, run `sudo csec uninstall` **before** removing
the package (that fully restores the per-user desktop proxy). Removing the
package alone stops the service and clears the system-wide proxy.

> Sandboxed formats (Flatpak/Snap/AppImage) are intentionally **not** used:
> CSec installs a systemd service and edits system proxy settings, which those
> sandboxes forbid.

---

## Building from source

One codebase, two targets — the `Makefile` auto-detects the OS.

**Linux (native):**

```
make            # -> ./csec  (cc -std=gnu11 ... -pthread)
```

**Windows (MinGW-w64, cross-compilable from Linux):**

```
make windows    # -> csec.exe  (i686-w64-mingw32-gcc)
```

Or directly:

```
i686-w64-mingw32-gcc -std=gnu11 -O2 -o csec.exe csec.c proxy.c filter.c sha256.c \
  -static -lws2_32 -ladvapi32 -lcomctl32 -lcomdlg32 -lshell32 -mwindows
```

Shared sources: `proxy.c` (engine), `filter.c` (config + matching),
`sha256.c` (bundled hash — no OpenSSL/CryptoAPI dependency).

---

## License

GPL v3 — see [LICENSE](LICENSE).

Block lists: [The Block List Project](https://github.com/blocklistproject/Lists) — MIT License.
