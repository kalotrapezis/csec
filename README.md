# CSec — Classroom Web Filter

Blocks all websites except the ones you allow.
Runs as a Windows Service. Survives reboot. No internet connection required.

**Version:** 0.0.2 Alpha

---

## What it does

- **Whitelist mode** (default): every domain not on the list is blocked — HTTP and HTTPS
- **Blacklist mode**: every domain on the list is blocked — all other sites are allowed
- One entry covers the domain and all subdomains: `code.org` covers
  `studio.code.org`, `www.code.org`, etc.
- The filter stays active through reboot — students cannot escape by restarting
- Managed through a password-protected GUI (`csec.exe`)
- Lists are plain JSON files — easy to share via USB or a shared folder
- Built-in preset lists for gambling, adult content, social media, and online games

---

## Requirements

- Windows 7 SP1 or later (32-bit or 64-bit)
- Administrator rights to install and uninstall

---

## Setup

1. Copy `csec.exe` and `csec-config.json` to the same folder on the target machine
2. Open `csec.exe`
3. Click **Install Service** at the bottom of the window
4. Approve the Administrator prompt
5. The filter is now active — all sites blocked until you add domains
6. Log in with the default password `123456` and add your allowed domains

---

## Admin interface

Open `csec.exe` and log in to manage the domain list.

```
┌─ CSec 0.0.2 Alpha — Classroom Web Filter ────────────────────────────┐
│  Admin Access  [_________password_________]  [Login]             [?] │
│  Filter mode:  ● Whitelist — block all except list                    │
│                ○ Blacklist — allow all except list                    │
│  URL           [_________domain____________]  [Add]                   │
│                Enter domain only — e.g. code.org                      │
│ ┌───────────────────────────────────────────────────────────────────┐ │
│ │ Allowed URLs                                                      │ │
│ │ ☐  code.org                                                       │ │
│ │ ☐  googleapis.com                                                 │ │
│ └───────────────────────────────────────────────────────────────────┘ │
│  [Remove sel.] [Import JSON] [Export JSON] [Block Presets] [Chg Pwd]  │
│ ──────────────────────────────────────────────────────────────────── │
│  Service: running        [Install Service]  [Uninstall Service]       │
└───────────────────────────────────────────────────────────────────────┘
```

### Filter mode

After logging in, select how the list is applied:

| Mode | Behaviour |
|---|---|
| **Whitelist** (default) | Every site is blocked **unless** it is on the list |
| **Blacklist** | Every site is allowed **unless** it is on the list |

Switching mode saves immediately and takes effect without restarting the service.

**Recommended for most classrooms:** Whitelist — add only the sites students need,
everything else is blocked.

**For bring-your-own-device or unrestricted labs:** Blacklist — use with the preset
category lists to block gambling, adult content, and social media.

### Block Presets

Click **Block Presets** (log in first) to enable ready-made category lists:

| Category | Domains blocked | Includes |
|---|---|---|
| Gambling sites | 32 | bet365, DraftKings, PokerStars, stake.com, … |
| Adult content / OnlyFans | 23 | Pornhub, OnlyFans, Chaturbate, Fansly, … |
| Social media | 20 | TikTok, Instagram, X, Snapchat, Reddit, Discord, … |
| Online games | 18 | Roblox, Poki, CrazyGames, Friv, Miniclip, … |

Tick a category and click **OK** — domains are added to the list and the
service is notified immediately. Unticking removes them.

> **Note:** Presets work best in **Blacklist** mode. In Whitelist mode the
> checked domains are *allowed*, not blocked.

Domain lists are curated from:
- [The Block List Project](https://github.com/blocklistproject/Lists) — MIT License
- [StevenBlack/hosts](https://github.com/StevenBlack/hosts) — MIT License

### Adding domains

Type the domain — no `http://`, no `www.`, no path:

```
code.org
wordwall.net
khanacademy.org
```

You can also paste a full URL — CSec strips everything down to the domain
automatically.

### Known sites — automatic extras

Adding these domains also adds the supporting CDN and auth domains they need:

| You add | Also added automatically |
|---|---|
| `google.com` | googleapis.com, gstatic.com, googleusercontent.com, … |
| `youtube.com` | ytimg.com, googlevideo.com, youtu.be, … |
| `microsoft.com` | microsoftonline.com, live.com, windowsupdate.com, … |
| `office.com` | microsoft.com, microsoftonline.com, sharepoint.com, … |

### Removing domains

Tick the checkbox next to each domain you want to remove, then click
**Remove selected**.

### Sharing the allowlist

Build your list on the teacher machine, click **Export to JSON**, copy
the file to each student machine via USB or shared folder, then open
`csec.exe` on each and click **Import from JSON**.

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

## Building from source

Requires MinGW-w64 (`i686-w64-mingw32-gcc`).

```
make
```

Or manually:

```
i686-w64-mingw32-gcc -std=c99 -O2 -o csec.exe csec.c filter.c \
  -static -lws2_32 -ladvapi32 -lcrypt32 -lcomctl32 -lcomdlg32 -lshell32 -mwindows
```

---

## License

GPL v3 — see [LICENSE](LICENSE).
