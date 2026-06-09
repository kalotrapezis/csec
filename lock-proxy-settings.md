# Skill: Lock Windows Proxy Settings

## Purpose

Prevent users from changing proxy settings on Windows 10/11 using either Group Policy or Registry. Apply this skill when the user asks to lock, disable, or restrict proxy settings on Windows machines — for example in a school lab, corporate environment, or any shared PC setup.

---

## Context & Decision

There are two methods available. Choose based on the Windows edition:

- **Windows 10/11 Pro or Enterprise** → Use **Group Policy** (simpler and cleaner).
- **Windows 10/11 Home** → Use **Registry** (Group Policy Editor is not available on Home editions).

Both methods produce the same result: the proxy settings panel in the Settings app and in Internet Options becomes grayed out and inaccessible to users.

> **Important:** If you want to lock a *specific* proxy configuration in place, configure the proxy first, then apply the lock. Otherwise you are simply locking out an empty/default state.

---

## Method A — Group Policy (Pro/Enterprise only)

### Lock Proxy Settings

```
Path: User Configuration
      → Administrative Templates
      → Windows Components
      → Internet Explorer
Policy: "Prevent changing proxy settings"
Action: Set to Enabled
```

**Steps for Claude Code to automate (PowerShell):**

```powershell
# Requires running as Administrator
# Sets the Group Policy registry equivalent (same key gpedit.msc writes)
$regPath = "HKCU:\Software\Policies\Microsoft\Internet Explorer\Control Panel"

if (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}

Set-ItemProperty -Path $regPath -Name "Proxy" -Value 1 -Type DWord
Write-Host "Proxy settings locked via Group Policy registry key."
```

### Unlock Proxy Settings (Revert)

In Group Policy Editor: set the same policy back to **Not Configured**.

**PowerShell equivalent:**

```powershell
$regPath = "HKCU:\Software\Policies\Microsoft\Internet Explorer\Control Panel"
Set-ItemProperty -Path $regPath -Name "Proxy" -Value 0 -Type DWord
Write-Host "Proxy settings unlocked."
```

---

## Method B — Registry (All editions, including Home)

### Lock Proxy Settings

Registry path to create/modify:

```
HKEY_CURRENT_USER\Software\Policies\Microsoft\Internet Explorer\Control Panel
```

Key to set:

| Name  | Type         | Value |
|-------|--------------|-------|
| Proxy | DWORD 32-bit | 1     |

**Steps for Claude Code to automate (PowerShell):**

```powershell
# Step 1: Ensure parent keys exist
$iePath = "HKCU:\Software\Policies\Microsoft\Internet Explorer"
$cpPath  = "$iePath\Control Panel"

if (-not (Test-Path $iePath)) {
    New-Item -Path $iePath -Force | Out-Null
}
if (-not (Test-Path $cpPath)) {
    New-Item -Path $cpPath -Force | Out-Null
}

# Step 2: Create and set the Proxy DWORD
Set-ItemProperty -Path $cpPath -Name "Proxy" -Value 1 -Type DWord

Write-Host "Proxy settings locked. Please restart the computer for changes to take effect."
```

### Unlock Proxy Settings (Revert)

```powershell
$cpPath = "HKCU:\Software\Policies\Microsoft\Internet Explorer\Control Panel"
Set-ItemProperty -Path $cpPath -Name "Proxy" -Value 0 -Type DWord
Write-Host "Proxy settings unlocked. Please restart."
```

Or delete the key entirely to fully remove the restriction:

```powershell
$cpPath = "HKCU:\Software\Policies\Microsoft\Internet Explorer\Control Panel"
Remove-ItemProperty -Path $cpPath -Name "Proxy" -ErrorAction SilentlyContinue
Write-Host "Proxy key removed."
```

---

## Scope Notes

- Both methods apply to the **current user** (`HKEY_CURRENT_USER`). To lock proxy settings for **all users**, the registry path would need to be under `HKEY_LOCAL_MACHINE` — but that requires a different Group Policy path and additional testing.
- After applying the Registry method, **a system restart is required** for the change to take effect.
- The Group Policy method takes effect immediately or after a `gpupdate /force` command.
- These methods lock the Settings app (`Network & Internet → Proxy`) and also the legacy **Internet Options** panel.

---

## Quick Verification

After applying the lock, verify by running:

```powershell
$cpPath = "HKCU:\Software\Policies\Microsoft\Internet Explorer\Control Panel"
$val = Get-ItemPropertyValue -Path $cpPath -Name "Proxy" -ErrorAction SilentlyContinue
if ($val -eq 1) {
    Write-Host "LOCKED: Proxy settings are restricted."
} elseif ($val -eq 0) {
    Write-Host "UNLOCKED: Proxy settings are accessible."
} else {
    Write-Host "Key not found — proxy settings are not restricted."
}
```

---

## Sources

- top-password.com — *2 Methods to Prevent Users from Changing Proxy Settings in Windows 11/10*
- windowscentral.com — *How to prevent users from changing proxy settings on Windows 10*
