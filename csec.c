/*
 * csec.exe  —  Classroom Web Filter  (Windows frontend)
 *
 * Service install/uninstall, the Win32 admin GUI, and system-proxy
 * enforcement via the registry. The actual filtering proxy lives in the
 * shared, cross-platform engine (proxy.c); the Linux frontend is csec_posix.c.
 *
 * Usage:
 *   csec.exe --install     Install and start the filter service (run as Admin)
 *   csec.exe --uninstall   Stop and remove the service (run as Admin)
 *   csec.exe               Open admin UI  /  run as service (if started by SCM)
 */

#include "compat.h"        /* winsock2 + windows.h */
#include <commctrl.h>
#include <commdlg.h>
#include <shellapi.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "proxy.h"         /* shared engine + filter.h + SERVICE_NAME/VERSION/PROXY_PORT
                              + g_cfg/g_cfg_lock/g_running/g_config_path/g_lists_dir */

/* =========================================================================
   Shared: config path, stringify
   ========================================================================= */

#define STR_(x) #x
#define STR(x)  STR_(x)

void resolve_config_path(void) {
    char exe[MAX_PATH];
    GetModuleFileNameA(NULL, exe, MAX_PATH);
    char *sep = strrchr(exe, '\\');
    if (sep) *(sep + 1) = '\0';
    snprintf(g_config_path, MAX_PATH, "%s%s", exe, CONFIG_FILE);
    snprintf(g_lists_dir,   MAX_PATH, "%slists", exe);
}

/* =========================================================================
   Registry — set / clear system proxy
   ========================================================================= */

#define INET_KEY     "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings"
#define POLICY_KEY   "SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings"
#define HKLM_INET    "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings"
#define IE_CP_KEY    "Software\\Policies\\Microsoft\\Internet Explorer\\Control Panel"

static void registry_set_proxy(int enable) {
    const char *proxy = "127.0.0.1:" STR(PROXY_PORT);
    /* Bypass all RFC1918 LAN ranges, loopback, link-local and intranet names
       so LAN apps (e.g. ClassGame on 192.168.x.x:3000) talk directly. */
    const char *bypass =
        "<local>;localhost;127.*;"
        "10.*;"
        "192.168.*;"
        "172.16.*;172.17.*;172.18.*;172.19.*;"
        "172.20.*;172.21.*;172.22.*;172.23.*;"
        "172.24.*;172.25.*;172.26.*;172.27.*;"
        "172.28.*;172.29.*;172.30.*;172.31.*;"
        "169.254.*";

    /* HKCU — for the current user (correct when called from --install) */
    HKEY hk;
    if (RegOpenKeyExA(HKEY_CURRENT_USER, INET_KEY, 0, KEY_SET_VALUE, &hk) == ERROR_SUCCESS) {
        DWORD v = enable ? 1 : 0;
        RegSetValueExA(hk, "ProxyEnable", 0, REG_DWORD, (const BYTE *)&v, sizeof(v));
        if (enable) {
            RegSetValueExA(hk, "ProxyServer", 0, REG_SZ,
                           (const BYTE *)proxy, (DWORD)strlen(proxy) + 1);
            RegSetValueExA(hk, "ProxyOverride", 0, REG_SZ,
                           (const BYTE *)bypass, (DWORD)strlen(bypass) + 1);
        } else {
            RegDeleteValueA(hk, "ProxyServer");
            RegDeleteValueA(hk, "ProxyOverride");
        }
        RegCloseKey(hk);
    }

    /* HKLM Policies — system-wide, writable by SYSTEM so the service can enforce it */
    if (enable) {
        HKEY hp;
        if (RegCreateKeyExA(HKEY_LOCAL_MACHINE, POLICY_KEY,
                            0, NULL, 0, KEY_SET_VALUE, NULL, &hp, NULL) == ERROR_SUCCESS) {
            DWORD one = 1;
            RegSetValueExA(hp, "ProxyEnable", 0, REG_DWORD, (const BYTE *)&one, sizeof(one));
            RegSetValueExA(hp, "ProxyServer",  0, REG_SZ,
                           (const BYTE *)proxy, (DWORD)strlen(proxy) + 1);
            RegSetValueExA(hp, "ProxyOverride", 0, REG_SZ,
                           (const BYTE *)bypass, (DWORD)strlen(bypass) + 1);
            RegCloseKey(hp);
        }
        /* ProxySettingsPerUser=0 makes Windows use HKLM proxy for all accounts */
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, HKLM_INET, 0, KEY_SET_VALUE, &hk) == ERROR_SUCCESS) {
            DWORD zero = 0;
            RegSetValueExA(hk, "ProxySettingsPerUser", 0, REG_DWORD, (const BYTE *)&zero, sizeof(zero));
            RegCloseKey(hk);
        }
    } else {
        RegDeleteKeyA(HKEY_LOCAL_MACHINE, POLICY_KEY);
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, HKLM_INET, 0, KEY_SET_VALUE, &hk) == ERROR_SUCCESS) {
            RegDeleteValueA(hk, "ProxySettingsPerUser");
            RegCloseKey(hk);
        }
    }
}

/* Apply or remove the IE Control Panel "Proxy" policy lock.
   When lock=1, the proxy settings panel is grayed out for all users.
   Applies to: HKCU (admin), every loaded HKU hive (active users), HKU\.DEFAULT. */
static void registry_lock_proxy(int lock) {
    const char *sub = IE_CP_KEY;
    DWORD val = lock ? 1 : 0;

    /* Helper: set Proxy=val in hive\sub, creating keys as needed */
    HKEY roots[2] = { HKEY_CURRENT_USER, HKEY_USERS };
    int  nroots    = 2;

    /* HKCU — the admin user performing install/uninstall */
    {
        HKEY hk;
        if (RegCreateKeyExA(HKEY_CURRENT_USER, sub,
                            0, NULL, 0, KEY_SET_VALUE, NULL, &hk, NULL) == ERROR_SUCCESS) {
            RegSetValueExA(hk, "Proxy", 0, REG_DWORD, (const BYTE *)&val, sizeof(val));
            RegCloseKey(hk);
        }
    }

    /* All loaded user hives under HKU (catches any currently logged-in accounts) */
    {
        DWORD i = 0;
        char  sid[256];
        DWORD sid_len = sizeof(sid);
        while (RegEnumKeyExA(HKEY_USERS, i++, sid, &sid_len,
                             NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
            sid_len = sizeof(sid);
            /* Skip .DEFAULT here — handled separately below */
            if (strcmp(sid, ".DEFAULT") == 0) continue;
            /* Skip _Classes sub-keys (e.g. S-1-5-18_Classes) */
            if (strstr(sid, "_Classes")) continue;

            char full[512];
            snprintf(full, sizeof(full), "%s\\%s", sid, sub);
            HKEY hk;
            if (RegCreateKeyExA(HKEY_USERS, full,
                                0, NULL, 0, KEY_SET_VALUE, NULL, &hk, NULL) == ERROR_SUCCESS) {
                RegSetValueExA(hk, "Proxy", 0, REG_DWORD, (const BYTE *)&val, sizeof(val));
                RegCloseKey(hk);
            }
        }
    }

    /* HKU\.DEFAULT — applies to future/new accounts and the welcome screen */
    {
        char full[512];
        snprintf(full, sizeof(full), ".DEFAULT\\%s", sub);
        HKEY hk;
        if (RegCreateKeyExA(HKEY_USERS, full,
                            0, NULL, 0, KEY_SET_VALUE, NULL, &hk, NULL) == ERROR_SUCCESS) {
            RegSetValueExA(hk, "Proxy", 0, REG_DWORD, (const BYTE *)&val, sizeof(val));
            RegCloseKey(hk);
        }
    }

    (void)roots; (void)nroots;
}

/* Hook called by the shared engine (proxy_run) on every service start:
   re-assert the system proxy. The settings-panel lock is applied separately
   in ServiceMain / svc_install. */
void platform_enforce_proxy(int enable) {
    registry_set_proxy(enable);
}

/* =========================================================================
   Windows Service plumbing
   ========================================================================= */

static SERVICE_STATUS        g_svc;
static SERVICE_STATUS_HANDLE g_svc_h;

static void WINAPI svc_ctrl(DWORD ctrl) {
    if (ctrl == SERVICE_CONTROL_STOP || ctrl == SERVICE_CONTROL_SHUTDOWN) {
        g_running = 0;
        g_svc.dwCurrentState = SERVICE_STOP_PENDING;
        SetServiceStatus(g_svc_h, &g_svc);
    } else if (ctrl == SERVICE_CONTROL_PARAMCHANGE) {
        cfg_reload();
    }
}

static void WINAPI ServiceMain(DWORD argc, LPSTR *argv) {
    (void)argc; (void)argv;
    InitializeCriticalSection(&g_cfg_lock);
    resolve_config_path();
    cfg_reload();
    registry_lock_proxy(1); /* re-enforce lock on every reboot/service start */

    g_svc_h = RegisterServiceCtrlHandlerA(SERVICE_NAME, svc_ctrl);
    if (!g_svc_h) return;

    g_svc.dwServiceType      = SERVICE_WIN32_OWN_PROCESS;
    g_svc.dwCurrentState     = SERVICE_RUNNING;
    g_svc.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN |
                               SERVICE_ACCEPT_PARAMCHANGE;
    SetServiceStatus(g_svc_h, &g_svc);

    proxy_run();

    registry_set_proxy(0);
    g_svc.dwCurrentState = SERVICE_STOPPED;
    SetServiceStatus(g_svc_h, &g_svc);
    DeleteCriticalSection(&g_cfg_lock);
}

/* =========================================================================
   Install / Uninstall  (run as Administrator from command line)
   ========================================================================= */

static int svc_install(void) {
    char path[MAX_PATH];
    GetModuleFileNameA(NULL, path, MAX_PATH);

    SC_HANDLE scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    if (!scm) {
        MessageBoxA(NULL, "Cannot open Service Manager.\nRun as Administrator.",
                    "CSec", MB_OK | MB_ICONERROR);
        return 1;
    }
    SC_HANDLE svc = CreateServiceA(scm, SERVICE_NAME, "CSec Web Filter",
        SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS,
        SERVICE_AUTO_START, SERVICE_ERROR_NORMAL,
        path, NULL, NULL, NULL, NULL, NULL);

    if (!svc) {
        DWORD err = GetLastError();
        char msg[128];
        if (err == ERROR_SERVICE_EXISTS)
            strcpy(msg, "Service already installed.\nRun --uninstall first.");
        else
            sprintf(msg, "Failed to install service (error %lu).", err);
        MessageBoxA(NULL, msg, "CSec", MB_OK | MB_ICONERROR);
        CloseServiceHandle(scm); return 1;
    }

    SC_ACTION actions[3] = {{SC_ACTION_RESTART,2000},{SC_ACTION_RESTART,5000},{SC_ACTION_RESTART,10000}};
    SERVICE_FAILURE_ACTIONSA fa = {0};
    fa.dwResetPeriod = INFINITE; fa.cActions = 3; fa.lpsaActions = actions;
    ChangeServiceConfig2A(svc, SERVICE_CONFIG_FAILURE_ACTIONS, &fa);

    registry_set_proxy(1);   /* configure proxy (HKCU + HKLM) */
    registry_lock_proxy(1);  /* lock the settings panel for all users */
    StartServiceA(svc, 0, NULL);
    CloseServiceHandle(svc); CloseServiceHandle(scm);

    char msg[256];
    sprintf(msg, "CSec installed and started.\n\nConfig: %s\n\nDefault password: 123456", g_config_path);
    MessageBoxA(NULL, msg, "CSec", MB_OK | MB_ICONINFORMATION);
    return 0;
}

static int svc_uninstall(void) {
    SC_HANDLE scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!scm) {
        MessageBoxA(NULL, "Cannot open Service Manager.\nRun as Administrator.",
                    "CSec", MB_OK | MB_ICONERROR);
        return 1;
    }
    SC_HANDLE svc = OpenServiceA(scm, SERVICE_NAME,
                                 SERVICE_STOP | DELETE | SERVICE_QUERY_STATUS);
    if (!svc) {
        MessageBoxA(NULL, "Service not found.", "CSec", MB_OK | MB_ICONERROR);
        CloseServiceHandle(scm); return 1;
    }
    SERVICE_STATUS st;
    ControlService(svc, SERVICE_CONTROL_STOP, &st);
    for (int i = 0; i < 50; i++) {
        if (!QueryServiceStatus(svc, &st) || st.dwCurrentState == SERVICE_STOPPED) break;
        Sleep(100);
    }
    DeleteService(svc);
    CloseServiceHandle(svc); CloseServiceHandle(scm);
    registry_set_proxy(0);   /* restore proxy (remove HKCU/HKLM entries) */
    registry_lock_proxy(0);  /* unlock the settings panel */
    MessageBoxA(NULL, "CSec removed.\nInternet access restored.", "CSec", MB_OK | MB_ICONINFORMATION);
    return 0;
}

/* =========================================================================
   Admin GUI
   ========================================================================= */

#define ID_EDIT_PASS  101
#define ID_BTN_LOGIN  102
#define ID_EDIT_URL   103
#define ID_BTN_ADD    104
#define ID_LV         105
#define ID_BTN_REMOVE 106
#define ID_BTN_IMPORT 107
#define ID_BTN_EXPORT 108
#define ID_BTN_CHGPWD   109
#define ID_BTN_HELP     110
#define ID_BTN_INSTALL  111
#define ID_BTN_UNINSTALL 112
#define ID_STATIC_SVC   113
#define ID_RADIO_WHITE  114
#define ID_RADIO_BLACK  115
#define ID_BTN_PRESETS  116
#define ID_CHK_SAFESEARCH 117
#define ID_RADIO_YT_OFF      118
#define ID_RADIO_YT_MODERATE 119
#define ID_RADIO_YT_STRICT   120

/* Window width/height (client area) */
#define WIN_W 640
#define WIN_H 521

static HWND g_hwnd;
static HWND g_edit_pass, g_btn_login;
static HWND g_radio_white, g_radio_black;
static HWND g_chk_safesearch;
static HWND g_radio_yt_off, g_radio_yt_mod, g_radio_yt_strict;
static HWND g_edit_url,  g_btn_add;
static HWND g_lv;
static HWND g_btn_remove, g_btn_import, g_btn_export, g_btn_presets, g_btn_chgpwd;
static HWND g_btn_install, g_btn_uninstall, g_static_svc;
static CSec_Config g_acfg;   /* admin copy of config */
static int  g_logged_in = 0;

/* -------------------------------------------------------------------------
   Elevation helpers
   ---------------------------------------------------------------------- */

static int is_admin(void) {
    BOOL admin = FALSE;
    HANDLE token;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        TOKEN_ELEVATION elev;
        DWORD sz = sizeof(elev);
        if (GetTokenInformation(token, TokenElevation, &elev, sz, &sz))
            admin = elev.TokenIsElevated;
        CloseHandle(token);
    }
    return admin;
}

/* Re-launch csec.exe with arg under UAC elevation and wait for it to finish */
static void run_elevated(const char *arg) {
    char path[MAX_PATH];
    GetModuleFileNameA(NULL, path, MAX_PATH);
    SHELLEXECUTEINFOA sei = {0};
    sei.cbSize       = sizeof(sei);
    sei.fMask        = SEE_MASK_NOCLOSEPROCESS;
    sei.hwnd         = g_hwnd;
    sei.lpVerb       = "runas";
    sei.lpFile       = path;
    sei.lpParameters = arg;
    sei.nShow        = SW_SHOW;
    if (ShellExecuteExA(&sei) && sei.hProcess) {
        WaitForSingleObject(sei.hProcess, INFINITE);
        CloseHandle(sei.hProcess);
    }
}

/* -------------------------------------------------------------------------
   Service status label
   ---------------------------------------------------------------------- */

static void update_svc_label(void) {
    if (!g_static_svc) return;
    SC_HANDLE scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
    if (!scm) { SetWindowTextA(g_static_svc, "Service: unknown"); return; }
    SC_HANDLE svc = OpenServiceA(scm, SERVICE_NAME, SERVICE_QUERY_STATUS);
    if (!svc) {
        CloseServiceHandle(scm);
        SetWindowTextA(g_static_svc, "Service: not installed");
        return;
    }
    SERVICE_STATUS st;
    QueryServiceStatus(svc, &st);
    CloseServiceHandle(svc); CloseServiceHandle(scm);
    switch (st.dwCurrentState) {
        case SERVICE_RUNNING:      SetWindowTextA(g_static_svc, "Service: running"); break;
        case SERVICE_STOPPED:      SetWindowTextA(g_static_svc, "Service: stopped"); break;
        case SERVICE_START_PENDING:SetWindowTextA(g_static_svc, "Service: starting..."); break;
        case SERVICE_STOP_PENDING: SetWindowTextA(g_static_svc, "Service: stopping..."); break;
        default:                   SetWindowTextA(g_static_svc, "Service: installed"); break;
    }
}

static void do_install_service(void) {
    if (is_admin()) {
        svc_install();
    } else {
        run_elevated("--install");
    }
    update_svc_label();
}

static void do_uninstall_service(void) {
    if (!g_logged_in) {
        MessageBoxA(g_hwnd,
            "Log in with the admin password first before uninstalling.",
            "CSec", MB_OK | MB_ICONINFORMATION);
        SetFocus(g_edit_pass);
        return;
    }
    int r = MessageBoxA(g_hwnd,
        "This will stop the filter and restore full internet access.\n\nAre you sure?",
        "CSec — Uninstall Service", MB_YESNO | MB_ICONWARNING);
    if (r != IDYES) return;
    if (is_admin()) {
        svc_uninstall();
    } else {
        run_elevated("--uninstall");
    }
    update_svc_label();
}

/* Tell the running service to reload config */
static void notify_service(void) {
    SC_HANDLE scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
    if (!scm) return;
    SC_HANDLE svc = OpenServiceA(scm, SERVICE_NAME, SERVICE_USER_DEFINED_CONTROL);
    if (svc) {
        SERVICE_STATUS st;
        ControlService(svc, SERVICE_CONTROL_PARAMCHANGE, &st);
        CloseServiceHandle(svc);
    }
    CloseServiceHandle(scm);
}

static void lv_update_header(void) {
    LVCOLUMNA col = {0};
    col.mask    = LVCF_TEXT;
    col.pszText = g_acfg.blacklist_mode ? "Blocked URLs" : "Allowed URLs";
    ListView_SetColumn(g_lv, 0, &col);
}

static void lv_refresh(void) {
    lv_update_header();
    ListView_DeleteAllItems(g_lv);
    for (int i = 0; i < g_acfg.count; i++) {
        LVITEMA it = {0};
        it.mask    = LVIF_TEXT;
        it.iItem   = i;
        it.pszText = g_acfg.domains[i];
        ListView_InsertItem(g_lv, &it);
    }
}

/* -------------------------------------------------------------------------
   Block Presets dialog — dynamically lists .txt files from lists\ folder
   ---------------------------------------------------------------------- */

#define ID_LV_LISTS 300

static BOOL g_preset_done;

/* Read Title and Entries count from the comment header of a list file. */
static void read_list_header(const char *path, char *title, int title_len, int *entries) {
    *entries = -1;
    title[0] = '\0';
    FILE *f = fopen(path, "r");
    if (!f) return;
    char line[256];
    while (fgets(line, sizeof(line), f)) {
        if (line[0] != '#') break;
        if (strncmp(line, "# Title:", 8) == 0) {
            const char *s = line + 8;
            while (*s == ' ') s++;
            strncpy(title, s, title_len - 1);
            title[title_len - 1] = '\0';
            char *nl = strchr(title, '\n'); if (nl) *nl = '\0';
            char *cr = strchr(title, '\r'); if (cr) *cr = '\0';
        }
        if (strncmp(line, "# Entries:", 10) == 0) {
            /* "2,500" → strip commas */
            const char *s = line + 10;
            int v = 0;
            while (*s) {
                if (*s >= '0' && *s <= '9') v = v * 10 + (*s - '0');
                else if (*s == '\n' || *s == '\r') break;
                s++;
            }
            *entries = v;
        }
        if (title[0] && *entries >= 0) break;
    }
    fclose(f);
}

/* Returns 1 if name is in g_acfg.enabled_lists (space-separated). */
static int list_is_enabled(const char *name) {
    const char *p = g_acfg.enabled_lists;
    size_t nlen = strlen(name);
    while (*p) {
        while (*p == ' ') p++;
        if (strncmp(p, name, nlen) == 0 && (p[nlen] == ' ' || p[nlen] == '\0'))
            return 1;
        while (*p && *p != ' ') p++;
    }
    return 0;
}

static LRESULT CALLBACK PresetProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    static HWND lv;
    switch (msg) {
        case WM_CREATE: {
            HINSTANCE hi = ((CREATESTRUCTA *)lp)->hInstance;
            CreateWindowA("STATIC",
                "Select lists from your lists\\ folder to use for blocking.",
                WS_CHILD|WS_VISIBLE, 10, 8, 460, 16, hwnd, NULL, hi, NULL);
            CreateWindowA("STATIC",
                "Only active in Blacklist mode. Large lists load when the service starts.",
                WS_CHILD|WS_VISIBLE, 10, 26, 460, 16, hwnd, NULL, hi, NULL);

            lv = CreateWindowExA(WS_EX_CLIENTEDGE, WC_LISTVIEWA, "",
                WS_CHILD|WS_VISIBLE|LVS_REPORT|LVS_SHOWSELALWAYS,
                10, 50, 460, 310, hwnd, (HMENU)ID_LV_LISTS, hi, NULL);
            ListView_SetExtendedListViewStyle(lv,
                LVS_EX_CHECKBOXES | LVS_EX_FULLROWSELECT);

            LVCOLUMNA c1 = {0};
            c1.mask=LVCF_TEXT|LVCF_WIDTH; c1.cx=240; c1.pszText="Category";
            ListView_InsertColumn(lv, 0, &c1);
            LVCOLUMNA c2 = {0};
            c2.mask=LVCF_TEXT|LVCF_WIDTH; c2.cx=105; c2.pszText="Domains";
            ListView_InsertColumn(lv, 1, &c2);
            LVCOLUMNA c3 = {0};
            c3.mask=LVCF_TEXT|LVCF_WIDTH; c3.cx=100; c3.pszText="File";
            ListView_InsertColumn(lv, 2, &c3);

            /* Enumerate *.txt files in lists\ folder */
            char search[MAX_PATH];
            snprintf(search, MAX_PATH, "%s\\*.txt", g_lists_dir);
            WIN32_FIND_DATAA ffd;
            HANDLE h = FindFirstFileA(search, &ffd);
            if (h != INVALID_HANDLE_VALUE) {
                int row = 0;
                do {
                    char filepath[MAX_PATH];
                    snprintf(filepath, MAX_PATH, "%s\\%s", g_lists_dir, ffd.cFileName);

                    char title[128]; int entries;
                    read_list_header(filepath, title, sizeof(title), &entries);
                    if (!title[0]) {
                        strncpy(title, ffd.cFileName, sizeof(title)-1);
                        char *dot = strrchr(title, '.'); if (dot) *dot = '\0';
                    }

                    LVITEMA it = {0};
                    it.mask    = LVIF_TEXT;
                    it.iItem   = row;
                    it.pszText = title;
                    ListView_InsertItem(lv, &it);

                    char cnt_buf[32];
                    if (entries >= 0) {
                        int e = entries;
                        if (e >= 1000000)
                            sprintf(cnt_buf, "%d.%dM", e/1000000, (e%1000000)/100000);
                        else if (e >= 1000)
                            sprintf(cnt_buf, "%d,%03d", e/1000, e%1000);
                        else
                            sprintf(cnt_buf, "%d", e);
                    } else {
                        strcpy(cnt_buf, "?");
                    }
                    ListView_SetItemText(lv, row, 1, cnt_buf);
                    ListView_SetItemText(lv, row, 2, ffd.cFileName);

                    /* Strip .txt for enabled_lists matching */
                    char name[64];
                    strncpy(name, ffd.cFileName, sizeof(name)-1);
                    char *dot = strrchr(name, '.'); if (dot) *dot = '\0';
                    if (list_is_enabled(name))
                        ListView_SetCheckState(lv, row, TRUE);

                    row++;
                } while (FindNextFileA(h, &ffd));
                FindClose(h);
            }

            if (ListView_GetItemCount(lv) == 0) {
                CreateWindowA("STATIC",
                    "No .txt files found in lists\\ folder.\r\n"
                    "Place list files next to csec.exe in a lists\\ subfolder.",
                    WS_CHILD|WS_VISIBLE, 10, 170, 460, 40, hwnd, NULL, hi, NULL);
            }

            CreateWindowA("BUTTON", "OK", WS_CHILD|WS_VISIBLE|BS_DEFPUSHBUTTON,
                170, 372, 80, 28, hwnd, (HMENU)IDOK, hi, NULL);
            CreateWindowA("BUTTON", "Cancel", WS_CHILD|WS_VISIBLE,
                270, 372, 80, 28, hwnd, (HMENU)IDCANCEL, hi, NULL);
            return 0;
        }
        case WM_COMMAND:
            if (LOWORD(wp) == IDOK && HIWORD(wp) == BN_CLICKED) {
                /* Build new enabled_lists string from checked rows */
                char new_lists[512] = {0};
                int count = ListView_GetItemCount(lv);
                for (int i = 0; i < count; i++) {
                    if (!ListView_GetCheckState(lv, i)) continue;
                    char file[64];
                    ListView_GetItemText(lv, i, 2, file, sizeof(file));
                    char *dot = strrchr(file, '.'); if (dot) *dot = '\0';
                    if (new_lists[0]) strncat(new_lists, " ", sizeof(new_lists)-strlen(new_lists)-1);
                    strncat(new_lists, file, sizeof(new_lists)-strlen(new_lists)-1);
                }
                strncpy(g_acfg.enabled_lists, new_lists, sizeof(g_acfg.enabled_lists)-1);
                config_save(&g_acfg, g_config_path);
                notify_service();
                DestroyWindow(hwnd);
            } else if (LOWORD(wp) == IDCANCEL && HIWORD(wp) == BN_CLICKED) {
                DestroyWindow(hwnd);
            }
            break;
        case WM_DESTROY:
            g_preset_done = TRUE;
            break;
    }
    return DefWindowProcA(hwnd, msg, wp, lp);
}

static void do_presets(void) {
    HINSTANCE hi = GetModuleHandleA(NULL);
    WNDCLASSA wc = {0};
    wc.lpfnWndProc   = PresetProc;
    wc.hInstance     = hi;
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    wc.hCursor       = LoadCursorA(NULL, IDC_ARROW);
    wc.lpszClassName = "CSec_Presets";
    RegisterClassA(&wc);

    g_preset_done = FALSE;
    RECT r; GetWindowRect(g_hwnd, &r);
    int pw = 500, ph = 450;
    int px = r.left + (r.right  - r.left - pw) / 2;
    int py = r.top  + (r.bottom - r.top  - ph) / 2;

    HWND dlg = CreateWindowA("CSec_Presets", "Block Lists",
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_THICKFRAME,
        px, py, pw, ph, g_hwnd, NULL, hi, NULL);
    ShowWindow(dlg, SW_SHOW);

    EnableWindow(g_hwnd, FALSE);
    MSG m;
    while (!g_preset_done) {
        BOOL ret = GetMessage(&m, NULL, 0, 0);
        if (ret <= 0) { if (ret == 0) PostQuitMessage((int)m.wParam); break; }
        TranslateMessage(&m); DispatchMessage(&m);
    }
    EnableWindow(g_hwnd, TRUE);
    SetForegroundWindow(g_hwnd);
}

static void sync_youtube_radios(int mode) {
    SendMessage(g_radio_yt_off,    BM_SETCHECK, mode == 0 ? BST_CHECKED : BST_UNCHECKED, 0);
    SendMessage(g_radio_yt_mod,    BM_SETCHECK, mode == 1 ? BST_CHECKED : BST_UNCHECKED, 0);
    SendMessage(g_radio_yt_strict, BM_SETCHECK, mode == 2 ? BST_CHECKED : BST_UNCHECKED, 0);
}

static void enable_controls(int on) {
    EnableWindow(g_radio_white, on);
    EnableWindow(g_radio_black, on);
    EnableWindow(g_chk_safesearch, on);
    EnableWindow(g_radio_yt_off,    on);
    EnableWindow(g_radio_yt_mod,    on);
    EnableWindow(g_radio_yt_strict, on);
    EnableWindow(g_edit_url,   on);
    EnableWindow(g_btn_add,    on);
    EnableWindow(g_lv,         on);
    EnableWindow(g_btn_remove,  on);
    EnableWindow(g_btn_import,  on);
    EnableWindow(g_btn_export,  on);
    EnableWindow(g_btn_presets, on);
    EnableWindow(g_btn_chgpwd,  on);
}

static void do_login(void) {
    char pw[128], hash[65];
    GetWindowTextA(g_edit_pass, pw, sizeof(pw));
    sha256_hex(pw, hash);
    if (strcmp(hash, g_acfg.admin_hash) != 0) {
        MessageBoxA(g_hwnd, "Wrong password.", "CSec", MB_OK | MB_ICONERROR);
        SetWindowTextA(g_edit_pass, "");
        SetFocus(g_edit_pass);
        return;
    }
    g_logged_in = 1;
    EnableWindow(g_edit_pass, FALSE);
    EnableWindow(g_btn_login, FALSE);
    enable_controls(TRUE);
    /* Sync radio buttons to saved mode */
    SendMessage(g_radio_white, BM_SETCHECK,
                g_acfg.blacklist_mode ? BST_UNCHECKED : BST_CHECKED, 0);
    SendMessage(g_radio_black, BM_SETCHECK,
                g_acfg.blacklist_mode ? BST_CHECKED : BST_UNCHECKED, 0);
    /* Sync SafeSearch checkbox + YouTube radios to saved state */
    SendMessage(g_chk_safesearch, BM_SETCHECK,
                g_acfg.safesearch ? BST_CHECKED : BST_UNCHECKED, 0);
    sync_youtube_radios(g_acfg.youtube_mode);
    lv_refresh();
    SetFocus(g_edit_url);
}

static void do_add(void) {
    char raw[MAX_DOMAIN_LEN], domain[MAX_DOMAIN_LEN];
    GetWindowTextA(g_edit_url, raw, sizeof(raw));
    if (!raw[0]) return;

    normalize_domain(raw, domain, sizeof(domain));
    if (!domain[0]) return;

    if (!domain_add(&g_acfg, domain)) {
        MessageBoxA(g_hwnd, "Already in list or list full.", "CSec", MB_OK | MB_ICONINFORMATION);
        return;
    }

    /* Auto-add bundle extras if this is a known site */
    char bundle_msg[512] = {0};
    int bi = bundle_find(domain);
    if (bi >= 0) {
        strcat(bundle_msg, "Also added required domains for ");
        strcat(bundle_msg, domain);
        strcat(bundle_msg, ":\r\n\r\n");
        for (int j = 0; BUNDLES[bi].extras[j]; j++) {
            if (domain_add(&g_acfg, BUNDLES[bi].extras[j])) {
                strcat(bundle_msg, "  + ");
                strcat(bundle_msg, BUNDLES[bi].extras[j]);
                strcat(bundle_msg, "\r\n");
            }
        }
    }

    if (config_save(&g_acfg, g_config_path)) {
        notify_service();
        lv_refresh();
        SetWindowTextA(g_edit_url, "");
        SetFocus(g_edit_url);
        if (bundle_msg[0])
            MessageBoxA(g_hwnd, bundle_msg, "CSec — Extra domains added", MB_OK | MB_ICONINFORMATION);
    } else {
        MessageBoxA(g_hwnd, "Added but failed to save config.", "CSec", MB_OK | MB_ICONWARNING);
    }
}

static void do_remove_selected(void) {
    int count = ListView_GetItemCount(g_lv);
    int removed = 0;
    /* Iterate backwards so indices don't shift during removal */
    for (int i = count - 1; i >= 0; i--) {
        if (ListView_GetCheckState(g_lv, i)) {
            domain_remove(&g_acfg, g_acfg.domains[i]);
            removed++;
        }
    }
    if (removed == 0) {
        MessageBoxA(g_hwnd, "No domains checked.", "CSec", MB_OK | MB_ICONINFORMATION);
        return;
    }
    if (config_save(&g_acfg, g_config_path)) notify_service();
    lv_refresh();
}

static void do_import(void) {
    OPENFILENAMEA ofn = {0};
    char path[MAX_PATH] = {0};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner   = g_hwnd;
    ofn.lpstrFilter = "JSON Files\0*.json\0All Files\0*.*\0";
    ofn.lpstrFile   = path;
    ofn.nMaxFile    = MAX_PATH;
    ofn.Flags       = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
    ofn.lpstrDefExt = "json";
    if (!GetOpenFileNameA(&ofn)) return;

    CSec_Config tmp;
    if (!config_load(&tmp, path)) {
        MessageBoxA(g_hwnd, "Failed to load file.", "CSec", MB_OK | MB_ICONERROR);
        return;
    }
    int added = 0;
    for (int i = 0; i < tmp.count; i++)
        if (domain_add(&g_acfg, tmp.domains[i])) added++;
    config_save(&g_acfg, g_config_path);
    notify_service();
    lv_refresh();
    char msg[64];
    sprintf(msg, "Imported %d new domain(s). Total: %d", added, g_acfg.count);
    MessageBoxA(g_hwnd, msg, "CSec", MB_OK | MB_ICONINFORMATION);
}

static void do_export(void) {
    OPENFILENAMEA ofn = {0};
    char path[MAX_PATH] = {0};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner   = g_hwnd;
    ofn.lpstrFilter = "JSON Files\0*.json\0All Files\0*.*\0";
    ofn.lpstrFile   = path;
    ofn.nMaxFile    = MAX_PATH;
    ofn.Flags       = OFN_OVERWRITEPROMPT;
    ofn.lpstrDefExt = "json";
    if (!GetSaveFileNameA(&ofn)) return;
    if (!config_save(&g_acfg, path))
        MessageBoxA(g_hwnd, "Failed to write file.", "CSec", MB_OK | MB_ICONERROR);
}

/* -------------------------------------------------------------------------
   Change password — manual modal window
   ---------------------------------------------------------------------- */

static char  g_cpwd_current[128];
static char  g_cpwd_new[128];
static BOOL  g_cpwd_done;

static LRESULT CALLBACK CpwdProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    static HWND e_cur, e_new, e_cfm;
    switch (msg) {
        case WM_CREATE: {
            HINSTANCE hi = ((CREATESTRUCTA *)lp)->hInstance;
            int y = 18;
            CreateWindowA("STATIC", "Current password:", WS_CHILD|WS_VISIBLE,
                          10, y+2, 120, 18, hwnd, NULL, hi, NULL);
            e_cur = CreateWindowA("EDIT", "", WS_CHILD|WS_VISIBLE|WS_BORDER|ES_PASSWORD,
                                  135, y, 150, 22, hwnd, (HMENU)201, hi, NULL);
            y += 34;
            CreateWindowA("STATIC", "New password:", WS_CHILD|WS_VISIBLE,
                          10, y+2, 120, 18, hwnd, NULL, hi, NULL);
            e_new = CreateWindowA("EDIT", "", WS_CHILD|WS_VISIBLE|WS_BORDER|ES_PASSWORD,
                                  135, y, 150, 22, hwnd, (HMENU)202, hi, NULL);
            y += 34;
            CreateWindowA("STATIC", "Confirm:", WS_CHILD|WS_VISIBLE,
                          10, y+2, 120, 18, hwnd, NULL, hi, NULL);
            e_cfm = CreateWindowA("EDIT", "", WS_CHILD|WS_VISIBLE|WS_BORDER|ES_PASSWORD,
                                  135, y, 150, 22, hwnd, (HMENU)203, hi, NULL);
            y += 42;
            CreateWindowA("BUTTON", "OK", WS_CHILD|WS_VISIBLE|BS_DEFPUSHBUTTON,
                          60, y, 80, 26, hwnd, (HMENU)IDOK, hi, NULL);
            CreateWindowA("BUTTON", "Cancel", WS_CHILD|WS_VISIBLE,
                          150, y, 80, 26, hwnd, (HMENU)IDCANCEL, hi, NULL);
            SetFocus(e_cur);
            return 0;
        }
        case WM_COMMAND:
            if (LOWORD(wp) == IDOK && HIWORD(wp) == BN_CLICKED) {
                char cfm[128];
                GetWindowTextA(e_new, g_cpwd_new, sizeof(g_cpwd_new));
                GetWindowTextA(e_cfm, cfm, sizeof(cfm));
                if (!g_cpwd_new[0]) {
                    MessageBoxA(hwnd, "Password cannot be empty.", "CSec", MB_OK|MB_ICONERROR);
                    break;
                }
                if (strcmp(g_cpwd_new, cfm) != 0) {
                    MessageBoxA(hwnd, "Passwords do not match.", "CSec", MB_OK|MB_ICONERROR);
                    break;
                }
                GetWindowTextA(e_cur, g_cpwd_current, sizeof(g_cpwd_current));
                DestroyWindow(hwnd);
            } else if (LOWORD(wp) == IDCANCEL && HIWORD(wp) == BN_CLICKED) {
                g_cpwd_current[0] = g_cpwd_new[0] = '\0';
                DestroyWindow(hwnd);
            }
            break;
        case WM_DESTROY:
            g_cpwd_done = TRUE;
            break;
    }
    return DefWindowProcA(hwnd, msg, wp, lp);
}

static void do_change_password(void) {
    HINSTANCE hi = GetModuleHandleA(NULL);
    WNDCLASSA wc = {0};
    wc.lpfnWndProc   = CpwdProc;
    wc.hInstance     = hi;
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    wc.hCursor       = LoadCursorA(NULL, IDC_ARROW);
    wc.lpszClassName = "CSec_Cpwd";
    RegisterClassA(&wc); /* ignore error if already registered */

    g_cpwd_current[0] = g_cpwd_new[0] = '\0';
    g_cpwd_done = FALSE;

    RECT r; GetWindowRect(g_hwnd, &r);
    int pw = 300, ph = 190;
    int px = r.left + (r.right  - r.left - pw) / 2;
    int py = r.top  + (r.bottom - r.top  - ph) / 2;

    HWND dlg = CreateWindowA("CSec_Cpwd", "Change Password",
                             WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU,
                             px, py, pw, ph, g_hwnd, NULL, hi, NULL);
    ShowWindow(dlg, SW_SHOW);

    EnableWindow(g_hwnd, FALSE);
    MSG m;
    while (!g_cpwd_done) {
        BOOL ret = GetMessage(&m, NULL, 0, 0);
        if (ret <= 0) { if (ret == 0) PostQuitMessage((int)m.wParam); break; }
        TranslateMessage(&m); DispatchMessage(&m);
    }
    EnableWindow(g_hwnd, TRUE);
    SetForegroundWindow(g_hwnd);

    if (!g_cpwd_current[0] && !g_cpwd_new[0]) return; /* cancelled */

    char hash[65];
    sha256_hex(g_cpwd_current, hash);
    if (strcmp(hash, g_acfg.admin_hash) != 0) {
        MessageBoxA(g_hwnd, "Wrong current password.", "CSec", MB_OK | MB_ICONERROR);
        return;
    }
    sha256_hex(g_cpwd_new, g_acfg.admin_hash);
    if (config_save(&g_acfg, g_config_path))
        MessageBoxA(g_hwnd, "Password changed.", "CSec", MB_OK | MB_ICONINFORMATION);
    else
        MessageBoxA(g_hwnd, "Changed in memory but failed to save.", "CSec", MB_OK | MB_ICONWARNING);
}

/* -------------------------------------------------------------------------
   Help / onboarding dialog
   ---------------------------------------------------------------------- */

static const char *HELP_TEXT =
"HOW CSEC WORKS\r\n"
"══════════════════════════════════════════════════════\r\n"
"\r\n"
"CSec has two parts:\r\n"
"\r\n"
"  1. csec.exe (this window)\r\n"
"     The admin tool. Lets you manage the allowed URL\r\n"
"     list, import/export lists, change the password.\r\n"
"     Closing this window does NOT stop the filter.\r\n"
"\r\n"
"  2. The CSec Windows Service\r\n"
"     The real filter. Runs in the background at all\r\n"
"     times, even when no one is logged in. Blocks every\r\n"
"     website that is not on your allowed list.\r\n"
"     It starts automatically when Windows starts.\r\n"
"\r\n"
"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\r\n"
"FIRST-TIME SETUP (do this once on each PC)\r\n"
"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\r\n"
"\r\n"
"  1. Open csec.exe (this app)\r\n"
"\r\n"
"  2. Click  \"Install Service\"  at the bottom of the\r\n"
"     window. Windows will ask for Administrator\r\n"
"     permission — click Yes.\r\n"
"\r\n"
"     The filter activates immediately. All websites\r\n"
"     are now blocked until you add allowed domains.\r\n"
"\r\n"
"  3. Log in with the admin password (default: 123456)\r\n"
"     and add the domains your class needs.\r\n"
"\r\n"
"  To remove CSec from a machine:\r\n"
"  Click  \"Uninstall Service\"  at the bottom.\r\n"
"  This stops the filter and restores full internet.\r\n"
"\r\n"
"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\r\n"
"ADDING ALLOWED WEBSITES\r\n"
"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\r\n"
"\r\n"
"  1. Log in with your password (default: 123456)\r\n"
"  2. Type a domain in the URL box, e.g.  code.org\r\n"
"  3. Click Add (or press Enter)\r\n"
"\r\n"
"  Tips:\r\n"
"  • No need for www. or https://\r\n"
"  • One entry covers all subdomains:\r\n"
"    \"code.org\" also allows \"studio.code.org\"\r\n"
"  • Changes apply instantly — no restart needed\r\n"
"\r\n"
"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\r\n"
"REMOVING WEBSITES\r\n"
"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\r\n"
"\r\n"
"  1. Log in with your password\r\n"
"  2. Tick the checkbox next to each domain to remove\r\n"
"  3. Click \"Remove selected\"\r\n"
"\r\n"
"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\r\n"
"SHARING YOUR LIST WITH OTHER PCs\r\n"
"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\r\n"
"\r\n"
"  1. Build your list on the teacher PC\r\n"
"  2. Click \"Export to JSON\" — save to a USB drive\r\n"
"  3. On each student PC: open csec.exe, click\r\n"
"     \"Import from JSON\", and pick the USB file\r\n"
"\r\n"
"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\r\n"
"CHANGING / RESETTING THE PASSWORD\r\n"
"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\r\n"
"\r\n"
"  If you know the current password:\r\n"
"    Log in → click \"Change Password\"\r\n"
"\r\n"
"  If you forgot the password:\r\n"
"    1. Open CMD as Administrator\r\n"
"    2. Navigate to the CSec folder\r\n"
"    3. Run:   csec.exe --reset-password\r\n"
"    4. Password is reset to: 123456\r\n"
"    5. Log in immediately and set a new password!\r\n"
"\r\n"
"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\r\n"
"SECURITY — WHAT STUDENTS CAN BYPASS\r\n"
"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\r\n"
"\r\n"
"CSec sets the Windows system proxy. This means:\r\n"
"\r\n"
"  BLOCKED (uses Windows proxy):\r\n"
"    Chrome, Edge, Internet Explorer, and most apps\r\n"
"\r\n"
"  NOT BLOCKED — students may get around CSec via:\r\n"
"\r\n"
"  • Firefox — has its own proxy settings. A student\r\n"
"    can switch Firefox to \"No Proxy\" and bypass CSec.\r\n"
"    Fix: uninstall Firefox, or use Firefox admin policy\r\n"
"    to lock proxy settings.\r\n"
"\r\n"
"  • Local Administrator account — a student with\r\n"
"    admin rights can stop the service, clear the\r\n"
"    proxy, or uninstall CSec entirely. Student\r\n"
"    accounts should NOT have administrator rights.\r\n"
"\r\n"
"  • Phone hotspot / tethering — a student can plug\r\n"
"    in a phone and use mobile data, which bypasses\r\n"
"    the PC's proxy entirely. Disable USB ports or\r\n"
"    use a router-level filter to stop this.\r\n"
"\r\n"
"  • VPN apps — if a student installs a VPN it can\r\n"
"    tunnel around the proxy. Block VPN installs\r\n"
"    with a restricted user account.\r\n"
"\r\n"
"  CSec is a deterrent for most students, not a\r\n"
"  full lockdown. For stronger control, combine it\r\n"
"  with restricted Windows user accounts and a\r\n"
"  router-level content filter.\r\n"
"\r\n"
"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\r\n"
"EMERGENCY — RESTORING INTERNET ACCESS\r\n"
"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\r\n"
"\r\n"
"If a PC is stuck with no internet and you need to\r\n"
"fix it fast:\r\n"
"\r\n"
"  Option A — through this app:\r\n"
"    Click \"Uninstall Service\" at the bottom.\r\n"
"    Windows will ask for Administrator permission.\r\n"
"\r\n"
"  Option B — manually from CMD as Administrator\r\n"
"    (if the app won't open or UAC is blocked):\r\n"
"\r\n"
"    sc stop CSec\r\n"
"    sc delete CSec\r\n"
"\r\n"
"    If that fails, clear the proxy manually:\r\n"
"\r\n"
"    reg add \"HKCU\\Software\\Microsoft\\Windows\\\r\n"
"    CurrentVersion\\Internet Settings\"\r\n"
"    /v ProxyEnable /t REG_DWORD /d 0 /f\r\n"
"\r\n"
"    reg delete \"HKCU\\Software\\Microsoft\\Windows\\\r\n"
"    CurrentVersion\\Internet Settings\"\r\n"
"    /v ProxyServer /f\r\n"
"\r\n"
"    reg delete \"HKLM\\SOFTWARE\\Policies\\Microsoft\\\r\n"
"    Windows\\CurrentVersion\\Internet Settings\" /f\r\n"
"\r\n"
"    sc stop CSec\r\n"
"    sc delete CSec\r\n"
"\r\n"
"══════════════════════════════════════════════════════\r\n";

static BOOL g_help_done;

static LRESULT CALLBACK HelpProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
        case WM_CREATE: {
            HINSTANCE hi = ((CREATESTRUCTA *)lp)->hInstance;
            RECT r; GetClientRect(hwnd, &r);
            /* Scrollable read-only text area */
            HWND edit = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", HELP_TEXT,
                WS_CHILD | WS_VISIBLE | WS_VSCROLL |
                ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL,
                8, 8, r.right - 16, r.bottom - 50,
                hwnd, NULL, hi, NULL);
            /* Use a fixed-width font so columns align */
            HFONT font = CreateFontA(14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                DEFAULT_QUALITY, FIXED_PITCH | FF_MODERN, "Consolas");
            if (font) SendMessage(edit, WM_SETFONT, (WPARAM)font, TRUE);
            /* Scroll to top */
            SendMessage(edit, EM_SETSEL, 0, 0);
            SendMessage(edit, EM_SCROLLCARET, 0, 0);
            /* Close button */
            CreateWindowA("BUTTON", "Close", WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON,
                (r.right - 80) / 2, r.bottom - 36, 80, 28,
                hwnd, (HMENU)IDOK, hi, NULL);
            return 0;
        }
        case WM_COMMAND:
            if (LOWORD(wp) == IDOK) DestroyWindow(hwnd);
            break;
        case WM_KEYDOWN:
            if (wp == VK_ESCAPE) DestroyWindow(hwnd);
            break;
        case WM_DESTROY:
            g_help_done = TRUE;
            break;
    }
    return DefWindowProcA(hwnd, msg, wp, lp);
}

static void show_help(void) {
    HINSTANCE hi = GetModuleHandleA(NULL);

    WNDCLASSA wc    = {0};
    wc.lpfnWndProc  = HelpProc;
    wc.hInstance    = hi;
    wc.hbrBackground= (HBRUSH)(COLOR_BTNFACE + 1);
    wc.hCursor      = LoadCursorA(NULL, IDC_ARROW);
    wc.lpszClassName= "CSec_Help";
    RegisterClassA(&wc);

    RECT pr; GetWindowRect(g_hwnd, &pr);
    int hw = 560, hh = 560;
    int hx = pr.left + (pr.right  - pr.left - hw) / 2;
    int hy = pr.top  + (pr.bottom - pr.top  - hh) / 2;

    HWND dlg = CreateWindowA("CSec_Help", "CSec — How it works",
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_THICKFRAME,
        hx, hy, hw, hh, g_hwnd, NULL, hi, NULL);
    ShowWindow(dlg, SW_SHOW);

    g_help_done = FALSE;
    EnableWindow(g_hwnd, FALSE);
    MSG m;
    while (!g_help_done) {
        BOOL ret = GetMessage(&m, NULL, 0, 0);
        if (ret <= 0) { if (ret == 0) PostQuitMessage((int)m.wParam); break; }
        TranslateMessage(&m); DispatchMessage(&m);
    }
    EnableWindow(g_hwnd, TRUE);
    SetForegroundWindow(g_hwnd);
}

/* -------------------------------------------------------------------------
   Main window
   ---------------------------------------------------------------------- */

static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
        case WM_CREATE: {
            HINSTANCE hi = ((CREATESTRUCTA *)lp)->hInstance;
            /* Row 1 — login  (client width = 640) */
            CreateWindowA("STATIC", "Admin Access", WS_CHILD|WS_VISIBLE,
                          15, 20, 100, 18, hwnd, NULL, hi, NULL);
            g_edit_pass = CreateWindowA("EDIT", "", WS_CHILD|WS_VISIBLE|WS_BORDER|ES_PASSWORD,
                                        120, 17, 370, 24, hwnd, (HMENU)ID_EDIT_PASS, hi, NULL);
            g_btn_login = CreateWindowA("BUTTON", "Login", WS_CHILD|WS_VISIBLE,
                                        500, 17, 90, 24, hwnd, (HMENU)ID_BTN_LOGIN, hi, NULL);
            /* "?" always visible, even before login */
            CreateWindowA("BUTTON", "?", WS_CHILD|WS_VISIBLE,
                          600, 17, 24, 24, hwnd, (HMENU)ID_BTN_HELP, hi, NULL);
            /* Row 2 — filter mode (whitelist / blacklist), two stacked rows */
            CreateWindowA("STATIC", "Filter mode:", WS_CHILD|WS_VISIBLE,
                          15, 51, 100, 18, hwnd, NULL, hi, NULL);
            g_radio_white = CreateWindowA("BUTTON",
                          "Whitelist - block all except list",
                          WS_CHILD|WS_VISIBLE|BS_AUTORADIOBUTTON|WS_GROUP,
                          120, 49, 490, 20, hwnd, (HMENU)ID_RADIO_WHITE, hi, NULL);
            g_radio_black = CreateWindowA("BUTTON",
                          "Blacklist - allow all except list",
                          WS_CHILD|WS_VISIBLE|BS_AUTORADIOBUTTON,
                          120, 71, 490, 20, hwnd, (HMENU)ID_RADIO_BLACK, hi, NULL);
            /* Row 2b — Safe Search (prominent, separate from Block Lists) */
            CreateWindowA("STATIC", "Safe Search:", WS_CHILD|WS_VISIBLE,
                          15, 99, 100, 18, hwnd, NULL, hi, NULL);
            g_chk_safesearch = CreateWindowA("BUTTON",
                          "Force SafeSearch on Google search  (recommended)",
                          WS_CHILD|WS_VISIBLE|BS_AUTOCHECKBOX,
                          120, 97, 490, 20, hwnd, (HMENU)ID_CHK_SAFESEARCH, hi, NULL);
            /* Row 2c — YouTube Restricted Mode (Off / Moderate / Strict) */
            CreateWindowA("STATIC", "YouTube:", WS_CHILD|WS_VISIBLE,
                          15, 121, 100, 18, hwnd, NULL, hi, NULL);
            g_radio_yt_off = CreateWindowA("BUTTON", "Off",
                          WS_CHILD|WS_VISIBLE|BS_AUTORADIOBUTTON|WS_GROUP,
                          120, 119, 60, 20, hwnd, (HMENU)ID_RADIO_YT_OFF, hi, NULL);
            g_radio_yt_mod = CreateWindowA("BUTTON", "Moderate",
                          WS_CHILD|WS_VISIBLE|BS_AUTORADIOBUTTON,
                          185, 119, 90, 20, hwnd, (HMENU)ID_RADIO_YT_MODERATE, hi, NULL);
            g_radio_yt_strict = CreateWindowA("BUTTON", "Strict  (recommended)",
                          WS_CHILD|WS_VISIBLE|BS_AUTORADIOBUTTON,
                          280, 119, 200, 20, hwnd, (HMENU)ID_RADIO_YT_STRICT, hi, NULL);
            /* Row 3 — add URL */
            CreateWindowA("STATIC", "URL", WS_CHILD|WS_VISIBLE,
                          15, 153, 100, 18, hwnd, NULL, hi, NULL);
            g_edit_url = CreateWindowA("EDIT", "", WS_CHILD|WS_VISIBLE|WS_BORDER,
                                       120, 150, 370, 24, hwnd, (HMENU)ID_EDIT_URL, hi, NULL);
            g_btn_add  = CreateWindowA("BUTTON", "Add", WS_CHILD|WS_VISIBLE,
                                       500, 150, 114, 24, hwnd, (HMENU)ID_BTN_ADD, hi, NULL);
            /* Hint below URL field */
            CreateWindowA("STATIC",
                          "Enter domain only - e.g.  code.org   (no https://, no www., no /path)",
                          WS_CHILD|WS_VISIBLE|SS_LEFTNOWORDWRAP,
                          120, 177, 500, 16, hwnd, NULL, hi, NULL);
            /* Domain list */
            g_lv = CreateWindowExA(WS_EX_CLIENTEDGE, WC_LISTVIEWA, "",
                                   WS_CHILD|WS_VISIBLE|LVS_REPORT|LVS_SHOWSELALWAYS|LVS_SINGLESEL,
                                   15, 195, 610, 220, hwnd, (HMENU)ID_LV, hi, NULL);
            ListView_SetExtendedListViewStyle(g_lv,
                LVS_EX_CHECKBOXES | LVS_EX_FULLROWSELECT);
            LVCOLUMNA col = {0};
            col.mask    = LVCF_TEXT | LVCF_WIDTH;
            col.cx      = 580;
            col.pszText = "Allowed URLs";
            ListView_InsertColumn(g_lv, 0, &col);
            /* Bottom row — 5 equal buttons (120px each, 2px gaps) */
            g_btn_remove  = CreateWindowA("BUTTON", "Remove selected",
                                          WS_CHILD|WS_VISIBLE, 15,  425, 120, 26,
                                          hwnd, (HMENU)ID_BTN_REMOVE, hi, NULL);
            g_btn_import  = CreateWindowA("BUTTON", "Import from JSON",
                                          WS_CHILD|WS_VISIBLE, 137, 425, 120, 26,
                                          hwnd, (HMENU)ID_BTN_IMPORT, hi, NULL);
            g_btn_export  = CreateWindowA("BUTTON", "Export to JSON",
                                          WS_CHILD|WS_VISIBLE, 259, 425, 120, 26,
                                          hwnd, (HMENU)ID_BTN_EXPORT, hi, NULL);
            g_btn_presets = CreateWindowA("BUTTON", "Block Lists",
                                          WS_CHILD|WS_VISIBLE, 381, 425, 120, 26,
                                          hwnd, (HMENU)ID_BTN_PRESETS, hi, NULL);
            g_btn_chgpwd  = CreateWindowA("BUTTON", "Change Password",
                                          WS_CHILD|WS_VISIBLE, 503, 425, 122, 26,
                                          hwnd, (HMENU)ID_BTN_CHGPWD, hi, NULL);
            /* Separator */
            CreateWindowExA(0, "STATIC", "", WS_CHILD|WS_VISIBLE|SS_ETCHEDHORZ,
                            15, 459, 610, 2, hwnd, NULL, hi, NULL);
            /* Service status + install/uninstall — always visible, no login needed */
            g_static_svc = CreateWindowA("STATIC", "Service: checking...",
                                         WS_CHILD|WS_VISIBLE,
                                         15, 470, 220, 20, hwnd, (HMENU)ID_STATIC_SVC, hi, NULL);
            g_btn_install = CreateWindowA("BUTTON", "Install Service",
                                          WS_CHILD|WS_VISIBLE,
                                          245, 468, 170, 28, hwnd, (HMENU)ID_BTN_INSTALL, hi, NULL);
            g_btn_uninstall = CreateWindowA("BUTTON", "Uninstall Service",
                                            WS_CHILD|WS_VISIBLE,
                                            423, 468, 182, 28, hwnd, (HMENU)ID_BTN_UNINSTALL, hi, NULL);
            /* Set initial radio state (config already loaded before CreateWindow) */
            SendMessage(g_radio_white, BM_SETCHECK, BST_CHECKED, 0);
            /* Initial SafeSearch + YouTube state from loaded config */
            SendMessage(g_chk_safesearch, BM_SETCHECK,
                        g_acfg.safesearch ? BST_CHECKED : BST_UNCHECKED, 0);
            sync_youtube_radios(g_acfg.youtube_mode);
            enable_controls(FALSE);
            SetFocus(g_edit_pass);
            return 0;
        }
        case WM_COMMAND:
            switch (LOWORD(wp)) {
                case ID_BTN_LOGIN:  do_login();           break;
                case ID_RADIO_WHITE:
                    if (g_logged_in && HIWORD(wp) == BN_CLICKED) {
                        g_acfg.blacklist_mode = 0;
                        config_save(&g_acfg, g_config_path);
                        notify_service();
                        lv_update_header();
                    }
                    break;
                case ID_RADIO_BLACK:
                    if (g_logged_in && HIWORD(wp) == BN_CLICKED) {
                        g_acfg.blacklist_mode = 1;
                        config_save(&g_acfg, g_config_path);
                        notify_service();
                        lv_update_header();
                    }
                    break;
                case ID_BTN_ADD:    if (g_logged_in) do_add();             break;
                case ID_BTN_REMOVE: if (g_logged_in) do_remove_selected(); break;
                case ID_BTN_IMPORT: if (g_logged_in) do_import();          break;
                case ID_BTN_EXPORT:   if (g_logged_in) do_export();          break;
                case ID_BTN_PRESETS:  if (g_logged_in) do_presets();        break;
                case ID_CHK_SAFESEARCH:
                    if (g_logged_in && HIWORD(wp) == BN_CLICKED) {
                        g_acfg.safesearch =
                            (SendMessage(g_chk_safesearch, BM_GETCHECK, 0, 0) == BST_CHECKED) ? 1 : 0;
                        config_save(&g_acfg, g_config_path);
                        notify_service();
                    }
                    break;
                case ID_RADIO_YT_OFF:
                case ID_RADIO_YT_MODERATE:
                case ID_RADIO_YT_STRICT:
                    if (g_logged_in && HIWORD(wp) == BN_CLICKED) {
                        g_acfg.youtube_mode =
                            (LOWORD(wp) == ID_RADIO_YT_OFF)      ? 0 :
                            (LOWORD(wp) == ID_RADIO_YT_MODERATE) ? 1 : 2;
                        config_save(&g_acfg, g_config_path);
                        notify_service();
                    }
                    break;
                case ID_BTN_CHGPWD:   if (g_logged_in) do_change_password(); break;
                case ID_BTN_HELP:     show_help(); break;
                case ID_BTN_INSTALL:  do_install_service(); break;
                case ID_BTN_UNINSTALL:do_uninstall_service(); break;
            }
            break;
        case WM_DESTROY:
            PostQuitMessage(0);
            break;
    }
    return DefWindowProcA(hwnd, msg, wp, lp);
}

static int admin_main(void) {
    HINSTANCE hi = GetModuleHandleA(NULL);

    INITCOMMONCONTROLSEX icc = {sizeof(icc), ICC_LISTVIEW_CLASSES};
    InitCommonControlsEx(&icc);

    config_load(&g_acfg, g_config_path);

    /* First run: no config file yet */
    const char *default_hash =
        "8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92";
    int first_run = (g_acfg.count == 0 &&
                     strcmp(g_acfg.admin_hash, default_hash) == 0);

    WNDCLASSA wc    = {0};
    wc.lpfnWndProc  = WndProc;
    wc.hInstance    = hi;
    wc.hbrBackground= (HBRUSH)(COLOR_BTNFACE + 1);
    wc.hCursor      = LoadCursorA(NULL, IDC_ARROW);
    wc.lpszClassName= "CSec_Main";
    if (!RegisterClassA(&wc)) return 1;

    /* Center on screen */
    int sw = GetSystemMetrics(SM_CXSCREEN);
    int sh = GetSystemMetrics(SM_CYSCREEN);
    RECT r = {0, 0, WIN_W, WIN_H};
    AdjustWindowRect(&r, WS_OVERLAPPED|WS_CAPTION|WS_SYSMENU|WS_MINIMIZEBOX, FALSE);
    int ww = r.right - r.left, wh = r.bottom - r.top;

    g_hwnd = CreateWindowA("CSec_Main", "CSec " VERSION " — Classroom Web Filter",
                           WS_OVERLAPPED|WS_CAPTION|WS_SYSMENU|WS_MINIMIZEBOX,
                           (sw - ww) / 2, (sh - wh) / 2, ww, wh,
                           NULL, NULL, hi, NULL);
    if (!g_hwnd) return 1;
    ShowWindow(g_hwnd, SW_SHOW);
    UpdateWindow(g_hwnd);
    update_svc_label();

    /* Auto-show help on first run */
    if (first_run) show_help();

    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0) > 0) {
        /* Enter in password field → Login; Enter in URL field → Add */
        if (msg.message == WM_KEYDOWN && msg.wParam == VK_RETURN) {
            HWND f = GetFocus();
            if (f == g_edit_pass)
                SendMessage(g_hwnd, WM_COMMAND, MAKEWPARAM(ID_BTN_LOGIN, BN_CLICKED),
                            (LPARAM)g_btn_login);
            else if (f == g_edit_url)
                SendMessage(g_hwnd, WM_COMMAND, MAKEWPARAM(ID_BTN_ADD, BN_CLICKED),
                            (LPARAM)g_btn_add);
        }
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    return (int)msg.wParam;
}

/* =========================================================================
   Entry point
   ========================================================================= */

int main(int argc, char *argv[]) {
    resolve_config_path();

    if (argc > 1) {
        if (strcmp(argv[1], "--install")        == 0) return svc_install();
        if (strcmp(argv[1], "--uninstall")      == 0) return svc_uninstall();
        if (strcmp(argv[1], "--reset-password") == 0) {
            CSec_Config cfg;
            config_load(&cfg, g_config_path);
            strcpy(cfg.admin_hash,
                   "8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92");
            if (config_save(&cfg, g_config_path))
                MessageBoxA(NULL,
                    "Password reset to: 123456\n\nOpen csec.exe and change it immediately.",
                    "CSec", MB_OK | MB_ICONINFORMATION);
            else
                MessageBoxA(NULL,
                    "Failed to save config file.\nMake sure csec-config.json is in the same folder.",
                    "CSec", MB_OK | MB_ICONERROR);
            return 0;
        }
        MessageBoxA(NULL,
                    "Usage:\r\n"
                    "  csec.exe                  Open admin UI\r\n"
                    "  csec.exe --install         Install service (run as Admin)\r\n"
                    "  csec.exe --uninstall       Remove service (run as Admin)\r\n"
                    "  csec.exe --reset-password  Reset password to 123456",
                    "CSec", MB_OK | MB_ICONINFORMATION);
        return 1;
    }

    /* If launched by SCM: run as service. Otherwise: open admin GUI. */
    SERVICE_TABLE_ENTRYA tbl[] = {{(LPSTR)SERVICE_NAME, ServiceMain}, {NULL, NULL}};
    if (!StartServiceCtrlDispatcherA(tbl)) {
        if (GetLastError() == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT)
            return admin_main();
    }
    return 0;
}
