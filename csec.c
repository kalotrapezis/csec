/*
 * csec.exe  —  Classroom Web Filter
 *
 * Usage:
 *   csec.exe --install     Install and start the filter service (run as Admin)
 *   csec.exe --uninstall   Stop and remove the service (run as Admin)
 *   csec.exe               Open admin UI  /  run as service (if started by SCM)
 */

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <commctrl.h>
#include <commdlg.h>
#include <shellapi.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "filter.h"

/* =========================================================================
   Shared: config path, stringify
   ========================================================================= */

#define STR_(x) #x
#define STR(x)  STR_(x)

#define SERVICE_NAME "CSec"
#define VERSION      "0.0.5 Alpha"
#define PROXY_PORT   8080

static char g_config_path[MAX_PATH];
static char g_lists_dir[MAX_PATH];   /* <exe dir>\lists */

static void resolve_config_path(void) {
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

    /* HKCU — for the current user (correct when called from --install) */
    HKEY hk;
    if (RegOpenKeyExA(HKEY_CURRENT_USER, INET_KEY, 0, KEY_SET_VALUE, &hk) == ERROR_SUCCESS) {
        DWORD v = enable ? 1 : 0;
        RegSetValueExA(hk, "ProxyEnable", 0, REG_DWORD, (const BYTE *)&v, sizeof(v));
        if (enable)
            RegSetValueExA(hk, "ProxyServer", 0, REG_SZ,
                           (const BYTE *)proxy, (DWORD)strlen(proxy) + 1);
        else {
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

/* =========================================================================
   Proxy server
   ========================================================================= */

#define RECV_TIMEOUT_MS 10000
#define BUF_SIZE        8192

static CSec_Config  g_cfg;
static CRITICAL_SECTION g_cfg_lock;
static volatile int g_running = 1;

/* forward declarations — defined later in the admin GUI section */
static int   extlists_blocked(const char *host);
static void  extlists_load_all(void);
static void  extlists_load_hot(void);
static DWORD WINAPI bg_load_thread(LPVOID arg);

typedef struct { SOCKET from; SOCKET to; } TunnelArgs;

static int recv_line(SOCKET s, char *buf, int len) {
    int n = 0;
    while (n < len - 1) {
        char c; int r = recv(s, &c, 1, 0);
        if (r <= 0) break;
        buf[n++] = c;
        if (c == '\n') break;
    }
    buf[n] = '\0'; return n;
}

static void strip_host(const char *src, char *dst, int dstlen) {
    strncpy(dst, src, dstlen - 1); dst[dstlen - 1] = '\0';
    char *p = strchr(dst, ':'); if (p) *p = '\0';
    int n = (int)strlen(dst);
    while (n > 0 && (dst[n-1] == '\r' || dst[n-1] == ' ')) dst[--n] = '\0';
}

static DWORD WINAPI tunnel_thread(LPVOID arg) {
    TunnelArgs *t = (TunnelArgs *)arg;
    char buf[BUF_SIZE]; int n;
    while ((n = recv(t->from, buf, sizeof(buf), 0)) > 0) send(t->to, buf, n, 0);
    free(t); return 0;
}

static DWORD WINAPI handle_client(LPVOID arg) {
    SOCKET client = (SOCKET)(UINT_PTR)arg;
    char buf[BUF_SIZE], method[16], url[2048], ver[16], host[MAX_DOMAIN_LEN];
    int port = 80;

    int n = recv_line(client, buf, sizeof(buf));
    if (n <= 0 || sscanf(buf, "%15s %2047s %15s", method, url, ver) != 3) goto done;

    host[0] = '\0';
    char hdrs[BUF_SIZE * 4]; int hlen = n;
    if (n < (int)sizeof(hdrs)) memcpy(hdrs, buf, n);

    while (hlen < (int)sizeof(hdrs) - 1) {
        int r = recv_line(client, buf, sizeof(buf));
        if (r <= 0) break;
        if (hlen + r < (int)sizeof(hdrs)) { memcpy(hdrs + hlen, buf, r); hlen += r; }
        if (strncasecmp(buf, "Host:", 5) == 0) strip_host(buf + 5, host, sizeof(host));
        if (buf[0] == '\r' || buf[0] == '\n') break;
    }
    hdrs[hlen] = '\0';

    if (strcmp(method, "CONNECT") == 0) {
        char *c = strrchr(url, ':');
        if (c) { port = atoi(c + 1); *c = '\0'; }
        strncpy(host, url, sizeof(host) - 1); host[sizeof(host)-1] = '\0';

        EnterCriticalSection(&g_cfg_lock);
        int ok = domain_allowed(&g_cfg, host);
        if (ok && g_cfg.blacklist_mode) ok = !extlists_blocked(host);
        LeaveCriticalSection(&g_cfg_lock);
        if (!ok) { send(client, "HTTP/1.1 403 Forbidden\r\n\r\n", 26, 0); goto done; }

        struct addrinfo hints = {0}, *res = NULL;
        hints.ai_family = AF_UNSPEC; hints.ai_socktype = SOCK_STREAM;
        char ps[8]; sprintf(ps, "%d", port);
        if (getaddrinfo(host, ps, &hints, &res) != 0) goto done;
        SOCKET rem = socket(res->ai_family, SOCK_STREAM, 0);
        if (rem == INVALID_SOCKET || connect(rem, res->ai_addr, (int)res->ai_addrlen) != 0)
            { freeaddrinfo(res); if (rem != INVALID_SOCKET) closesocket(rem); goto done; }
        freeaddrinfo(res);

        send(client, "HTTP/1.1 200 Connection Established\r\n\r\n", 39, 0);

        TunnelArgs *ta = (TunnelArgs *)malloc(sizeof(TunnelArgs));
        if (ta) { ta->from = rem; ta->to = client;
            HANDLE t = CreateThread(NULL, 0, tunnel_thread, ta, 0, NULL);
            if (!t) free(ta); else CloseHandle(t); }
        { char fb[BUF_SIZE]; int fn;
          while ((fn = recv(client, fb, sizeof(fb), 0)) > 0) send(rem, fb, fn, 0); }
        closesocket(rem);
    } else {
        if (!host[0]) goto done;
        EnterCriticalSection(&g_cfg_lock);
        int ok = domain_allowed(&g_cfg, host);
        if (ok && g_cfg.blacklist_mode) ok = !extlists_blocked(host);
        LeaveCriticalSection(&g_cfg_lock);
        if (!ok) {
            const char *deny = "HTTP/1.1 403 Forbidden\r\nContent-Type: text/html\r\n"
                "Connection: close\r\n\r\n<html><body><h2>Blocked by CSec</h2></body></html>";
            send(client, deny, (int)strlen(deny), 0); goto done;
        }
        struct addrinfo hints2 = {0}, *res2 = NULL;
        hints2.ai_family = AF_UNSPEC; hints2.ai_socktype = SOCK_STREAM;
        if (getaddrinfo(host, "80", &hints2, &res2) != 0) goto done;
        SOCKET rem2 = socket(res2->ai_family, SOCK_STREAM, 0);
        if (rem2 == INVALID_SOCKET || connect(rem2, res2->ai_addr, (int)res2->ai_addrlen) != 0)
            { freeaddrinfo(res2); if (rem2 != INVALID_SOCKET) closesocket(rem2); goto done; }
        freeaddrinfo(res2);
        send(rem2, hdrs, hlen, 0);
        { char fb[BUF_SIZE]; int fn;
          while ((fn = recv(rem2, fb, sizeof(fb), 0)) > 0) send(client, fb, fn, 0); }
        closesocket(rem2);
    }
done:
    closesocket(client); return 0;
}

static void cfg_reload(void) {
    CSec_Config tmp;
    if (config_load(&tmp, g_config_path)) {
        EnterCriticalSection(&g_cfg_lock);
        memcpy(&g_cfg, &tmp, sizeof(g_cfg));
        LeaveCriticalSection(&g_cfg_lock);
        /* Hot pass: blocks popular sites in <100ms while full lists load in background */
        extlists_load_hot();
        HANDLE t = CreateThread(NULL, 0, bg_load_thread, NULL, 0, NULL);
        if (t) CloseHandle(t);
    }
}

static void proxy_run(void) {
    WSADATA wsa; WSAStartup(MAKEWORD(2, 2), &wsa);
    registry_set_proxy(1); /* re-enforce HKLM on every service start */

    SOCKET srv = socket(AF_INET, SOCK_STREAM, 0);
    BOOL reuse = TRUE;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, (char *)&reuse, sizeof(reuse));

    struct sockaddr_in addr = {0};
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    addr.sin_port        = htons(PROXY_PORT);
    if (bind(srv, (struct sockaddr *)&addr, sizeof(addr)) != 0) goto cleanup;
    if (listen(srv, SOMAXCONN) != 0) goto cleanup;

    while (g_running) {
        fd_set fds; FD_ZERO(&fds); FD_SET(srv, &fds);
        struct timeval tv = {1, 0};
        if (select(0, &fds, NULL, NULL, &tv) <= 0) continue;
        SOCKET cl = accept(srv, NULL, NULL);
        if (cl == INVALID_SOCKET) continue;
        DWORD to = RECV_TIMEOUT_MS;
        setsockopt(cl, SOL_SOCKET, SO_RCVTIMEO, (char *)&to, sizeof(to));
        HANDLE t = CreateThread(NULL, 0, handle_client, (LPVOID)(UINT_PTR)cl, 0, NULL);
        if (t) CloseHandle(t); else closesocket(cl);
    }
cleanup:
    closesocket(srv); WSACleanup();
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

/* Window width/height (client area) */
#define WIN_W 640
#define WIN_H 474

static HWND g_hwnd;
static HWND g_edit_pass, g_btn_login;
static HWND g_radio_white, g_radio_black;
static HWND g_edit_url,  g_btn_add;
static HWND g_lv;
static HWND g_btn_remove, g_btn_import, g_btn_export, g_btn_presets, g_btn_chgpwd;
static HWND g_btn_install, g_btn_uninstall, g_static_svc;
static CSec_Config g_acfg;   /* admin copy of config */
static int  g_logged_in = 0;

/* -------------------------------------------------------------------------
   URL normalization — strips protocol, www., trailing path/port
   ---------------------------------------------------------------------- */

static void normalize_domain(const char *input, char *out, int outlen) {
    const char *p = input;
    /* Strip protocol */
    if (strncasecmp(p, "https://", 8) == 0)      p += 8;
    else if (strncasecmp(p, "http://", 7) == 0)  p += 7;
    /* Strip www. (only one level — keep "www2." etc.) */
    if (strncasecmp(p, "www.", 4) == 0) p += 4;
    strncpy(out, p, outlen - 1);
    out[outlen - 1] = '\0';
    /* Strip path */
    char *s = strchr(out, '/');  if (s) *s = '\0';
    /* Strip query string */
    s = strchr(out, '?');        if (s) *s = '\0';
    /* Strip port */
    s = strchr(out, ':');        if (s) *s = '\0';
    /* Lowercase */
    for (char *c = out; *c; c++) *c = (char)tolower((unsigned char)*c);
}

/* -------------------------------------------------------------------------
   Domain bundles — add these extra domains when a known site is added
   ---------------------------------------------------------------------- */

typedef struct { const char *trigger; const char *extras[12]; } Bundle;

static const Bundle BUNDLES[] = {
    { "google.com", {
        "googleapis.com", "gstatic.com", "googleusercontent.com",
        "accounts.google.com", "google-analytics.com", NULL } },
    { "youtube.com", {
        "youtu.be", "ytimg.com", "googlevideo.com", "ggpht.com",
        "googleapis.com", "gstatic.com", "youtube-nocookie.com", NULL } },
    { "microsoft.com", {
        "microsoftonline.com", "live.com", "msftncsi.com",
        "windowsupdate.com", "office.com", "msecnd.net", NULL } },
    { "office.com", {
        "microsoft.com", "microsoftonline.com", "live.com",
        "officeapps.live.com", "sharepoint.com", "msecnd.net", NULL } },
    { NULL, { NULL } }
};

/* Returns index into BUNDLES if domain matches a trigger, else -1 */
static int bundle_find(const char *domain) {
    for (int i = 0; BUNDLES[i].trigger; i++)
        if (strcmp(domain, BUNDLES[i].trigger) == 0) return i;
    return -1;
}

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
   External block lists — large domain files from the lists\ folder
   Format: hosts file  "0.0.0.0 domain.com"  (The Block List Project)
   ---------------------------------------------------------------------- */

#define MAX_EXT_LISTS 32

typedef struct {
    char  name[64];
    char **sorted;   /* sorted array of heap-allocated domain strings */
    int    count;
} ExtList;

static ExtList g_ext[MAX_EXT_LISTS];
static int     g_ext_count = 0;

static char *el_strdup(const char *s) {
    size_t n = strlen(s) + 1;
    char *p = (char *)malloc(n);
    if (p) memcpy(p, s, n);
    return p;
}

static int el_cmp(const void *a, const void *b) {
    return strcmp(*(const char **)a, *(const char **)b);
}

static void extlist_free(ExtList *el) {
    for (int i = 0; i < el->count; i++) free(el->sorted[i]);
    free(el->sorted);
    el->sorted = NULL;
    el->count  = 0;
}

/* max_lines: stop after this many domain entries (0 = load all) */
static int extlist_load_file(ExtList *el, const char *path, int max_lines) {
    extlist_free(el);
    FILE *f = fopen(path, "r");
    if (!f) return 0;

    int cap = 4096;
    el->sorted = (char **)malloc((size_t)cap * sizeof(char *));
    if (!el->sorted) { fclose(f); return 0; }

    char line[512];
    while (fgets(line, sizeof(line), f)) {
        if (max_lines > 0 && el->count >= max_lines) break;
        if (line[0] == '#' || line[0] == '\n' || line[0] == '\r') continue;
        /* format: "0.0.0.0 domain.com" */
        char *sp = strchr(line, ' ');
        if (!sp) continue;
        sp++;
        /* trim trailing whitespace */
        char *end = sp + strlen(sp);
        while (end > sp && (*(end-1)=='\r'||*(end-1)=='\n'||*(end-1)==' ')) end--;
        *end = '\0';
        if (!*sp || *sp == '#') continue;

        if (el->count >= cap) {
            cap *= 2;
            char **tmp = (char **)realloc(el->sorted, (size_t)cap * sizeof(char *));
            if (!tmp) break;
            el->sorted = tmp;
        }
        char *d = el_strdup(sp);
        if (d) el->sorted[el->count++] = d;
    }
    fclose(f);

    if (el->count > 0)
        qsort(el->sorted, (size_t)el->count, sizeof(char *), el_cmp);
    return el->count > 0;
}

/* Check if host (or any parent domain) is in one ext list. Caller holds lock. */
static int extlist_hit(const ExtList *el, const char *host) {
    if (!el->count) return 0;
    const char *key = host;
    if (bsearch(&key, el->sorted, (size_t)el->count, sizeof(char *), el_cmp)) return 1;
    /* try parent domains: studio.code.org -> code.org */
    const char *p = host;
    while ((p = strchr(p, '.')) != NULL) {
        p++;
        if (!strchr(p, '.')) break; /* skip bare TLD */
        key = p;
        if (bsearch(&key, el->sorted, (size_t)el->count, sizeof(char *), el_cmp)) return 1;
    }
    return 0;
}

/* Returns 1 if host is blocked by any enabled ext list. Caller holds g_cfg_lock. */
static int extlists_blocked(const char *host) {
    for (int i = 0; i < g_ext_count; i++)
        if (extlist_hit(&g_ext[i], host)) return 1;
    return 0;
}

/* HOT_LINES: domains loaded per file in the fast first pass.
   These must be at the TOP of each list file — put popular sites there. */
#define HOT_LINES 500

/* Load enabled list files. max_lines=0 loads everything; max_lines=HOT_LINES
   is the fast first pass. _priority.txt (if present) is always loaded in full
   as the first slot — put the most commonly-known sites there.
   Call WITHOUT holding g_cfg_lock (file I/O can be slow). */
static void extlists_load_impl(int max_lines) {
    /* Snapshot the names list while holding lock */
    char names[512];
    EnterCriticalSection(&g_cfg_lock);
    strncpy(names, g_cfg.enabled_lists, sizeof(names) - 1);
    names[sizeof(names) - 1] = '\0';
    LeaveCriticalSection(&g_cfg_lock);

    ExtList new_ext[MAX_EXT_LISTS];
    int     new_count = 0;
    memset(new_ext, 0, sizeof(new_ext));

    /* Always load _priority.txt first (small curated list, no line limit) */
    if (new_count < MAX_EXT_LISTS) {
        char ppath[MAX_PATH];
        snprintf(ppath, MAX_PATH, "%s\\_priority.txt", g_lists_dir);
        if (extlist_load_file(&new_ext[new_count], ppath, 0)) {
            strncpy(new_ext[new_count].name, "_priority", 63);
            new_count++;
        }
    }

    /* Walk space-separated enabled_lists without strtok (not thread-safe) */
    const char *p = names;
    while (*p && new_count < MAX_EXT_LISTS) {
        while (*p == ' ') p++;
        if (!*p) break;
        const char *start = p;
        while (*p && *p != ' ') p++;
        int len = (int)(p - start);
        if (len == 0) continue;

        char tok[64];
        if (len >= (int)sizeof(tok)) len = (int)sizeof(tok) - 1;
        memcpy(tok, start, (size_t)len);
        tok[len] = '\0';

        char path[MAX_PATH];
        snprintf(path, MAX_PATH, "%s\\%s.txt", g_lists_dir, tok);
        if (extlist_load_file(&new_ext[new_count], path, max_lines)) {
            strncpy(new_ext[new_count].name, tok, 63);
            new_count++;
        }
    }

    /* Swap atomically under lock */
    EnterCriticalSection(&g_cfg_lock);
    for (int i = 0; i < g_ext_count; i++) extlist_free(&g_ext[i]);
    memcpy(g_ext, new_ext, (size_t)new_count * sizeof(ExtList));
    g_ext_count = new_count;
    LeaveCriticalSection(&g_cfg_lock);
}

static void extlists_load_all(void)  { extlists_load_impl(0);         }
static void extlists_load_hot(void)  { extlists_load_impl(HOT_LINES); }

static DWORD WINAPI bg_load_thread(LPVOID arg) {
    (void)arg;
    /* Progressive batches — files must be sorted by popularity (run sort_lists.py).
       Each step expands coverage; pauses keep the HDD from being hammered. */
    static const int steps[] = {1500, 5000, 0}; /* 0 = full (no limit) */
    for (int i = 0; i < (int)(sizeof(steps)/sizeof(steps[0])); i++) {
        Sleep(5000);
        extlists_load_impl(steps[i]);
    }
    return 0;
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

static void enable_controls(int on) {
    EnableWindow(g_radio_white, on);
    EnableWindow(g_radio_black, on);
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
            /* Row 3 — add URL */
            CreateWindowA("STATIC", "URL", WS_CHILD|WS_VISIBLE,
                          15, 106, 100, 18, hwnd, NULL, hi, NULL);
            g_edit_url = CreateWindowA("EDIT", "", WS_CHILD|WS_VISIBLE|WS_BORDER,
                                       120, 103, 370, 24, hwnd, (HMENU)ID_EDIT_URL, hi, NULL);
            g_btn_add  = CreateWindowA("BUTTON", "Add", WS_CHILD|WS_VISIBLE,
                                       500, 103, 114, 24, hwnd, (HMENU)ID_BTN_ADD, hi, NULL);
            /* Hint below URL field */
            CreateWindowA("STATIC",
                          "Enter domain only - e.g.  code.org   (no https://, no www., no /path)",
                          WS_CHILD|WS_VISIBLE|SS_LEFTNOWORDWRAP,
                          120, 130, 500, 16, hwnd, NULL, hi, NULL);
            /* Domain list */
            g_lv = CreateWindowExA(WS_EX_CLIENTEDGE, WC_LISTVIEWA, "",
                                   WS_CHILD|WS_VISIBLE|LVS_REPORT|LVS_SHOWSELALWAYS|LVS_SINGLESEL,
                                   15, 148, 610, 220, hwnd, (HMENU)ID_LV, hi, NULL);
            ListView_SetExtendedListViewStyle(g_lv,
                LVS_EX_CHECKBOXES | LVS_EX_FULLROWSELECT);
            LVCOLUMNA col = {0};
            col.mask    = LVCF_TEXT | LVCF_WIDTH;
            col.cx      = 580;
            col.pszText = "Allowed URLs";
            ListView_InsertColumn(g_lv, 0, &col);
            /* Bottom row — 5 equal buttons (120px each, 2px gaps) */
            g_btn_remove  = CreateWindowA("BUTTON", "Remove selected",
                                          WS_CHILD|WS_VISIBLE, 15,  378, 120, 26,
                                          hwnd, (HMENU)ID_BTN_REMOVE, hi, NULL);
            g_btn_import  = CreateWindowA("BUTTON", "Import from JSON",
                                          WS_CHILD|WS_VISIBLE, 137, 378, 120, 26,
                                          hwnd, (HMENU)ID_BTN_IMPORT, hi, NULL);
            g_btn_export  = CreateWindowA("BUTTON", "Export to JSON",
                                          WS_CHILD|WS_VISIBLE, 259, 378, 120, 26,
                                          hwnd, (HMENU)ID_BTN_EXPORT, hi, NULL);
            g_btn_presets = CreateWindowA("BUTTON", "Block Lists",
                                          WS_CHILD|WS_VISIBLE, 381, 378, 120, 26,
                                          hwnd, (HMENU)ID_BTN_PRESETS, hi, NULL);
            g_btn_chgpwd  = CreateWindowA("BUTTON", "Change Password",
                                          WS_CHILD|WS_VISIBLE, 503, 378, 122, 26,
                                          hwnd, (HMENU)ID_BTN_CHGPWD, hi, NULL);
            /* Separator */
            CreateWindowExA(0, "STATIC", "", WS_CHILD|WS_VISIBLE|SS_ETCHEDHORZ,
                            15, 412, 610, 2, hwnd, NULL, hi, NULL);
            /* Service status + install/uninstall — always visible, no login needed */
            g_static_svc = CreateWindowA("STATIC", "Service: checking...",
                                         WS_CHILD|WS_VISIBLE,
                                         15, 423, 220, 20, hwnd, (HMENU)ID_STATIC_SVC, hi, NULL);
            g_btn_install = CreateWindowA("BUTTON", "Install Service",
                                          WS_CHILD|WS_VISIBLE,
                                          245, 421, 170, 28, hwnd, (HMENU)ID_BTN_INSTALL, hi, NULL);
            g_btn_uninstall = CreateWindowA("BUTTON", "Uninstall Service",
                                            WS_CHILD|WS_VISIBLE,
                                            423, 421, 182, 28, hwnd, (HMENU)ID_BTN_UNINSTALL, hi, NULL);
            /* Set initial radio state (config already loaded before CreateWindow) */
            SendMessage(g_radio_white, BM_SETCHECK, BST_CHECKED, 0);
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
