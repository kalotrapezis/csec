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
#define VERSION      "0.0.1c Alpha"
#define PROXY_PORT   8080

static char g_config_path[MAX_PATH];

static void resolve_config_path(void) {
    char exe[MAX_PATH];
    GetModuleFileNameA(NULL, exe, MAX_PATH);
    char *sep = strrchr(exe, '\\');
    if (sep) *(sep + 1) = '\0';
    snprintf(g_config_path, MAX_PATH, "%s%s", exe, CONFIG_FILE);
}

/* =========================================================================
   Registry — set / clear system proxy
   ========================================================================= */

#define INET_KEY     "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings"
#define POLICY_KEY   "SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings"
#define HKLM_INET    "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings"

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

/* =========================================================================
   Proxy server
   ========================================================================= */

#define RECV_TIMEOUT_MS 10000
#define BUF_SIZE        8192

static CSec_Config  g_cfg;
static CRITICAL_SECTION g_cfg_lock;
static volatile int g_running = 1;

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

    registry_set_proxy(1); /* set HKCU now, while running as real admin user */
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
    registry_set_proxy(0);
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

/* Window width/height (client area) */
#define WIN_W 640
#define WIN_H 430

static HWND g_hwnd;
static HWND g_edit_pass, g_btn_login;
static HWND g_edit_url,  g_btn_add;
static HWND g_lv;
static HWND g_btn_remove, g_btn_import, g_btn_export, g_btn_chgpwd;
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

static void lv_refresh(void) {
    ListView_DeleteAllItems(g_lv);
    for (int i = 0; i < g_acfg.count; i++) {
        LVITEMA it = {0};
        it.mask    = LVIF_TEXT;
        it.iItem   = i;
        it.pszText = g_acfg.domains[i];
        ListView_InsertItem(g_lv, &it);
    }
}

static void enable_controls(int on) {
    EnableWindow(g_edit_url,   on);
    EnableWindow(g_btn_add,    on);
    EnableWindow(g_lv,         on);
    EnableWindow(g_btn_remove, on);
    EnableWindow(g_btn_import, on);
    EnableWindow(g_btn_export, on);
    EnableWindow(g_btn_chgpwd, on);
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
            /* Row 2 — add URL */
            CreateWindowA("STATIC", "URL", WS_CHILD|WS_VISIBLE,
                          15, 56, 100, 18, hwnd, NULL, hi, NULL);
            g_edit_url = CreateWindowA("EDIT", "", WS_CHILD|WS_VISIBLE|WS_BORDER,
                                       120, 53, 370, 24, hwnd, (HMENU)ID_EDIT_URL, hi, NULL);
            g_btn_add  = CreateWindowA("BUTTON", "Add", WS_CHILD|WS_VISIBLE,
                                       500, 53, 114, 24, hwnd, (HMENU)ID_BTN_ADD, hi, NULL);
            /* Hint below URL field */
            CreateWindowA("STATIC",
                          "Enter domain only — e.g.  code.org   (no https://, no www., no /path)",
                          WS_CHILD|WS_VISIBLE|SS_LEFTNOWORDWRAP,
                          120, 80, 500, 16, hwnd, NULL, hi, NULL);
            /* Domain list */
            g_lv = CreateWindowExA(WS_EX_CLIENTEDGE, WC_LISTVIEWA, "",
                                   WS_CHILD|WS_VISIBLE|LVS_REPORT|LVS_SHOWSELALWAYS|LVS_SINGLESEL,
                                   15, 100, 610, 240, hwnd, (HMENU)ID_LV, hi, NULL);
            ListView_SetExtendedListViewStyle(g_lv,
                LVS_EX_CHECKBOXES | LVS_EX_FULLROWSELECT);
            LVCOLUMNA col = {0};
            col.mask    = LVCF_TEXT | LVCF_WIDTH;
            col.cx      = 580;
            col.pszText = "Allowed URLs";
            ListView_InsertColumn(g_lv, 0, &col);
            /* Bottom row — 4 equal buttons */
            g_btn_remove = CreateWindowA("BUTTON", "Remove selected",
                                         WS_CHILD|WS_VISIBLE, 15,  350, 146, 26,
                                         hwnd, (HMENU)ID_BTN_REMOVE, hi, NULL);
            g_btn_import = CreateWindowA("BUTTON", "Import from JSON",
                                         WS_CHILD|WS_VISIBLE, 169, 350, 146, 26,
                                         hwnd, (HMENU)ID_BTN_IMPORT, hi, NULL);
            g_btn_export = CreateWindowA("BUTTON", "Export to JSON",
                                         WS_CHILD|WS_VISIBLE, 323, 350, 146, 26,
                                         hwnd, (HMENU)ID_BTN_EXPORT, hi, NULL);
            g_btn_chgpwd = CreateWindowA("BUTTON", "Change Password",
                                         WS_CHILD|WS_VISIBLE, 477, 350, 148, 26,
                                         hwnd, (HMENU)ID_BTN_CHGPWD, hi, NULL);
            /* Separator */
            CreateWindowExA(0, "STATIC", "", WS_CHILD|WS_VISIBLE|SS_ETCHEDHORZ,
                            15, 384, 610, 2, hwnd, NULL, hi, NULL);
            /* Service status + install/uninstall — always visible, no login needed */
            g_static_svc = CreateWindowA("STATIC", "Service: checking...",
                                         WS_CHILD|WS_VISIBLE,
                                         15, 395, 220, 20, hwnd, (HMENU)ID_STATIC_SVC, hi, NULL);
            g_btn_install = CreateWindowA("BUTTON", "Install Service",
                                          WS_CHILD|WS_VISIBLE,
                                          245, 393, 170, 28, hwnd, (HMENU)ID_BTN_INSTALL, hi, NULL);
            g_btn_uninstall = CreateWindowA("BUTTON", "Uninstall Service",
                                            WS_CHILD|WS_VISIBLE,
                                            423, 393, 182, 28, hwnd, (HMENU)ID_BTN_UNINSTALL, hi, NULL);
            enable_controls(FALSE);
            SetFocus(g_edit_pass);
            return 0;
        }
        case WM_COMMAND:
            switch (LOWORD(wp)) {
                case ID_BTN_LOGIN:  do_login();           break;
                case ID_BTN_ADD:    if (g_logged_in) do_add();             break;
                case ID_BTN_REMOVE: if (g_logged_in) do_remove_selected(); break;
                case ID_BTN_IMPORT: if (g_logged_in) do_import();          break;
                case ID_BTN_EXPORT: if (g_logged_in) do_export();          break;
                case ID_BTN_CHGPWD: if (g_logged_in) do_change_password(); break;
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
