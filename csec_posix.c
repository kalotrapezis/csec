/*
 * csec_posix.c — Linux frontend for CSec (Classroom Web Filter).
 *
 * Same proxy engine as Windows (proxy.c); here it runs as a systemd service
 * and is administered from the command line. The student-facing proxy is
 * enforced through the desktop proxy settings (GNOME/Cinnamon gsettings and
 * KDE kioslaverc) plus /etc/environment, mirroring the Windows registry path.
 *
 * Usage:
 *   sudo csec install            Install + start the service, turn on the proxy
 *   sudo csec uninstall          Stop + remove the service, restore the proxy
 *   csec status                  Show service + filter status
 *   sudo csec add <domain>       Add a domain to the list
 *   sudo csec remove <domain>    Remove a domain
 *   csec list                    Show the domain list
 *   sudo csec mode white|black   Whitelist / blacklist
 *   sudo csec safesearch on|off
 *   sudo csec youtube off|moderate|strict
 *   csec lists                   Show available block lists
 *   sudo csec lists enable|disable <name>
 *   sudo csec passwd             Change admin password
 *   sudo csec reset-password     Reset password to 123456
 *   sudo csec import <file>      Import a config JSON
 *   csec export <file>           Export the current config JSON
 *   csec daemon                  Run the proxy (used by systemd)
 */

#include "proxy.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <pwd.h>
#include <dirent.h>
#include <termios.h>
#include <sys/stat.h>
#include <sys/types.h>

#define LOCAL_BIN     "/usr/local/bin/csec"   /* where a manual `csec install` copies to */
#define UNIT_PATH     "/etc/systemd/system/csec.service"  /* manual-install unit */
#define CONFIG_DIR    "/etc/csec"
#define SYS_LISTS     "/usr/share/csec/lists" /* block lists shipped by the .deb/.rpm */
#define PROFILE_D     "/etc/profile.d/csec-proxy.sh"
#define ENV_FILE      "/etc/environment"
#define DEFAULT_HASH  "8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92"

#define PROXY_URL  "http://127.0.0.1:8080"
#define NOPROXY    "localhost,127.0.0.1,::1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,169.254.0.0/16"
#define BLK_BEGIN  "# >>> CSec proxy >>>"
#define BLK_END    "# <<< CSec proxy <<<"

/* =========================================================================
   Small helpers
   ========================================================================= */

/* Implemented in transparent.c */
void transparent_start(void);
int  nft_rules(int enable);

static int need_root(void);   /* defined below */

static int is_root(void) { return geteuid() == 0; }

/* The real (non-root) user behind a sudo invocation, or NULL. */
static const char *target_user(void) {
    const char *u = getenv("SUDO_USER");
    if (u && *u && strcmp(u, "root") != 0) return u;
    return NULL;
}

static int run(const char *cmd) { return system(cmd); }

static int dir_exists(const char *p) {
    struct stat st;
    return stat(p, &st) == 0 && S_ISDIR(st.st_mode);
}

/* True when the running binary was installed by a system package (/usr, but
   not /usr/local). In that case the package owns the binary + unit + lists. */
static int packaged(void) {
    char self[MAX_PATH];
    if (readlink("/proc/self/exe", self, sizeof(self) - 1) <= 0) return 0;
    return strncmp(self, "/usr/", 5) == 0 && strncmp(self, "/usr/local/", 11) != 0;
}

/* =========================================================================
   Frontend hooks required by the shared engine (proxy.h)
   ========================================================================= */

void resolve_config_path(void) {
    const char *c = getenv("CSEC_CONFIG");
    const char *l = getenv("CSEC_LISTS");
    if (c) snprintf(g_config_path, MAX_PATH, "%s", c);
    else   snprintf(g_config_path, MAX_PATH, "%s/%s", CONFIG_DIR, CONFIG_FILE);
    if (l)                              snprintf(g_lists_dir, MAX_PATH, "%s", l);
    else if (dir_exists(CONFIG_DIR "/lists")) snprintf(g_lists_dir, MAX_PATH, "%s/lists", CONFIG_DIR);
    else                                snprintf(g_lists_dir, MAX_PATH, "%s", SYS_LISTS);
}

/* =========================================================================
   Proxy enforcement — desktop settings + environment
   ========================================================================= */

/* Rewrite a marker-delimited block in a file. content == NULL removes it. */
static void update_block(const char *path, const char *content) {
    FILE *f = fopen(path, "rb");
    char *body = NULL; size_t cap = 0, len = 0;
    if (f) {
        char buf[4096]; size_t r;
        while ((r = fread(buf, 1, sizeof(buf), f)) > 0) {
            if (len + r + 1 > cap) { cap = (len + r + 1) * 2; body = realloc(body, cap); }
            memcpy(body + len, buf, r); len += r;
        }
        fclose(f);
    }
    if (body) body[len] = '\0';

    FILE *o = fopen(path, "wb");
    if (!o) { free(body); return; }

    /* Copy original, skipping any existing CSec block. */
    if (body) {
        char *b = strstr(body, BLK_BEGIN);
        if (b) {
            char *e = strstr(b, BLK_END);
            fwrite(body, 1, (size_t)(b - body), o);
            if (e) {
                e += strlen(BLK_END);
                if (*e == '\n') e++;
                fputs(e, o);
            }
        } else {
            fputs(body, o);
            if (len && body[len-1] != '\n') fputc('\n', o);
        }
    }
    if (content) {
        fprintf(o, "%s\n%s%s\n", BLK_BEGIN, content, BLK_END);
    }
    fclose(o);
    free(body);
}

/* System-wide proxy via /etc/environment + a profile.d script (no session
   needed — survives reboot, picked up by PAM/login shells). */
static void env_proxy(int enable) {
    if (enable) {
        char block[1024];
        snprintf(block, sizeof(block),
            "http_proxy=%s\nhttps_proxy=%s\nftp_proxy=%s\nno_proxy=%s\n"
            "HTTP_PROXY=%s\nHTTPS_PROXY=%s\nFTP_PROXY=%s\nNO_PROXY=%s\n",
            PROXY_URL, PROXY_URL, PROXY_URL, NOPROXY,
            PROXY_URL, PROXY_URL, PROXY_URL, NOPROXY);
        update_block(ENV_FILE, block);

        FILE *p = fopen(PROFILE_D, "wb");
        if (p) {
            fprintf(p,
                "# Installed by CSec — classroom web filter\n"
                "export http_proxy=%s https_proxy=%s ftp_proxy=%s no_proxy=%s\n"
                "export HTTP_PROXY=%s HTTPS_PROXY=%s FTP_PROXY=%s NO_PROXY=%s\n",
                PROXY_URL, PROXY_URL, PROXY_URL, NOPROXY,
                PROXY_URL, PROXY_URL, PROXY_URL, NOPROXY);
            fclose(p);
            chmod(PROFILE_D, 0644);
        }
    } else {
        update_block(ENV_FILE, NULL);
        unlink(PROFILE_D);
    }
}

/* Run a command in the target user's session (for gsettings/KDE dconf). */
static void run_as_user(const struct passwd *pw, const char *cmd) {
    char full[2048];
    snprintf(full, sizeof(full),
        "sudo -u %s env DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/%u/bus "
        "XDG_RUNTIME_DIR=/run/user/%u %s",
        pw->pw_name, (unsigned)pw->pw_uid, (unsigned)pw->pw_uid, cmd);
    run(full);
}

/* GNOME / Cinnamon (Linux Mint) proxy via gsettings. */
static void gnome_proxy(const struct passwd *pw, int enable) {
    if (enable) {
        run_as_user(pw, "gsettings set org.gnome.system.proxy mode 'manual'");
        run_as_user(pw, "gsettings set org.gnome.system.proxy.http host '127.0.0.1'");
        run_as_user(pw, "gsettings set org.gnome.system.proxy.http port 8080");
        run_as_user(pw, "gsettings set org.gnome.system.proxy.https host '127.0.0.1'");
        run_as_user(pw, "gsettings set org.gnome.system.proxy.https port 8080");
        run_as_user(pw, "gsettings set org.gnome.system.proxy.ftp host '127.0.0.1'");
        run_as_user(pw, "gsettings set org.gnome.system.proxy.ftp port 8080");
        run_as_user(pw, "gsettings set org.gnome.system.proxy ignore-hosts "
            "\"['localhost','127.0.0.0/8','10.0.0.0/8','172.16.0.0/12',"
            "'192.168.0.0/16','169.254.0.0/16','::1']\"");
    } else {
        run_as_user(pw, "gsettings set org.gnome.system.proxy mode 'none'");
    }
}

/* KDE Plasma (Fedora KDE) proxy via kioslaverc. */
static void kde_write(const struct passwd *pw, const char *key, const char *val) {
    char cmd[1024];
    snprintf(cmd, sizeof(cmd),
        "sh -c \"kwriteconfig6 --file kioslaverc --group 'Proxy Settings' --key %s '%s' "
        "2>/dev/null || kwriteconfig5 --file kioslaverc --group 'Proxy Settings' --key %s '%s' 2>/dev/null\"",
        key, val, key, val);
    run_as_user(pw, cmd);
}

static void kde_proxy(const struct passwd *pw, int enable) {
    if (enable) {
        kde_write(pw, "ProxyType", "1");
        kde_write(pw, "httpProxy",  "http://127.0.0.1 8080");
        kde_write(pw, "httpsProxy", "http://127.0.0.1 8080");
        kde_write(pw, "ftpProxy",   "http://127.0.0.1 8080");
        kde_write(pw, "socksProxy", "http://127.0.0.1 8080");
        kde_write(pw, "NoProxyFor", NOPROXY);
        kde_write(pw, "ReversedException", "false");
    } else {
        kde_write(pw, "ProxyType", "0");
    }
}

/* Set the proxy for the desktop user (GNOME/Cinnamon + KDE). */
static void desktop_proxy(int enable) {
    const char *u = target_user();
    if (!u) return;                 /* not run via sudo — env layer still applies */
    struct passwd *pw = getpwnam(u);
    if (!pw) return;
    gnome_proxy(pw, enable);
    kde_proxy(pw, enable);
}

/* Hook called by proxy_run() on every daemon start (running as root).
   Transparent mode re-asserts the nftables redirect; classic mode re-asserts
   the system-wide env proxy. Per-user desktop settings persist from install. */
void platform_enforce_proxy(int enable) {
    if (g_cfg.transparent) nft_rules(enable);
    else                   env_proxy(enable);
}

/* Apply the full enforcement for a given config (run at install/setup time,
   where we have the invoking user's session for the desktop settings). */
static void apply_enforcement(const CSec_Config *cfg) {
    if (cfg->transparent) {
        /* clear any classic-mode leftovers, then install the redirect */
        env_proxy(0);
        desktop_proxy(0);
        if (nft_rules(1) != 0)
            fprintf(stderr, "Warning: failed to install nftables rules (is `nft` present?).\n");
    } else {
        nft_rules(0);
        env_proxy(1);
        desktop_proxy(1);
    }
}

/* Remove all enforcement (both modes), used on uninstall / package removal. */
static void clear_enforcement(void) {
    nft_rules(0);
    env_proxy(0);
    desktop_proxy(0);
}

/* =========================================================================
   Service install / uninstall (systemd)
   ========================================================================= */

static int exe_path(char *out, size_t len) {
    ssize_t n = readlink("/proc/self/exe", out, len - 1);
    if (n <= 0) return 0;
    out[n] = '\0';
    return 1;
}

static int copy_file(const char *src, const char *dst, mode_t mode) {
    FILE *in = fopen(src, "rb");
    if (!in) return 0;
    FILE *out = fopen(dst, "wb");
    if (!out) { fclose(in); return 0; }
    char buf[8192]; size_t r;
    while ((r = fread(buf, 1, sizeof(buf), in)) > 0) fwrite(buf, 1, r, out);
    fclose(in); fclose(out);
    chmod(dst, mode);
    return 1;
}

/* Locate the bundled Lists directory next to the running binary or in CWD. */
static int find_lists_src(char *out, size_t len) {
    const char *l = getenv("CSEC_LISTS");
    if (l) { snprintf(out, len, "%s", l); return 1; }
    char exe[MAX_PATH];
    char dir[MAX_PATH];
    if (exe_path(exe, sizeof(exe))) {
        snprintf(dir, sizeof(dir), "%s", exe);
        char *slash = strrchr(dir, '/');
        if (slash) *slash = '\0';
        const char *names[] = { "Lists", "lists" };
        for (int i = 0; i < 2; i++) {
            snprintf(out, len, "%s/%s", dir, names[i]);
            struct stat st;
            if (stat(out, &st) == 0 && S_ISDIR(st.st_mode)) return 1;
        }
    }
    const char *cwd_names[] = { "Lists", "lists" };
    for (int i = 0; i < 2; i++) {
        struct stat st;
        if (stat(cwd_names[i], &st) == 0 && S_ISDIR(st.st_mode)) {
            snprintf(out, len, "%s", cwd_names[i]); return 1;
        }
    }
    return 0;
}

static void write_unit(const char *binpath) {
    FILE *f = fopen(UNIT_PATH, "wb");
    if (!f) { perror("write unit"); return; }
    fprintf(f,
        "[Unit]\n"
        "Description=CSec Classroom Web Filter\n"
        "After=network-online.target\n"
        "Wants=network-online.target\n\n"
        "[Service]\n"
        "Type=simple\n"
        "ExecStart=%s daemon\n"
        "ExecReload=/bin/kill -HUP $MAINPID\n"
        "Restart=always\n"
        "RestartSec=2\n\n"
        "[Install]\n"
        "WantedBy=multi-user.target\n",
        binpath);
    fclose(f);
}

/* Create the config dir + a default config if none exists. */
static void ensure_config(void) {
    mkdir(CONFIG_DIR, 0755);
    resolve_config_path();
    struct stat st;
    if (stat(g_config_path, &st) != 0) {
        CSec_Config cfg;
        config_load(&cfg, g_config_path);  /* fills defaults even if file missing */
        config_save(&cfg, g_config_path);
        printf("Created default config: %s (password: 123456)\n", g_config_path);
    }
}

static int run_setup(void);   /* guided first-run wizard, defined below */

static int cmd_install(void) {
    if (!is_root()) { fprintf(stderr, "Run as root: sudo csec install\n"); return 1; }

    if (!packaged()) {
        /* Manual install: place binary, lists and unit ourselves. */
        char self[MAX_PATH];
        if (exe_path(self, sizeof(self)) && strcmp(self, LOCAL_BIN) != 0) {
            if (!copy_file(self, LOCAL_BIN, 0755))
                fprintf(stderr, "Warning: could not copy binary to %s\n", LOCAL_BIN);
        }
        char lists_dst[MAX_PATH];
        snprintf(lists_dst, sizeof(lists_dst), "%s/lists", CONFIG_DIR);
        mkdir(CONFIG_DIR, 0755);
        mkdir(lists_dst, 0755);
        char lists_src[MAX_PATH];
        if (find_lists_src(lists_src, sizeof(lists_src))) {
            char cp[MAX_PATH * 2];
            snprintf(cp, sizeof(cp), "cp -f '%s'/*.txt '%s'/ 2>/dev/null", lists_src, lists_dst);
            run(cp);
            printf("Block lists installed to %s\n", lists_dst);
        } else {
            printf("No bundled Lists/ folder found — using %s if present.\n", SYS_LISTS);
        }
        write_unit(LOCAL_BIN);
    }
    /* Packaged install: binary, unit (/usr/lib/systemd) and lists (/usr/share)
       are already in place from the .deb/.rpm — nothing to copy. */

    ensure_config();

    run("systemctl daemon-reload");
    if (run("systemctl enable --now csec.service") != 0)
        fprintf(stderr, "Warning: failed to start service via systemctl\n");

    printf("\nCSec installed.\n"
           "  Config : %s\n"
           "  Lists  : %s\n\n", g_config_path, g_lists_dir);

    /* The wizard chooses the mode (incl. enforcement) and applies it itself.
       Non-interactive installs fall back to the saved/default config. */
    if (isatty(STDIN_FILENO)) {
        run_setup();
    } else {
        CSec_Config cfg; config_load(&cfg, g_config_path);
        apply_enforcement(&cfg);
        run("systemctl restart csec.service 2>/dev/null");
        printf("Run  sudo csec setup  to choose a mode and password.\n");
    }

    printf("\nLog out and back in so all apps pick up the change.\n");
    return 0;
}

/* Turn the filter off: stop the service and restore the proxy. Does NOT remove
   package-owned files (the binary / unit / lists) — that's the package manager's
   job. For a manual install it also removes the files we created. */
static int cmd_uninstall(void) {
    if (!is_root()) { fprintf(stderr, "Run as root: sudo csec uninstall\n"); return 1; }

    run("systemctl disable --now csec.service 2>/dev/null");
    clear_enforcement();

    if (!packaged()) {
        unlink(UNIT_PATH);
        run("systemctl daemon-reload");
        unlink(LOCAL_BIN);
    }

    printf("CSec stopped and proxy restored.\n"
           "Settings kept in %s — delete it manually to remove them.\n"
           "%s"
           "Log out and back in to clear the proxy from running apps.\n",
           CONFIG_DIR,
           packaged() ? "Run your package manager (dnf/apt remove csec) to remove the files.\n" : "");
    return 0;
}

/* Internal hook for package pre-removal scriptlets: stop + restore proxy only. */
static int cmd_pkg_restore(void) {
    if (!is_root()) return 1;
    run("systemctl disable --now csec.service 2>/dev/null");
    clear_enforcement();
    return 0;
}

/* Switch enforcement mode and re-apply (needs a service restart to (re)bind
   the transparent listener / re-assert rules). */
static int cmd_enforcement(const char *arg) {
    if (!need_root()) return 1;
    CSec_Config cfg; config_load(&cfg, g_config_path);
    if      (!strcmp(arg, "transparent")) cfg.transparent = 1;
    else if (!strcmp(arg, "proxy"))       cfg.transparent = 0;
    else { fprintf(stderr, "Usage: csec enforcement proxy|transparent\n"); return 1; }
    config_save(&cfg, g_config_path);
    apply_enforcement(&cfg);
    run("systemctl restart csec.service 2>/dev/null");
    printf("Enforcement set to %s.\n", cfg.transparent
           ? "transparent (nftables redirect — forces all browsers through the filter)"
           : "proxy (desktop/system proxy settings)");
    return 0;
}

/* =========================================================================
   Config-editing commands
   ========================================================================= */

static void reload_service(void) { run("systemctl reload csec.service 2>/dev/null"); }

static int need_root(void) {
    if (!is_root()) { fprintf(stderr, "This needs root. Try: sudo csec ...\n"); return 0; }
    return 1;
}

/* enabled_lists is a space-separated token buffer in the config. */
static int el_has(const char *list, const char *name) {
    char buf[512]; snprintf(buf, sizeof(buf), " %s ", list);
    char tok[80]; snprintf(tok, sizeof(tok), " %s ", name);
    return strstr(buf, tok) != NULL;
}
static void el_add(char *list, size_t len, const char *name) {
    if (el_has(list, name)) return;
    size_t cur = strlen(list);
    snprintf(list + cur, len - cur, "%s%s", cur ? " " : "", name);
}
static void el_remove(char *list, const char *name) {
    char out[512] = {0}; char *save = NULL;
    char tmp[512]; snprintf(tmp, sizeof(tmp), "%s", list);
    for (char *t = strtok_r(tmp, " ", &save); t; t = strtok_r(NULL, " ", &save)) {
        if (strcmp(t, name) == 0) continue;
        size_t cur = strlen(out);
        snprintf(out + cur, sizeof(out) - cur, "%s%s", cur ? " " : "", t);
    }
    strcpy(list, out);
}

static int read_password(const char *prompt, char *buf, size_t len) {
    fputs(prompt, stdout); fflush(stdout);
    struct termios old, no_echo;
    int have_tty = (tcgetattr(STDIN_FILENO, &old) == 0);
    if (have_tty) { no_echo = old; no_echo.c_lflag &= ~(tcflag_t)ECHO;
                    tcsetattr(STDIN_FILENO, TCSAFLUSH, &no_echo); }
    if (!fgets(buf, (int)len, stdin)) { if (have_tty) tcsetattr(STDIN_FILENO, TCSAFLUSH, &old); return 0; }
    if (have_tty) { tcsetattr(STDIN_FILENO, TCSAFLUSH, &old); fputc('\n', stdout); }
    buf[strcspn(buf, "\r\n")] = '\0';
    return 1;
}

static int cmd_add(const char *arg) {
    if (!need_root()) return 1;
    CSec_Config cfg; config_load(&cfg, g_config_path);
    char dom[MAX_DOMAIN_LEN]; normalize_domain(arg, dom, sizeof(dom));
    if (!dom[0]) { fprintf(stderr, "Empty domain.\n"); return 1; }
    if (!domain_add(&cfg, dom)) { printf("Already present (or list full): %s\n", dom); return 0; }
    printf("Added: %s\n", dom);
    int b = bundle_find(dom);
    if (b >= 0)
        for (int i = 0; BUNDLES[b].extras[i]; i++)
            if (domain_add(&cfg, BUNDLES[b].extras[i]))
                printf("  + %s (required by %s)\n", BUNDLES[b].extras[i], dom);
    config_save(&cfg, g_config_path);
    reload_service();
    return 0;
}

static int cmd_remove(const char *arg) {
    if (!need_root()) return 1;
    CSec_Config cfg; config_load(&cfg, g_config_path);
    char dom[MAX_DOMAIN_LEN]; normalize_domain(arg, dom, sizeof(dom));
    if (domain_remove(&cfg, dom)) { printf("Removed: %s\n", dom); config_save(&cfg, g_config_path); reload_service(); }
    else printf("Not found: %s\n", dom);
    return 0;
}

static int cmd_list(void) {
    CSec_Config cfg; config_load(&cfg, g_config_path);
    printf("Mode: %s\n", cfg.blacklist_mode ? "blacklist (allow all except list)"
                                            : "whitelist (block all except list)");
    printf("Domains (%d):\n", cfg.count);
    for (int i = 0; i < cfg.count; i++) printf("  %s\n", cfg.domains[i]);
    return 0;
}

static int cmd_mode(const char *arg) {
    if (!need_root()) return 1;
    CSec_Config cfg; config_load(&cfg, g_config_path);
    if      (!strcmp(arg, "white") || !strcmp(arg, "whitelist")) cfg.blacklist_mode = 0;
    else if (!strcmp(arg, "black") || !strcmp(arg, "blacklist")) cfg.blacklist_mode = 1;
    else { fprintf(stderr, "Usage: csec mode whitelist|blacklist\n"); return 1; }
    config_save(&cfg, g_config_path); reload_service();
    printf("Mode set to %s.\n", cfg.blacklist_mode ? "blacklist" : "whitelist");
    return 0;
}

static int cmd_safesearch(const char *arg) {
    if (!need_root()) return 1;
    CSec_Config cfg; config_load(&cfg, g_config_path);
    if      (!strcmp(arg, "on"))  cfg.safesearch = 1;
    else if (!strcmp(arg, "off")) cfg.safesearch = 0;
    else { fprintf(stderr, "Usage: csec safesearch on|off\n"); return 1; }
    config_save(&cfg, g_config_path); reload_service();
    printf("SafeSearch %s.\n", cfg.safesearch ? "enabled" : "disabled");
    return 0;
}

static int cmd_youtube(const char *arg) {
    if (!need_root()) return 1;
    CSec_Config cfg; config_load(&cfg, g_config_path);
    if      (!strcmp(arg, "off"))      cfg.youtube_mode = 0;
    else if (!strcmp(arg, "moderate")) cfg.youtube_mode = 1;
    else if (!strcmp(arg, "strict"))   cfg.youtube_mode = 2;
    else { fprintf(stderr, "Usage: csec youtube off|moderate|strict\n"); return 1; }
    config_save(&cfg, g_config_path); reload_service();
    printf("YouTube Restricted Mode: %s.\n",
           cfg.youtube_mode == 0 ? "off" : cfg.youtube_mode == 1 ? "moderate" : "strict");
    return 0;
}

/* Does a category list file (e.g. "porn") exist in the lists dir? */
static int list_file_exists(const char *name) {
    char path[MAX_PATH];
    snprintf(path, sizeof(path), "%s/%s.txt", g_lists_dir, name);
    struct stat st;
    return stat(path, &st) == 0;
}

/* Turn blocking of a category on (block=1) or off (block=0). */
static int set_block_list(const char *name, int block) {
    if (!need_root()) return 1;
    CSec_Config cfg; config_load(&cfg, g_config_path);
    if (block && !list_file_exists(name)) {
        fprintf(stderr, "No such category list: %s\nRun  csec lists  to see what's available.\n", name);
        return 1;
    }
    if (block) el_add(cfg.enabled_lists, sizeof(cfg.enabled_lists), name);
    else       el_remove(cfg.enabled_lists, name);
    config_save(&cfg, g_config_path); reload_service();

    printf("%s is now %s.\n", name, block ? "BLOCKED" : "allowed");
    if (block && !cfg.blacklist_mode)
        printf("\n  Heads up: you're in WHITELIST mode, where everything is already\n"
               "  blocked unless you allow it — so category block lists do nothing.\n"
               "  Switch with:  sudo csec mode blacklist\n");
    return 0;
}

static int cmd_block(const char *name)   { return set_block_list(name, 1); }
static int cmd_unblock(const char *name) { return set_block_list(name, 0); }

/* Show every category list and whether it is currently blocked. */
static int cmd_lists(void) {
    CSec_Config cfg; config_load(&cfg, g_config_path);
    DIR *d = opendir(g_lists_dir);
    if (!d) { fprintf(stderr, "Cannot open %s\n", g_lists_dir); return 1; }
    printf("Category block lists (block these kinds of sites):\n\n");
    struct dirent *e;
    int any_on = 0;
    while ((e = readdir(d))) {
        size_t n = strlen(e->d_name);
        if (n < 5 || strcmp(e->d_name + n - 4, ".txt") != 0) continue;
        if (e->d_name[0] == '_') continue; /* _priority.txt is always loaded */
        char name[80]; snprintf(name, sizeof(name), "%.*s", (int)(n - 4), e->d_name);
        int on = el_has(cfg.enabled_lists, name);
        if (on) any_on = 1;
        printf("  %-12s %s\n", name, on ? "BLOCKED" : "allowed");
    }
    closedir(d);
    printf("\n  Block a category:    sudo csec block porn\n");
    printf(  "  Stop blocking it:    sudo csec unblock porn\n");
    if (!cfg.blacklist_mode)
        printf("\n  Note: these only take effect in BLACKLIST mode (you're in whitelist).\n"
               "        In whitelist mode everything is blocked unless you `csec add` it.\n");
    else if (!any_on)
        printf("\n  Nothing is being blocked yet.\n");
    return 0;
}

static int cmd_passwd(void) {
    if (!need_root()) return 1;
    CSec_Config cfg; config_load(&cfg, g_config_path);
    char cur[128], n1[128], n2[128], hash[65];
    if (!read_password("Current password: ", cur, sizeof(cur))) return 1;
    sha256_hex(cur, hash);
    if (strcmp(hash, cfg.admin_hash) != 0) { fprintf(stderr, "Wrong password.\n"); return 1; }
    if (!read_password("New password: ", n1, sizeof(n1))) return 1;
    if (!read_password("Repeat new password: ", n2, sizeof(n2))) return 1;
    if (strcmp(n1, n2) != 0) { fprintf(stderr, "Passwords do not match.\n"); return 1; }
    if (!n1[0]) { fprintf(stderr, "Empty password not allowed.\n"); return 1; }
    sha256_hex(n1, cfg.admin_hash);
    config_save(&cfg, g_config_path);
    printf("Password changed.\n");
    return 0;
}

static int cmd_reset_password(void) {
    if (!need_root()) return 1;
    CSec_Config cfg; config_load(&cfg, g_config_path);
    strcpy(cfg.admin_hash, DEFAULT_HASH);
    config_save(&cfg, g_config_path);
    printf("Password reset to: 123456\n");
    return 0;
}

static int cmd_import(const char *file) {
    if (!need_root()) return 1;
    CSec_Config cfg;
    if (!config_load(&cfg, file)) { fprintf(stderr, "Cannot read %s\n", file); return 1; }
    config_save(&cfg, g_config_path); reload_service();
    printf("Imported %d domains from %s\n", cfg.count, file);
    return 0;
}

static int cmd_export(const char *file) {
    CSec_Config cfg; config_load(&cfg, g_config_path);
    if (!config_save(&cfg, file)) { fprintf(stderr, "Cannot write %s\n", file); return 1; }
    printf("Exported %d domains to %s\n", cfg.count, file);
    return 0;
}

static int cmd_status(void) {
    int active = (run("systemctl is-active --quiet csec.service") == 0);
    CSec_Config cfg; int have = config_load(&cfg, g_config_path);
    printf("Service : %s\n", active ? "running" : "stopped / not installed");
    printf("Config  : %s%s\n", g_config_path, have ? "" : " (missing — using defaults)");
    printf("Enforce : %s\n", cfg.transparent ? "transparent (nftables redirect)" : "proxy (desktop/system)");
    printf("Mode    : %s\n", cfg.blacklist_mode ? "blacklist" : "whitelist");
    printf("Domains : %d\n", cfg.count);
    printf("SafeSrch: %s\n", cfg.safesearch ? "on" : "off");
    printf("YouTube : %s\n", cfg.youtube_mode == 0 ? "off" : cfg.youtube_mode == 1 ? "moderate" : "strict");
    printf("Lists   : %s\n", cfg.enabled_lists[0] ? cfg.enabled_lists : "(none)");
    return 0;
}

/* =========================================================================
   Guided setup wizard  (csec setup)
   ========================================================================= */

#define MAX_CAT 64

/* Read one line from stdin. Returns 0 on EOF. */
static int ask_line(char *buf, size_t len) {
    if (!fgets(buf, (int)len, stdin)) { buf[0] = '\0'; return 0; }
    buf[strcspn(buf, "\r\n")] = '\0';
    return 1;
}

/* Yes/No prompt. def = default when the user just presses Enter. */
static int ask_yn(const char *q, int def) {
    char b[32];
    for (;;) {
        printf("%s %s ", q, def ? "[Y/n]" : "[y/N]"); fflush(stdout);
        if (!ask_line(b, sizeof(b))) return def;
        if (!b[0]) return def;
        if (b[0] == 'y' || b[0] == 'Y') return 1;
        if (b[0] == 'n' || b[0] == 'N') return 0;
        printf("  Please answer y or n.\n");
    }
}

static int name_cmp(const void *a, const void *b) {
    return strcmp((const char *)a, (const char *)b);
}

/* Collect category list names (sorted) from the lists dir. Returns count. */
static int scan_lists(char names[][80], int max) {
    DIR *d = opendir(g_lists_dir);
    if (!d) return 0;
    int n = 0; struct dirent *e;
    while ((e = readdir(d)) && n < max) {
        size_t L = strlen(e->d_name);
        if (L < 5 || strcmp(e->d_name + L - 4, ".txt") != 0) continue;
        if (e->d_name[0] == '_') continue;
        snprintf(names[n], 80, "%.*s", (int)(L - 4), e->d_name);
        n++;
    }
    closedir(d);
    qsort(names, n, 80, name_cmp);
    return n;
}

/* Enable every list (optionally all-but-ads) into cfg->enabled_lists. */
static void enable_all_lists(CSec_Config *cfg, int except_ads) {
    char names[MAX_CAT][80];
    int n = scan_lists(names, MAX_CAT);
    cfg->enabled_lists[0] = '\0';
    for (int i = 0; i < n; i++) {
        if (except_ads && strcmp(names[i], "ads") == 0) continue;
        el_add(cfg->enabled_lists, sizeof(cfg->enabled_lists), names[i]);
    }
}

/* Parse a selection line like "Block 1,2,3", "Allow 2 3", "Block * && Allow 2".
   Any non-digit separates numbers (so dots/commas/spaces all work). */
static void parse_selection(const char *line, char names[][80], int n,
                            char *enabled, size_t elen) {
    int blocked[MAX_CAT];
    for (int i = 0; i < n; i++) blocked[i] = el_has(enabled, names[i]);

    const char *p = line;
    while (*p) {
        const char *amp = strstr(p, "&&");
        char clause[256];
        size_t cl = amp ? (size_t)(amp - p) : strlen(p);
        if (cl >= sizeof(clause)) cl = sizeof(clause) - 1;
        memcpy(clause, p, cl); clause[cl] = '\0';

        char *c = clause; while (*c == ' ') c++;
        int doblock = -1;
        if      (strncasecmp(c, "block", 5) == 0) { doblock = 1; c += 5; }
        else if (strncasecmp(c, "allow", 5) == 0) { doblock = 0; c += 5; }
        if (doblock >= 0) {
            if (strchr(c, '*')) {
                for (int i = 0; i < n; i++) blocked[i] = doblock;
            } else {
                while (*c) {
                    if (*c >= '0' && *c <= '9') {
                        int v = 0;
                        while (*c >= '0' && *c <= '9') { v = v * 10 + (*c - '0'); c++; }
                        if (v >= 1 && v <= n) blocked[v - 1] = doblock;
                    } else c++;
                }
            }
        }
        if (!amp) break;
        p = amp + 2;
    }

    enabled[0] = '\0';
    for (int i = 0; i < n; i++)
        if (blocked[i]) el_add(enabled, elen, names[i]);
}

static void wizard_set_password(CSec_Config *cfg) {
    if (!ask_yn("Set an admin password now (otherwise stays 123456)?", 1)) return;
    char p1[128], p2[128];
    for (;;) {
        if (!read_password("  New password: ", p1, sizeof(p1))) return;
        if (!p1[0]) { printf("  Empty password not allowed.\n"); continue; }
        if (!read_password("  Confirm password: ", p2, sizeof(p2))) return;
        if (strcmp(p1, p2) != 0) { printf("  Passwords do not match — try again.\n"); continue; }
        sha256_hex(p1, cfg->admin_hash);
        printf("  Password set.\n");
        return;
    }
}

static void wizard_add_urls(CSec_Config *cfg) {
    if (!ask_yn("Add allowed sites now (one per line)?", 0)) return;
    printf("  Type one domain per line (e.g. code.org). Blank line when done:\n");
    char line[512];
    for (;;) {
        printf("    > "); fflush(stdout);
        if (!ask_line(line, sizeof(line)) || !line[0]) break;
        char dom[MAX_DOMAIN_LEN];
        normalize_domain(line, dom, sizeof(dom));
        if (!dom[0]) continue;
        if (domain_add(cfg, dom)) {
            printf("      added %s\n", dom);
            int b = bundle_find(dom);
            if (b >= 0)
                for (int i = 0; BUNDLES[b].extras[i]; i++)
                    if (domain_add(cfg, BUNDLES[b].extras[i]))
                        printf("        + %s\n", BUNDLES[b].extras[i]);
        }
    }
}

static void show_summary(const CSec_Config *cfg) {
    printf("\n  ---- Summary ----\n");
    printf("  Mode        : %s\n", cfg->blacklist_mode ? "blacklist (allow all except blocked)"
                                                       : "whitelist (block all except allowed)");
    printf("  Enforcement : %s\n", cfg->transparent ? "transparent (forces all browsers)"
                                                     : "proxy (desktop/system proxy)");
    printf("  SafeSearch  : %s\n", cfg->safesearch ? "on" : "off");
    printf("  YouTube     : %s\n", cfg->youtube_mode == 2 ? "strict" :
                                   cfg->youtube_mode == 1 ? "moderate" : "off");
    printf("  Block lists : %s%s\n",
           cfg->enabled_lists[0] ? cfg->enabled_lists : "(none)",
           (cfg->enabled_lists[0] && !cfg->blacklist_mode) ? "  [inactive in whitelist mode]" : "");
    printf("  Allowed (%d): %s\n", cfg->count, cfg->count ? "" : "(none yet)");
    for (int i = 0; i < cfg->count && i < 12; i++) printf("      %s\n", cfg->domains[i]);
    if (cfg->count > 12) printf("      ... and %d more\n", cfg->count - 12);
    printf("  -----------------\n");
}

static int run_setup(void) {
    if (!is_root()) { fprintf(stderr, "Run as root: sudo csec setup\n"); return 1; }
    resolve_config_path();

    for (;;) {  /* loop until the user confirms */
        CSec_Config cfg;
        config_load(&cfg, g_config_path);   /* start from current config / defaults */

        printf("\n========================================\n");
        printf(  "   CSec guided setup\n");
        printf(  "========================================\n\n");
        printf("Pick a starting point:\n\n");
        printf("  1) Whitelist — block everything except sites you add\n");
        printf("        + all category lists, SafeSearch, YouTube strict\n");
        printf("  2) Blacklist — allow all, block all bad categories\n");
        printf("        + all category lists, SafeSearch, YouTube strict\n");
        printf("  3) Whitelist, allow ads        (all lists except ads)\n");
        printf("  4) Blacklist, allow ads        (all lists except ads)\n");
        printf("  5) Custom — answer a few questions\n\n");

        char sel[16];
        printf("Choice [1-5]: "); fflush(stdout);
        if (!ask_line(sel, sizeof(sel))) { printf("\nSetup cancelled.\n"); return 1; }
        int choice = atoi(sel);

        if (choice >= 1 && choice <= 4) {
            cfg.blacklist_mode = (choice == 2 || choice == 4) ? 1 : 0;
            cfg.safesearch     = 1;
            cfg.youtube_mode   = 2;
            enable_all_lists(&cfg, /*except_ads=*/(choice == 3 || choice == 4));
        } else if (choice == 5) {
            /* ---- Custom flow ---- */
            char m[16];
            for (;;) {
                printf("Mode — Whitelist or Blacklist? [W/b]: "); fflush(stdout);
                ask_line(m, sizeof(m));
                if (!m[0] || m[0]=='w' || m[0]=='W') { cfg.blacklist_mode = 0; break; }
                if (m[0]=='b' || m[0]=='B')          { cfg.blacklist_mode = 1; break; }
            }
            cfg.safesearch   = ask_yn("Force Google SafeSearch?", 1) ? 1 : 0;
            cfg.youtube_mode = ask_yn("Force YouTube strict filter?", 1) ? 2 : 0;

            if (ask_yn("Block ALL default category lists?", 1))
                enable_all_lists(&cfg, 0);
            else
                cfg.enabled_lists[0] = '\0';

            if (ask_yn("Choose specific categories to block/allow?", 0)) {
                char names[MAX_CAT][80];
                int n = scan_lists(names, MAX_CAT);
                printf("\n  Categories:\n");
                for (int i = 0; i < n; i++)
                    printf("    %2d) %-12s %s\n", i + 1, names[i],
                           el_has(cfg.enabled_lists, names[i]) ? "BLOCKED" : "allowed");
                printf("\n  Examples:  Block 1,2,3   |   Allow 2 3   |   Block *   |   Block * && Allow 2\n");
                printf("  Selection: "); fflush(stdout);
                char line[256];
                if (ask_line(line, sizeof(line)) && line[0])
                    parse_selection(line, names, n, cfg.enabled_lists, sizeof(cfg.enabled_lists));
            }

            wizard_add_urls(&cfg);
        } else {
            printf("Please enter 1-5.\n");
            continue;
        }

        printf("\nEnforcement:\n");
        printf("  Transparent = force ALL browsers through the filter (can't be\n");
        printf("                bypassed via a browser's own proxy setting). Needs nftables.\n");
        printf("  Proxy       = set the desktop/system proxy only (a deterrent).\n");
        cfg.transparent = ask_yn("Use transparent mode?", 1) ? 1 : 0;

        wizard_set_password(&cfg);
        show_summary(&cfg);

        if (ask_yn("\nApply this configuration?", 1)) {
            if (config_save(&cfg, g_config_path)) {
                apply_enforcement(&cfg);
                run("systemctl restart csec.service 2>/dev/null");
                printf("\nDone. Configuration saved and applied.\n");
                printf(cfg.transparent
                       ? "Transparent mode is on — all browsers are filtered.\n"
                       : "Proxy mode — log out and back in so apps pick up the proxy.\n");
                return 0;
            }
            fprintf(stderr, "Failed to save %s\n", g_config_path);
            return 1;
        }
        printf("\nStarting over...\n");   /* loop again from the top */
    }
}

/* =========================================================================
   Daemon
   ========================================================================= */

static void on_stop(int sig)   { (void)sig; g_running = 0; }
static void on_reload(int sig) { (void)sig; g_reload = 1; }

static int run_daemon(void) {
    struct sigaction sa = {0};
    sa.sa_handler = on_stop;
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT,  &sa, NULL);
    sa.sa_handler = on_reload;
    sigaction(SIGHUP, &sa, NULL);
    signal(SIGPIPE, SIG_IGN);   /* writing to a closed peer must not kill us */

    mutex_init(&g_cfg_lock);
    cfg_reload();
    if (g_cfg.transparent) transparent_start();  /* extra listener for redirected :80/:443 */
    proxy_run();
    platform_enforce_proxy(0);  /* drop env proxy / nft rules on clean stop */
    mutex_destroy(&g_cfg_lock);
    return 0;
}

/* =========================================================================
   Entry point
   ========================================================================= */

static void usage(void) {
    printf(
"CSec " VERSION " — Classroom Web Filter (Linux)\n"
"\n"
"CSec is a filtering proxy. It works in one of two modes:\n"
"\n"
"  whitelist  Block EVERY site except the ones you allow with `csec add`.\n"
"             Best for a locked-down classroom. (This is the default.)\n"
"  blacklist  Allow every site except ones you block. Use the category\n"
"             block lists (porn, gambling, ...) to ban whole kinds of sites.\n"
"\n"
"SETUP\n"
"  sudo csec install            Turn the filter on (start service + set proxy)\n"
"  sudo csec setup              Guided wizard: pick a preset, mode and password\n"
"  sudo csec uninstall          Turn it off (stop service + restore proxy)\n"
"  csec status                  Show whether it's running and how it's set up\n"
"\n"
"ALLOW / BLOCK INDIVIDUAL SITES   (the list used depends on the mode above)\n"
"  sudo csec add youtube.com    Add a site to the list\n"
"  sudo csec remove youtube.com Remove a site from the list\n"
"  csec list                    Show the current site list\n"
"  sudo csec mode blacklist     Switch mode (whitelist | blacklist)\n"
"\n"
"ENFORCEMENT\n"
"  sudo csec enforcement transparent   Force ALL browsers through the filter\n"
"                                      (nftables redirect — can't be bypassed)\n"
"  sudo csec enforcement proxy         Desktop/system proxy only (a deterrent)\n"
"\n"
"BLOCK WHOLE CATEGORIES   (blacklist mode only)\n"
"  csec lists                   Show categories and what's blocked\n"
"  sudo csec block porn         Start blocking a category (porn, gambling, ...)\n"
"  sudo csec unblock porn       Stop blocking that category\n"
"\n"
"SAFE SEARCH\n"
"  sudo csec safesearch on|off          Force Google SafeSearch\n"
"  sudo csec youtube off|moderate|strict  YouTube Restricted Mode\n"
"\n"
"ADMIN\n"
"  sudo csec passwd             Change the admin password\n"
"  sudo csec reset-password     Reset the password to 123456\n"
"  sudo csec import <file.json> Load a saved configuration\n"
"  csec export <file.json>      Save the current configuration\n"
"\n"
"Tip: changes apply immediately — no restart needed. Log out and back in once\n"
"after `csec install` so every app picks up the proxy.\n");
}

int main(int argc, char *argv[]) {
    resolve_config_path();

    if (argc < 2) { usage(); return 0; }
    const char *c = argv[1];

    if      (!strcmp(c, "daemon"))         return run_daemon();
    else if (!strcmp(c, "install"))        return cmd_install();
    else if (!strcmp(c, "uninstall"))      return cmd_uninstall();
    else if (!strcmp(c, "setup"))          return run_setup();
    else if (!strcmp(c, "_restore"))       return cmd_pkg_restore();  /* used by package scriptlets */
    else if (!strcmp(c, "status"))         return cmd_status();
    else if (!strcmp(c, "list"))           return cmd_list();
    else if (!strcmp(c, "lists")) {
        /* hidden back-compat: `lists enable|disable <name>` == block|unblock */
        if (argc >= 4 && !strcmp(argv[2], "enable"))  return cmd_block(argv[3]);
        if (argc >= 4 && !strcmp(argv[2], "disable")) return cmd_unblock(argv[3]);
        return cmd_lists();
    }
    else if (!strcmp(c, "block")   && argc >= 3)    return cmd_block(argv[2]);
    else if (!strcmp(c, "unblock") && argc >= 3)    return cmd_unblock(argv[2]);
    else if (!strcmp(c, "passwd"))         return cmd_passwd();
    else if (!strcmp(c, "reset-password")) return cmd_reset_password();
    else if (!strcmp(c, "add") && argc >= 3)        return cmd_add(argv[2]);
    else if (!strcmp(c, "remove") && argc >= 3)     return cmd_remove(argv[2]);
    else if (!strcmp(c, "mode") && argc >= 3)       return cmd_mode(argv[2]);
    else if (!strcmp(c, "enforcement") && argc >= 3) return cmd_enforcement(argv[2]);
    else if (!strcmp(c, "safesearch") && argc >= 3) return cmd_safesearch(argv[2]);
    else if (!strcmp(c, "youtube") && argc >= 3)    return cmd_youtube(argv[2]);
    else if (!strcmp(c, "import") && argc >= 3)     return cmd_import(argv[2]);
    else if (!strcmp(c, "export") && argc >= 3)     return cmd_export(argv[2]);
    else if (!strcmp(c, "help") || !strcmp(c, "--help") || !strcmp(c, "-h")) { usage(); return 0; }

    fprintf(stderr, "Unknown or incomplete command: %s\n\n", c);
    usage();
    return 1;
}
