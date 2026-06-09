/* proxy.c — shared, cross-platform proxy engine.
 *
 * HTTP/HTTPS filtering proxy: whitelist/blacklist domain matching, external
 * block lists (hosts format), and SafeSearch / YouTube Restricted enforcement.
 * Identical on Windows and Linux — all OS differences live behind compat.h and
 * the two frontend-supplied hooks resolve_config_path() / platform_enforce_proxy().
 */

#include "proxy.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

/* SafeSearch redirect IPs (Google's published endpoints).
   forcesafesearch.google.com    -> 216.239.38.120  (Google search SafeSearch lock)
   restrict.youtube.com          -> 216.239.38.120  (YouTube Restricted Mode strict)
   restrictmoderate.youtube.com  -> 216.239.38.119  (YouTube Restricted Mode moderate) */
#define SAFESEARCH_GOOGLE_IP        "216.239.38.120"
#define YOUTUBE_RESTRICT_STRICT_IP  "216.239.38.120"
#define YOUTUBE_RESTRICT_MOD_IP     "216.239.38.119"

#define RECV_TIMEOUT_MS 10000
#define BUF_SIZE        8192

/* ---- shared state ---- */
CSec_Config      g_cfg;
mutex_t          g_cfg_lock;
volatile int     g_running = 1;
volatile int     g_reload  = 0;
char             g_config_path[MAX_PATH];
char             g_lists_dir[MAX_PATH];

/* forward declarations — defined later in this file */
static void  *bg_load_thread(void *arg);

/* =========================================================================
   SafeSearch / YouTube Restricted enforcement
   ========================================================================= */

/* If SafeSearch / YouTube Restricted is enabled and the host is a Google or
   YouTube endpoint, return the IP of Google's enforcing endpoint — we connect
   there instead of the real one, while keeping the original Host header / SNI
   so the cert validates and the user transparently lands on the locked version. */
static int is_youtube_host(const char *host) {
    return (strcmp(host, "youtube.com") == 0           ||
            strcmp(host, "www.youtube.com") == 0       ||
            strcmp(host, "m.youtube.com") == 0         ||
            strcmp(host, "youtubei.googleapis.com") == 0 ||
            strcmp(host, "youtube.googleapis.com") == 0);
}

static const char *safesearch_redirect_ip(const char *host) {
    /* Google search — covers google.com plus all country TLDs (google.gr, etc.).
       The www.google.* prefix match catches them all. */
    if (g_cfg.safesearch) {
        if (strcmp(host, "google.com") == 0)        return SAFESEARCH_GOOGLE_IP;
        if (strncmp(host, "www.google.", 11) == 0)  return SAFESEARCH_GOOGLE_IP;
    }
    /* YouTube — three modes. 0 = off, 1 = moderate, 2 = strict (default). */
    if (g_cfg.youtube_mode > 0 && is_youtube_host(host)) {
        return (g_cfg.youtube_mode == 2) ? YOUTUBE_RESTRICT_STRICT_IP
                                         : YOUTUBE_RESTRICT_MOD_IP;
    }
    return NULL;
}

/* Public wrappers (used by the Linux transparent path in transparent.c). */
int host_allowed(const char *host) {
    mutex_lock(&g_cfg_lock);
    int ok = domain_allowed(&g_cfg, host);
    if (ok && g_cfg.blacklist_mode) ok = !extlists_blocked(host);
    mutex_unlock(&g_cfg_lock);
    return ok;
}

const char *safesearch_target(const char *host) {
    return safesearch_redirect_ip(host);
}

/* =========================================================================
   Proxy client handling
   ========================================================================= */

typedef struct { sock_t from; sock_t to; } TunnelArgs;

static int recv_line(sock_t s, char *buf, int len) {
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
    while (*src == ' ' || *src == '\t') src++;   /* skip space after "Host:" */
    strncpy(dst, src, dstlen - 1); dst[dstlen - 1] = '\0';
    char *p = strchr(dst, ':'); if (p) *p = '\0';
    int n = (int)strlen(dst);
    while (n > 0 && (dst[n-1] == '\r' || dst[n-1] == '\n' ||
                     dst[n-1] == ' '  || dst[n-1] == '\t')) dst[--n] = '\0';
}

static void *tunnel_thread(void *arg) {
    TunnelArgs *t = (TunnelArgs *)arg;
    char buf[BUF_SIZE]; int n;
    while ((n = recv(t->from, buf, sizeof(buf), 0)) > 0) send(t->to, buf, n, 0);
    free(t); return NULL;
}

static void *handle_client(void *arg) {
    sock_t client = *(sock_t *)arg;
    free(arg);
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

        mutex_lock(&g_cfg_lock);
        int ok = domain_allowed(&g_cfg, host);
        if (ok && g_cfg.blacklist_mode) ok = !extlists_blocked(host);
        mutex_unlock(&g_cfg_lock);
        if (!ok) { send(client, "HTTP/1.1 403 Forbidden\r\n\r\n", 26, 0); goto done; }

        struct addrinfo hints = {0}, *res = NULL;
        hints.ai_family = AF_UNSPEC; hints.ai_socktype = SOCK_STREAM;
        char ps[8]; sprintf(ps, "%d", port);
        /* SafeSearch: redirect to Google's enforcing endpoint. SNI + Host
           are unchanged, so the cert validates and Google serves the locked
           version of search/YouTube. */
        const char *target = safesearch_redirect_ip(host);
        if (!target) target = host;
        if (getaddrinfo(target, ps, &hints, &res) != 0) goto done;
        sock_t rem = socket(res->ai_family, SOCK_STREAM, 0);
        if (rem == INVALID_SOCK || connect(rem, res->ai_addr, (int)res->ai_addrlen) != 0)
            { freeaddrinfo(res); if (rem != INVALID_SOCK) closesock(rem); goto done; }
        freeaddrinfo(res);

        send(client, "HTTP/1.1 200 Connection Established\r\n\r\n", 39, 0);

        TunnelArgs *ta = (TunnelArgs *)malloc(sizeof(TunnelArgs));
        if (ta) { ta->from = rem; ta->to = client; spawn_thread(tunnel_thread, ta); }
        { char fb[BUF_SIZE]; int fn;
          while ((fn = recv(client, fb, sizeof(fb), 0)) > 0) send(rem, fb, fn, 0); }
        closesock(rem);
    } else {
        if (!host[0]) goto done;
        mutex_lock(&g_cfg_lock);
        int ok = domain_allowed(&g_cfg, host);
        if (ok && g_cfg.blacklist_mode) ok = !extlists_blocked(host);
        mutex_unlock(&g_cfg_lock);
        if (!ok) {
            const char *deny = "HTTP/1.1 403 Forbidden\r\nContent-Type: text/html\r\n"
                "Connection: close\r\n\r\n<html><body><h2>Blocked by CSec</h2></body></html>";
            send(client, deny, (int)strlen(deny), 0); goto done;
        }
        struct addrinfo hints2 = {0}, *res2 = NULL;
        hints2.ai_family = AF_UNSPEC; hints2.ai_socktype = SOCK_STREAM;
        /* SafeSearch redirect — see CONNECT branch above for explanation. */
        const char *target2 = safesearch_redirect_ip(host);
        if (!target2) target2 = host;
        if (getaddrinfo(target2, "80", &hints2, &res2) != 0) goto done;
        sock_t rem2 = socket(res2->ai_family, SOCK_STREAM, 0);
        if (rem2 == INVALID_SOCK || connect(rem2, res2->ai_addr, (int)res2->ai_addrlen) != 0)
            { freeaddrinfo(res2); if (rem2 != INVALID_SOCK) closesock(rem2); goto done; }
        freeaddrinfo(res2);
        send(rem2, hdrs, hlen, 0);
        { char fb[BUF_SIZE]; int fn;
          while ((fn = recv(rem2, fb, sizeof(fb), 0)) > 0) send(client, fb, fn, 0); }
        closesock(rem2);
    }
done:
    closesock(client); return NULL;
}

/* =========================================================================
   URL normalization + domain bundles (shared with the admin frontends)
   ========================================================================= */

void normalize_domain(const char *input, char *out, int outlen) {
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

const Bundle BUNDLES[] = {
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

int bundle_find(const char *domain) {
    for (int i = 0; BUNDLES[i].trigger; i++)
        if (strcmp(domain, BUNDLES[i].trigger) == 0) return i;
    return -1;
}

/* =========================================================================
   External block lists — large domain files from the lists/ folder
   Format: hosts file  "0.0.0.0 domain.com"  (The Block List Project)
   ========================================================================= */

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
int extlists_blocked(const char *host) {
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
    mutex_lock(&g_cfg_lock);
    strncpy(names, g_cfg.enabled_lists, sizeof(names) - 1);
    names[sizeof(names) - 1] = '\0';
    mutex_unlock(&g_cfg_lock);

    ExtList new_ext[MAX_EXT_LISTS];
    int     new_count = 0;
    memset(new_ext, 0, sizeof(new_ext));

    /* Always load _priority.txt first (small curated list, no line limit) */
    if (new_count < MAX_EXT_LISTS) {
        char ppath[MAX_PATH];
        snprintf(ppath, MAX_PATH, "%s" PATHSEP "_priority.txt", g_lists_dir);
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
        snprintf(path, MAX_PATH, "%s" PATHSEP "%s.txt", g_lists_dir, tok);
        if (extlist_load_file(&new_ext[new_count], path, max_lines)) {
            strncpy(new_ext[new_count].name, tok, 63);
            new_count++;
        }
    }

    /* Swap atomically under lock */
    mutex_lock(&g_cfg_lock);
    for (int i = 0; i < g_ext_count; i++) extlist_free(&g_ext[i]);
    memcpy(g_ext, new_ext, (size_t)new_count * sizeof(ExtList));
    g_ext_count = new_count;
    mutex_unlock(&g_cfg_lock);
}

void extlists_load_all(void)  { extlists_load_impl(0);         }
void extlists_load_hot(void)  { extlists_load_impl(HOT_LINES); }

static void *bg_load_thread(void *arg) {
    (void)arg;
    /* Progressive batches — files must be sorted by popularity (run sort_lists.py).
       Each step expands coverage; pauses keep the HDD from being hammered. */
    static const int steps[] = {1500, 5000, 0}; /* 0 = full (no limit) */
    for (int i = 0; i < (int)(sizeof(steps)/sizeof(steps[0])); i++) {
        sleep_ms(5000);
        extlists_load_impl(steps[i]);
    }
    return NULL;
}

/* =========================================================================
   Config reload + main proxy loop
   ========================================================================= */

void cfg_reload(void) {
    CSec_Config tmp;
    if (config_load(&tmp, g_config_path)) {
        mutex_lock(&g_cfg_lock);
        memcpy(&g_cfg, &tmp, sizeof(g_cfg));
        mutex_unlock(&g_cfg_lock);
        /* Hot pass: blocks popular sites in <100ms while full lists load in background */
        extlists_load_hot();
        spawn_thread(bg_load_thread, NULL);
    }
}

void proxy_run(void) {
    net_init();
    platform_enforce_proxy(1); /* re-enforce on every service/daemon start */

    sock_t srv = socket(AF_INET, SOCK_STREAM, 0);
    int reuse = 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, (const char *)&reuse, sizeof(reuse));

    struct sockaddr_in addr = {0};
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    addr.sin_port        = htons(PROXY_PORT);
    if (bind(srv, (struct sockaddr *)&addr, sizeof(addr)) != 0) goto cleanup;
    if (listen(srv, SOMAXCONN) != 0) goto cleanup;

    while (g_running) {
        if (g_reload) { g_reload = 0; cfg_reload(); }
        fd_set fds; FD_ZERO(&fds); FD_SET(srv, &fds);
        struct timeval tv = {1, 0};
        if (select((int)srv + 1, &fds, NULL, NULL, &tv) <= 0) continue;
        sock_t cl = accept(srv, NULL, NULL);
        if (cl == INVALID_SOCK) continue;
        set_recv_timeout(cl, RECV_TIMEOUT_MS);
        sock_t *cp = (sock_t *)malloc(sizeof(sock_t));
        if (!cp) { closesock(cl); continue; }
        *cp = cl;
        spawn_thread(handle_client, cp);
    }
cleanup:
    closesock(srv);
}
