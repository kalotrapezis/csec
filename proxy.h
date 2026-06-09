/* proxy.h — shared, cross-platform proxy engine API.
   The engine (proxy.c) is identical on every platform; each OS frontend
   supplies resolve_config_path() and platform_enforce_proxy(). */
#ifndef CSEC_PROXY_H
#define CSEC_PROXY_H

#include "compat.h"
#include "filter.h"

#define SERVICE_NAME "CSec"
#define VERSION      "0.0.9"
#define PROXY_PORT   8080

/* ---- shared state (defined in proxy.c) ---- */
extern CSec_Config      g_cfg;
extern mutex_t          g_cfg_lock;
extern volatile int     g_running;   /* set to 0 to stop proxy_run() */
extern volatile int     g_reload;    /* set to 1 to request a config reload */
extern char             g_config_path[MAX_PATH];
extern char             g_lists_dir[MAX_PATH];

/* ---- engine entry points ---- */
void cfg_reload(void);   /* reload config + block lists into g_cfg */
void proxy_run(void);    /* run the proxy until g_running == 0 */

/* ---- external block lists (caller of extlists_blocked holds g_cfg_lock) ---- */
int  extlists_blocked(const char *host);
void extlists_load_all(void);
void extlists_load_hot(void);

/* Filtering decision for a hostname (takes g_cfg_lock internally).
   Returns 1 = allowed, 0 = blocked. Used by both the explicit and the
   transparent (Linux) request paths. */
int  host_allowed(const char *host);

/* If SafeSearch / YouTube Restricted applies to this host, returns the IP of
   Google's enforcing endpoint to connect to instead (Host/SNI unchanged), else NULL. */
const char *safesearch_target(const char *host);

/* ---- shared domain helpers (used by the admin frontends) ---- */
void normalize_domain(const char *input, char *out, int outlen);

typedef struct { const char *trigger; const char *extras[12]; } Bundle;
extern const Bundle BUNDLES[];
int  bundle_find(const char *domain);   /* index into BUNDLES, or -1 */

/* ---- provided by each platform frontend ---- */
void resolve_config_path(void);         /* fill g_config_path + g_lists_dir */
void platform_enforce_proxy(int enable);/* re-assert proxy on proxy_run start */

#endif /* CSEC_PROXY_H */
