#ifndef CSEC_FILTER_H
#define CSEC_FILTER_H

#define MAX_DOMAINS     1024
#define MAX_DOMAIN_LEN  256
#define CONFIG_FILE     "csec-config.json"

typedef struct {
    char domains[MAX_DOMAINS][MAX_DOMAIN_LEN];
    int  count;
    char admin_hash[65]; /* SHA-256 hex, null-terminated */
    int  blacklist_mode; /* 0 = whitelist (default), 1 = blacklist */
    int  preset_flags;   /* bitmask of active preset categories */
} CSec_Config;

/* Load config from path. Returns 1 on success, 0 on failure (missing file = empty config). */
int  config_load(CSec_Config *cfg, const char *path);

/* Save config to path. Returns 1 on success, 0 on failure. */
int  config_save(const CSec_Config *cfg, const char *path);

/* Returns 1 if hostname is allowed, 0 if blocked.
   Matches exact domain or any subdomain: "code.org" allows "studio.code.org". */
int  domain_allowed(const CSec_Config *cfg, const char *hostname);

/* Add domain to list. Returns 1 on success, 0 if full or already present. */
int  domain_add(CSec_Config *cfg, const char *domain);

/* Remove domain from list. Returns 1 if removed, 0 if not found. */
int  domain_remove(CSec_Config *cfg, const char *domain);

/* SHA-256 of input string, written as lowercase hex into out[65]. Windows CryptoAPI. */
void sha256_hex(const char *input, char out[65]);

#endif /* CSEC_FILTER_H */
