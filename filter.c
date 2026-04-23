#include "filter.h"

#include <windows.h>
#include <wincrypt.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>

/* -------------------------------------------------------------------------
   Helpers
   ---------------------------------------------------------------------- */

static void str_lower(char *s) {
    for (; *s; s++) *s = (char)tolower((unsigned char)*s);
}

/* Strip leading/trailing whitespace in place. */
static void str_trim(char *s) {
    char *start = s;
    while (*start && isspace((unsigned char)*start)) start++;
    if (start != s) memmove(s, start, strlen(start) + 1);
    char *end = s + strlen(s);
    while (end > s && isspace((unsigned char)*(end - 1))) end--;
    *end = '\0';
}

/* -------------------------------------------------------------------------
   JSON parser — minimal, handles only our config format.

   Format:
   {
     "allowed": ["domain1", "domain2", ...],
     "admin_hash": "hexstring"
   }
   ---------------------------------------------------------------------- */

/* Advance past whitespace. */
static const char *skip_ws(const char *p) {
    while (*p && isspace((unsigned char)*p)) p++;
    return p;
}

/* Parse a JSON string at *p (which must point at the opening quote).
   Writes up to buflen-1 chars into buf, null-terminates.
   Returns pointer past closing quote, or NULL on error. */
static const char *parse_string(const char *p, char *buf, int buflen) {
    if (*p != '"') return NULL;
    p++;
    int i = 0;
    while (*p && *p != '"') {
        if (*p == '\\') {
            p++;
            if (!*p) return NULL;
            if (i < buflen - 1) buf[i++] = *p;
        } else {
            if (i < buflen - 1) buf[i++] = *p;
        }
        p++;
    }
    if (*p != '"') return NULL;
    buf[i] = '\0';
    return p + 1;
}

static int config_parse(CSec_Config *cfg, const char *json) {
    const char *p = skip_ws(json);
    if (*p != '{') return 0;
    p++;

    while (1) {
        p = skip_ws(p);
        if (*p == '}') break;
        if (*p == ',') { p++; continue; }
        if (*p != '"') return 0;

        char key[64];
        p = parse_string(p, key, sizeof(key));
        if (!p) return 0;
        p = skip_ws(p);
        if (*p != ':') return 0;
        p++;
        p = skip_ws(p);

        if (strcmp(key, "allowed") == 0) {
            if (*p != '[') return 0;
            p++;
            while (1) {
                p = skip_ws(p);
                if (*p == ']') { p++; break; }
                if (*p == ',') { p++; continue; }
                if (*p != '"') return 0;
                char domain[MAX_DOMAIN_LEN];
                p = parse_string(p, domain, sizeof(domain));
                if (!p) return 0;
                str_trim(domain);
                str_lower(domain);
                if (domain[0] && cfg->count < MAX_DOMAINS) {
                    strncpy(cfg->domains[cfg->count], domain, MAX_DOMAIN_LEN - 1);
                    cfg->domains[cfg->count][MAX_DOMAIN_LEN - 1] = '\0';
                    cfg->count++;
                }
            }
        } else if (strcmp(key, "admin_hash") == 0) {
            p = parse_string(p, cfg->admin_hash, sizeof(cfg->admin_hash));
            if (!p) return 0;
        } else if (strcmp(key, "mode") == 0) {
            char mode[32];
            p = parse_string(p, mode, sizeof(mode));
            if (!p) return 0;
            cfg->blacklist_mode = (strcmp(mode, "blacklist") == 0) ? 1 : 0;
        } else if (strcmp(key, "presets") == 0) {
            int val = 0;
            while (isdigit((unsigned char)*p)) { val = val * 10 + (*p - '0'); p++; }
            cfg->preset_flags = val;
        } else if (strcmp(key, "enabled_lists") == 0) {
            p = parse_string(p, cfg->enabled_lists, sizeof(cfg->enabled_lists));
            if (!p) return 0;
        } else {
            /* Unknown key — skip value (strings and arrays only in our format) */
            if (*p == '"') {
                char tmp[512];
                p = parse_string(p, tmp, sizeof(tmp));
                if (!p) return 0;
            } else if (*p == '[') {
                int depth = 1; p++;
                while (*p && depth > 0) {
                    if (*p == '[') depth++;
                    else if (*p == ']') depth--;
                    p++;
                }
            }
        }
    }
    return 1;
}

/* -------------------------------------------------------------------------
   Public API
   ---------------------------------------------------------------------- */

int config_load(CSec_Config *cfg, const char *path) {
    memset(cfg, 0, sizeof(*cfg));
    /* Default password hash = SHA-256("123456") */
    strcpy(cfg->admin_hash,
           "8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92");

    FILE *f = fopen(path, "rb");
    if (!f) return 0; /* missing file is not an error — start with empty list */

    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    rewind(f);

    if (size <= 0 || size > 1024 * 1024) { fclose(f); return 0; }

    char *buf = (char *)malloc((size_t)size + 1);
    if (!buf) { fclose(f); return 0; }

    fread(buf, 1, (size_t)size, f);
    buf[size] = '\0';
    fclose(f);

    int ok = config_parse(cfg, buf);
    free(buf);
    return ok;
}

int config_save(const CSec_Config *cfg, const char *path) {
    FILE *f = fopen(path, "wb");
    if (!f) return 0;

    fprintf(f, "{\n  \"allowed\": [");
    for (int i = 0; i < cfg->count; i++) {
        if (i > 0) fprintf(f, ",");
        fprintf(f, "\n    \"%s\"", cfg->domains[i]);
    }
    if (cfg->count > 0) fprintf(f, "\n  ");
    fprintf(f, "],\n");
    fprintf(f, "  \"admin_hash\": \"%s\",\n", cfg->admin_hash);
    fprintf(f, "  \"mode\": \"%s\",\n", cfg->blacklist_mode ? "blacklist" : "whitelist");
    fprintf(f, "  \"presets\": %d,\n", cfg->preset_flags);
    fprintf(f, "  \"enabled_lists\": \"%s\"\n}\n", cfg->enabled_lists);

    fclose(f);
    return 1;
}

int domain_allowed(const CSec_Config *cfg, const char *hostname) {
    if (!hostname || !*hostname) return 0;

    /* Lowercase copy of hostname */
    char host[MAX_DOMAIN_LEN];
    strncpy(host, hostname, MAX_DOMAIN_LEN - 1);
    host[MAX_DOMAIN_LEN - 1] = '\0';
    str_lower(host);

    /* Strip port if present (e.g. "code.org:80") */
    char *colon = strchr(host, ':');
    if (colon) *colon = '\0';

    int found = 0;
    for (int i = 0; i < cfg->count && !found; i++) {
        const char *d = cfg->domains[i];
        size_t dlen = strlen(d);
        size_t hlen = strlen(host);

        /* Exact match */
        if (strcmp(host, d) == 0) { found = 1; break; }

        /* Subdomain match: host ends with "." + d */
        if (hlen > dlen + 1 &&
            host[hlen - dlen - 1] == '.' &&
            strcmp(host + hlen - dlen, d) == 0) { found = 1; break; }
    }
    /* Whitelist: allow if found. Blacklist: allow if NOT found. */
    return cfg->blacklist_mode ? !found : found;
}

int domain_add(CSec_Config *cfg, const char *domain) {
    if (cfg->count >= MAX_DOMAINS) return 0;

    char d[MAX_DOMAIN_LEN];
    strncpy(d, domain, MAX_DOMAIN_LEN - 1);
    d[MAX_DOMAIN_LEN - 1] = '\0';
    str_trim(d);
    str_lower(d);
    if (!d[0]) return 0;

    /* Check for duplicate */
    for (int i = 0; i < cfg->count; i++) {
        if (strcmp(cfg->domains[i], d) == 0) return 0;
    }

    strncpy(cfg->domains[cfg->count], d, MAX_DOMAIN_LEN - 1);
    cfg->domains[cfg->count][MAX_DOMAIN_LEN - 1] = '\0';
    cfg->count++;
    return 1;
}

int domain_remove(CSec_Config *cfg, const char *domain) {
    char d[MAX_DOMAIN_LEN];
    strncpy(d, domain, MAX_DOMAIN_LEN - 1);
    d[MAX_DOMAIN_LEN - 1] = '\0';
    str_trim(d);
    str_lower(d);

    for (int i = 0; i < cfg->count; i++) {
        if (strcmp(cfg->domains[i], d) == 0) {
            /* Shift remaining entries down */
            memmove(&cfg->domains[i], &cfg->domains[i + 1],
                    (size_t)(cfg->count - i - 1) * sizeof(cfg->domains[0]));
            cfg->count--;
            return 1;
        }
    }
    return 0;
}

void sha256_hex(const char *input, char out[65]) {
    HCRYPTPROV prov = 0;
    HCRYPTHASH hash = 0;
    BYTE digest[32];
    DWORD digest_len = sizeof(digest);

    out[0] = '\0';

    if (!CryptAcquireContext(&prov, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
        return;
    if (!CryptCreateHash(prov, CALG_SHA_256, 0, 0, &hash))
        goto cleanup;
    if (!CryptHashData(hash, (const BYTE *)input, (DWORD)strlen(input), 0))
        goto cleanup;
    if (!CryptGetHashParam(hash, HP_HASHVAL, digest, &digest_len, 0))
        goto cleanup;

    for (DWORD i = 0; i < digest_len; i++)
        sprintf(out + i * 2, "%02x", digest[i]);
    out[64] = '\0';

cleanup:
    if (hash) CryptDestroyHash(hash);
    if (prov) CryptReleaseContext(prov, 0);
}
