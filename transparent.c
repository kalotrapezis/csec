/*
 * transparent.c — Linux transparent interception for CSec.
 *
 * With nftables redirecting outbound :80/:443 to this listener, every browser
 * is filtered regardless of its own proxy settings. There is no CONNECT, so we
 * recover the hostname from the HTTP Host header (port 80) or the TLS SNI
 * (port 443), apply the same allow/block decision as the explicit proxy, and
 * either splice the connection to its real destination or drop it.
 *
 * Loop prevention: the nft rules skip traffic owned by uid 0 (root), and the
 * daemon runs as root — so the proxy's own upstream connections are never
 * redirected back into itself.
 */

#include "proxy.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <linux/netfilter_ipv4.h>   /* SO_ORIGINAL_DST */

#define TRANS_PORT 8081
#define TBUF       16384

/* ---- HTTP Host header ---------------------------------------------------- */
static int parse_http_host(const char *buf, int len, char *out, int outlen) {
    /* find a line "Host: <name>" (case-insensitive), within the first chunk */
    for (int i = 0; i + 5 < len; i++) {
        if ((i == 0 || buf[i-1] == '\n') && strncasecmp(buf + i, "host:", 5) == 0) {
            int j = i + 5;
            while (j < len && (buf[j] == ' ' || buf[j] == '\t')) j++;
            int k = 0;
            while (j < len && buf[j] != '\r' && buf[j] != '\n' && buf[j] != ':' && k < outlen - 1)
                out[k++] = buf[j++];
            out[k] = '\0';
            return k > 0;
        }
    }
    return 0;
}

/* ---- TLS ClientHello SNI -------------------------------------------------- */
static int parse_sni(const unsigned char *b, int n, char *out, int outlen) {
    int p = 0;
    if (n < 5 || b[0] != 0x16) return 0;            /* TLS handshake record */
    p = 5;                                           /* skip record header  */
    if (p + 4 > n || b[p] != 0x01) return 0;         /* ClientHello         */
    p += 4;                                           /* hs type + length   */
    p += 2 + 32;                                      /* client version + random */
    if (p >= n) return 0;
    int sid = b[p]; p += 1 + sid;                     /* session id          */
    if (p + 2 > n) return 0;
    int cs = (b[p] << 8) | b[p+1]; p += 2 + cs;       /* cipher suites       */
    if (p + 1 > n) return 0;
    int comp = b[p]; p += 1 + comp;                   /* compression methods */
    if (p + 2 > n) return 0;
    int extlen = (b[p] << 8) | b[p+1]; p += 2;        /* extensions length   */
    int end = p + extlen; if (end > n) end = n;
    while (p + 4 <= end) {
        int et = (b[p] << 8) | b[p+1];
        int el = (b[p+2] << 8) | b[p+3];
        p += 4;
        if (et == 0x0000) {                           /* server_name         */
            int sp = p;
            if (sp + 2 > n) return 0;
            sp += 2;                                   /* server_name_list len */
            if (sp + 3 > n) return 0;
            int nt = b[sp]; sp += 1;                   /* name type (0 = host) */
            int nl = (b[sp] << 8) | b[sp+1]; sp += 2;
            if (nt != 0 || sp + nl > n) return 0;
            int k = 0;
            for (int i = 0; i < nl && k < outlen - 1; i++) out[k++] = (char)b[sp+i];
            out[k] = '\0';
            return k > 0;
        }
        p += el;
    }
    return 0;
}

/* ---- one-way splice ------------------------------------------------------- */
typedef struct { sock_t from, to; } pipe_t;
static void *t_pipe(void *arg) {
    pipe_t *t = arg;
    char b[TBUF]; int n;
    while ((n = recv(t->from, b, sizeof(b), 0)) > 0) send(t->to, b, n, 0);
    free(t); return NULL;
}

/* ---- per-connection handler ---------------------------------------------- */
static void *t_handle(void *arg) {
    sock_t c = *(sock_t *)arg; free(arg);

    struct sockaddr_in dst; socklen_t dl = sizeof(dst);
    if (getsockopt(c, SOL_IP, SO_ORIGINAL_DST, &dst, &dl) != 0) { closesock(c); return NULL; }
    int oport = ntohs(dst.sin_port);

    char buf[TBUF];
    int n = recv(c, buf, sizeof(buf), 0);
    if (n <= 0) { closesock(c); return NULL; }

    char host[256] = "";
    int is_tls = ((unsigned char)buf[0] == 0x16) || oport == 443;
    if (is_tls) parse_sni((const unsigned char *)buf, n, host, sizeof(host));
    else        parse_http_host(buf, n, host, sizeof(host));

    /* Fail closed: if we can't tell what this is, or it's blocked, drop it. */
    if (!host[0] || !host_allowed(host)) {
        if (!is_tls && host[0]) {
            const char *deny = "HTTP/1.1 403 Forbidden\r\nContent-Type: text/html\r\n"
                "Connection: close\r\n\r\n<html><body><h2>Blocked by CSec</h2></body></html>";
            send(c, deny, (int)strlen(deny), 0);
        }
        closesock(c); return NULL;
    }

    /* Upstream: SafeSearch/YouTube enforcing IP if applicable, else the real
       destination IP recovered from SO_ORIGINAL_DST (no DNS needed). */
    struct sockaddr_in up; memset(&up, 0, sizeof(up));
    up.sin_family = AF_INET;
    up.sin_port   = htons(oport);
    const char *ss = safesearch_target(host);
    if (ss) inet_pton(AF_INET, ss, &up.sin_addr);
    else    up.sin_addr = dst.sin_addr;

    sock_t r = socket(AF_INET, SOCK_STREAM, 0);
    if (r == INVALID_SOCK || connect(r, (struct sockaddr *)&up, sizeof(up)) != 0) {
        if (r != INVALID_SOCK) closesock(r);
        closesock(c); return NULL;
    }

    send(r, buf, n, 0);                       /* replay the bytes we peeked */

    pipe_t *ud = malloc(sizeof(*ud));
    if (ud) { ud->from = r; ud->to = c; spawn_thread(t_pipe, ud); }
    { char b[TBUF]; int m; while ((m = recv(c, b, sizeof(b), 0)) > 0) send(r, b, m, 0); }
    closesock(r); closesock(c);
    return NULL;
}

static void *t_accept_loop(void *arg) {
    sock_t srv = *(sock_t *)arg; free(arg);
    while (g_running) {
        fd_set fds; FD_ZERO(&fds); FD_SET(srv, &fds);
        struct timeval tv = {1, 0};
        if (select((int)srv + 1, &fds, NULL, NULL, &tv) <= 0) continue;
        sock_t cl = accept(srv, NULL, NULL);
        if (cl == INVALID_SOCK) continue;
        set_recv_timeout(cl, 10000);
        sock_t *cp = malloc(sizeof(sock_t));
        if (!cp) { closesock(cl); continue; }
        *cp = cl;
        spawn_thread(t_handle, cp);
    }
    closesock(srv);
    return NULL;
}

/* Start the transparent listener in a background thread (called from the
   daemon when transparent mode is on). Safe to call once. */
void transparent_start(void) {
    sock_t srv = socket(AF_INET, SOCK_STREAM, 0);
    if (srv == INVALID_SOCK) { perror("transparent socket"); return; }
    int reuse = 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    struct sockaddr_in a; memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_ANY);
    a.sin_port = htons(TRANS_PORT);
    if (bind(srv, (struct sockaddr *)&a, sizeof(a)) != 0) { perror("transparent bind"); closesock(srv); return; }
    if (listen(srv, SOMAXCONN) != 0) { perror("transparent listen"); closesock(srv); return; }
    sock_t *sp = malloc(sizeof(sock_t));
    if (!sp) { closesock(srv); return; }
    *sp = srv;
    spawn_thread(t_accept_loop, sp);
}

/* Install (enable=1) or remove (enable=0) the nftables redirect rules.
   Returns 0 on success. Requires root + the `nft` command. */
int nft_rules(int enable) {
    if (enable) {
        /* IPv4: redirect user (non-root) web traffic into the proxy.
           IPv6: reject :80/:443 so it can't be used to slip past v4 redirect. */
        const char *script =
            "nft -f - <<'EOF'\n"
            "table ip csec { }\n"
            "delete table ip csec\n"
            "table ip6 csec { }\n"
            "delete table ip6 csec\n"
            "table ip csec {\n"
            "  chain out {\n"
            "    type nat hook output priority -100; policy accept;\n"
            "    meta skuid 0 return\n"
            "    ip daddr { 127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16 } return\n"
            "    tcp dport { 80, 443 } redirect to :8081\n"
            "  }\n"
            "}\n"
            "table ip6 csec {\n"
            "  chain out {\n"
            "    type filter hook output priority 0; policy accept;\n"
            "    meta skuid 0 return\n"
            "    ip6 daddr { ::1, fe80::/10, fc00::/7 } return\n"
            "    tcp dport { 80, 443 } reject with tcp reset\n"
            "  }\n"
            "}\n"
            "EOF\n";
        return system(script);
    } else {
        system("nft delete table ip csec 2>/dev/null");
        system("nft delete table ip6 csec 2>/dev/null");
        return 0;
    }
}
