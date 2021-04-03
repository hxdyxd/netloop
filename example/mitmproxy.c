/*
 * mitmproxy.c of netloop
 * Copyright (C) 2021-2021  hxdyxd <hxdyxd@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <netloop.h>
#include <netssl.h>
#include <signal.h>

#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>

#include <log.h>
#define NONE_PRINTF   LOG_NONE
#define DEBUG_PRINTF  LOG_DEBUG
#define WARN_PRINTF   LOG_WARN
#define ERROR_PRINTF  LOG_ERROR
#define ASSERT(if_true)     while(!(if_true)) {  \
    ERROR_PRINTF("assert(%s) failed at %s, %s:%d\n",  \
     #if_true, __FILE__, __FUNCTION__, __LINE__); exit(-1);};

#define SSL_DUMP_ERRORS()                                    \
    do {                                                     \
        unsigned long r;                                     \
        while ((r = ERR_get_error()) != 0) {                 \
            ERROR_PRINTF("%s\n", ERR_error_string(r, NULL)); \
        }                                                    \
    } while(0)

#define EXAMPLE_ADDR    "::"
#define EXAMPLE_PORT    8088

#define CERT_FILE     "server.crt"
#define KEY_FILE      "server.key"

#define MAX_HOST_NAME_LEN   (128)

struct addrinfo_t {
    char host[MAX_HOST_NAME_LEN];
    uint16_t port;
};

struct ssl_cert_t {
    EVP_PKEY  *pkey;
    X509      *x509;
};

struct mitm_data_t {
    struct netloop_conn_t *peer;
    struct ssl_cert_t ca;
};

static int parse_addr_in_http(struct addrinfo_t *addr, char *buf, int len)
{
    char *method, *method_d;
    char *url, *url_d;
    char tmp[512];
    strncpy(tmp, buf, sizeof(tmp) - 1);

    method = tmp;
    method_d = strstr(method, " ");
    if (!method_d) {
        goto exit;
    }
    *method_d = 0;

    url = method_d + 1;
    url_d = strstr(url, " ");
    if (!url_d) {
        goto exit;
    }
    *url_d = 0;

    DEBUG_PRINTF("parse addr \"%s %s\"\n", method, url);

    if (strncmp(url, "http://", 7) == 0) {
        addr->port = 80;
    } else {
        addr->port = 443;
    }

    char *host = strstr(url, "://");
    if (host) {
        host += 3;
    } else {
        host = url;
    }

    char *host_d = strstr(host, ":");
    if (host_d) {
        int port = strtoul(host_d + 1, NULL, 10);
        if (port) {
            addr->port = port;
        }
    } else {
        host_d = strstr(host, "/");
    }

    if (host_d) {
        *host_d = 0;
    }

    strncpy(addr->host, host, MAX_HOST_NAME_LEN - 1);
    return 0;
exit:
    return -1;
}

/* Set the key and cert */
static SSL_CTX *create_ssl_ctx(const char *cert, const char *key)
{
    int r;
    SSL_CTX *sslctx;
    sslctx = SSL_CTX_new(TLS_method());
    if (!sslctx) {
        ERROR_PRINTF("SSL_CTX_new() fail!\n");
        return NULL;
    }

    r = SSL_CTX_set_cipher_list(sslctx, "ALL:!aNULL:!eNULL");
    if (r <= 0) {
        ERROR_PRINTF("SSL_CTX_use_certificate_file() fail!\n");
        free(sslctx);
        return NULL;
    }

    r = SSL_CTX_use_certificate_file(sslctx, cert, SSL_FILETYPE_PEM);
    if (r <= 0) {
        ERROR_PRINTF("SSL_CTX_use_certificate_file() fail!\n");
        free(sslctx);
        return NULL;
    }

    r = SSL_CTX_use_PrivateKey_file(sslctx, key, SSL_FILETYPE_PEM);
    if (r <= 0) {
        ERROR_PRINTF("SSL_CTX_use_PrivateKey_file() fail!\n");
        free(sslctx);
        return NULL;
    }
    return sslctx;
}

static X509 *import_x509_ca(char *cert)
{
    FILE *f;
    f = fopen(cert, "r");
    if (!f) {
        ERROR_PRINTF("can't open certificate %s\n", cert);
        return NULL;
    }

    // Read cert
    X509 *x509 = PEM_read_X509(f, NULL, NULL, NULL);
    if (!x509) {
        ERROR_PRINTF("can't read certificate %s\n", cert);
        fclose(f);
        return NULL;
    }
    fclose(f);

    DEBUG_PRINTF("import Certificate %s ok!\n", cert);
    return x509;
    //X509_free(x509);
}

static EVP_PKEY *import_pem_key(char *key)
{
    FILE *f;
    f = fopen(key, "r");
    if (!f) {
        ERROR_PRINTF("can't open key %s\n", key);
        return NULL;
    }

    // Read key
    EVP_PKEY *pkey = PEM_read_PrivateKey(f, NULL, NULL, NULL);
    if (!pkey) {
        ERROR_PRINTF("can't read key %s\n", key);
        fclose(f);
        return NULL;
    }
    fclose(f);

    DEBUG_PRINTF("import PrivateKey %s ok!\n", key);
    return pkey;
    //EVP_PKEY_free(pkey);
}

static int add_x509_extension(X509 *cert, int nid, char *value)
{
    X509_EXTENSION *ex = NULL;
    X509V3_CTX ctx;

    // This sets the 'context' of the extensions. No configuration database
    X509V3_set_ctx_nodb(&ctx);

    // Issuer and subject certs: both the target since it is self signed, no request and no CRL
    X509V3_set_ctx(&ctx, cert, cert, NULL, NULL, 0);
    ex = X509V3_EXT_conf_nid(NULL, &ctx, nid, value);
    if (!ex) {
        return -1;
    }

    int result = X509_add_ext(cert, ex, -1);

    X509_EXTENSION_free(ex);

    return (result == 0) ? 0 : -1;
}

static int create_x509_certificate(struct ssl_cert_t *ca, const char *domain)
{
    int r;
    X509 *x509;
    x509 = X509_new();
    if (!x509) {
        SSL_DUMP_ERRORS();
        return -1;
    }
    X509_set_version(x509, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
    X509_gmtime_adj(X509_get_notBefore(x509), -600);
    X509_gmtime_adj(X509_get_notAfter(x509), 365 * 24 * 3600);

    X509_NAME *name;
    name = X509_get_subject_name(x509);

    //X509_NAME_add_entry_by_txt(name, "C",  MBSTRING_ASC,
    //                           (unsigned char *)"CA", -1, -1, 0);
    //X509_NAME_add_entry_by_txt(name, "O",  MBSTRING_ASC,
    //                           (unsigned char *)"MyCompany Inc.", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                               (unsigned char *)domain, -1, -1, 0);

    char *san = NULL;
    r = asprintf(&san, "DNS: %s", domain);
    if (r < 0) {
        ERROR_PRINTF("asprintf() %s\n", strerror(errno));
        goto out1;
    }
    r = add_x509_extension(x509, NID_subject_alt_name, san);
    free(san);
    if (0 == r) {
        SSL_DUMP_ERRORS();
        goto out1;
    }

    X509_NAME *ca_name = X509_get_subject_name(ca->x509);

    r = X509_set_issuer_name(x509, ca_name);
    if (0 == r) {
        SSL_DUMP_ERRORS();
        goto out1;
    }

    r = X509_set_pubkey(x509, ca->pkey);
    if (0 == r) {
        SSL_DUMP_ERRORS();
        goto out1;
    }

    r = X509_sign(x509, ca->pkey, EVP_sha256());
    if (0 == r) {
        SSL_DUMP_ERRORS();
        goto out1;
    }

    //X509_print_fp(stdout, x509);
    char *path = "_tmp";
    r = access(path, F_OK);
    if (r < 0) {
        r = mkdir(path, S_IRWXU|S_IRWXG);
        if (r < 0) {
            ERROR_PRINTF("mkdir() %s\n", strerror(errno));
            goto out1;
        }
        DEBUG_PRINTF("create %s\n", path);
    }

    char *cert = NULL;
    r = asprintf(&cert, "%s/%s.crt", path, domain);
    if (r < 0) {
        ERROR_PRINTF("asprintf() %s\n", strerror(errno));
        goto out1;
    }

    FILE *f;
    f = fopen(cert, "wb");
    free(cert);
    if (!f) {
        ERROR_PRINTF("can't open file\n");
        goto out1;
    }
    PEM_write_X509(
        f,         /* write the certificate to the file we've opened */
        x509       /* our certificate */
    );
    fclose(f);

    return 0;
out1:
    X509_free(x509);
    return -1;
}

static SSL_CTX *create_ssl_self_ctx(struct ssl_cert_t *ca, const char *domain, const char *key)
{
    int r;
    SSL_CTX *ctx;
    char *path = "_tmp";
    char *cert = NULL;
    r = asprintf(&cert, "%s/%s.crt", path, domain);
    if (r < 0) {
        ERROR_PRINTF("asprintf() %s\n", strerror(errno));
        return NULL;
    }

    r = access(cert, F_OK);
    if (r < 0) {
        r = create_x509_certificate(ca, domain);
        if (r < 0) {
            free(cert);
            return NULL;
        }
        DEBUG_PRINTF("create %s\n", cert);
    }
    ctx = create_ssl_ctx(cert, key);
    free(cert);
    return ctx;
}

static void tcp_connect_callback(struct netloop_conn_t *conn)
{
    struct netloop_conn_t *peer = (struct netloop_conn_t *)netloop_priv(conn);

    if (NETLOOP_TYPE_REMOTE == conn->type) {
        DEBUG_PRINTF("new connect peer fd: %d %c %c --> %d %c %c\n",
         peer->fd, peer->type, peer->proto, conn->fd, conn->type, conn->proto);
    }
}

static void tcp_recv_callback(struct netloop_conn_t *conn, void *buf, int len)
{
    struct netloop_conn_t *peer = (struct netloop_conn_t *)netloop_priv(conn);
    ASSERT(peer);

    peer->send(peer, buf, len);
    NONE_PRINTF("new data %d\n", len);
}

static void tcp_close_callback(struct netloop_conn_t *conn)
{
    struct netloop_conn_t *peer = (struct netloop_conn_t *)netloop_priv(conn);
    if (peer) {
        peer->data = NULL;
        peer->close(peer);
    }
}

static void tcp_full_callback(struct netloop_conn_t *conn)
{
    struct netloop_conn_t *peer = (struct netloop_conn_t *)netloop_priv(conn);
    ASSERT(peer);

    peer->pause_recv(peer);
    NONE_PRINTF("full\n");
}

static void tcp_drain_callback(struct netloop_conn_t *conn)
{
    struct netloop_conn_t *peer = (struct netloop_conn_t *)netloop_priv(conn);
    ASSERT(peer);

    peer->resume_recv(peer);
    NONE_PRINTF("drain\n");
}

static void ssl_pre_recv_callback(struct netloop_conn_t *conn, void *buf, int len)
{
    struct netloop_conn_t *peer = (struct netloop_conn_t *)netloop_priv(conn);
    ASSERT(peer);

    peer->send(peer, buf, len);
    char *line = strstr(buf, "\r");
    if (line) {
        len = line - (char *)buf;
        DEBUG_PRINTF("new msg: %.*s\n", len, (char *)buf);
    }
    conn->recv_cb = tcp_recv_callback;
}

static void ssl_remote_set_sni_callback(struct netloop_conn_t *conn)
{
    int r;
    const char *hostname = netloop_get_peer_host(conn);

    if (hostname && netloop_ssl_get_ssl(conn)) {
        r = SSL_set_tlsext_host_name(netloop_ssl_get_ssl(conn), hostname);
        if (!r) {
            ERROR_PRINTF("SSL_set_tlsext_host_name(%s) %d\n", hostname, r);
        }
    }
}

static int ssl_do_remote_connect(struct netloop_conn_t *conn, char *host, uint16_t port)
{
    struct netloop_conn_t *remote;
    struct netloop_ssl_server_t *server = (struct netloop_ssl_server_t *)conn->head;
    ASSERT(server);

    remote = server->new_remote(server, &(struct netloop_ssl_opt_t){
        .tcp = {
            .host = host,
            .port = port,
            .connect_cb = tcp_connect_callback,
            .recv_cb = tcp_recv_callback,
            .close_cb = tcp_close_callback,
            .full_cb = tcp_full_callback,
            .drain_cb = tcp_drain_callback,
            .data = NULL,
        },
        .ctx = NULL,
    });
    if (!remote) {
        ERROR_PRINTF("new_remote fail!\n");
        conn->close(conn);
        return -1;
    }
    conn->recv_cb = ssl_pre_recv_callback;
    conn->close_cb = tcp_close_callback;  //!!
    conn->data = remote;
    remote->data = conn;
    //netloop_ssl_set_preconnect_callback(remote, ssl_remote_set_sni_callback);
    return 0;
}

static void do_fake_connect(struct netloop_conn_t *conn, char *host, uint16_t port)
{
    int r;
    SSL_CTX *sslctx;
    struct mitm_data_t *md = (struct mitm_data_t *)netloop_priv(conn);

    sslctx = create_ssl_self_ctx(&md->ca, host, KEY_FILE);
    if (!sslctx) {
        ERROR_PRINTF("create_ssl_ctx() fail!\n");
        conn->close(conn);
        return;
    }

    char *connect_msg = "HTTP/1.1 200 Connection Established\r\n\r\n";
    conn->send(conn, connect_msg, strlen(connect_msg));
    ((struct netloop_ssl_conn_t *)conn)->data = host;

    DEBUG_PRINTF("ssl strip: %s:%u\n", host, port);
    conn->connect_cb = NULL;
    conn = netloop_ssl_init_by_conn(conn, sslctx);
    if (!conn) {
        conn->close(conn);
        return;
    }

    r = ssl_do_remote_connect(conn, host, port);
    if (r < 0) {
        return;
    }
}

static struct netloop_conn_t *do_http(struct netloop_conn_t *conn, char *host, uint16_t port)
{
    struct netloop_conn_t *remote;
    struct netloop_server_t *server = (struct netloop_server_t *)conn->head;
    ASSERT(server);

    remote = server->new_remote(server, &(struct netloop_opt_t){
        .host = host,
        .port = port,
        .connect_cb = tcp_connect_callback,
        .recv_cb = tcp_recv_callback,
        .close_cb = tcp_close_callback,
        .full_cb = tcp_full_callback,
        .drain_cb = tcp_drain_callback,
        .data = NULL,
    });
    if (!remote) {
        ERROR_PRINTF("new_remote fail!\n");
        conn->close(conn);
        return remote;
    }
    conn->recv_cb = tcp_recv_callback;
    conn->close_cb = tcp_close_callback;
    conn->data = remote;
    remote->data = conn;

    return remote;
}

static void tcp_pre_recv_callback(struct netloop_conn_t *conn, void *buf, int len)
{
    int r;
    struct addrinfo_t addr;

    r = parse_addr_in_http(&addr, buf, len);
    if (r < 0) {
        ERROR_PRINTF("parse addr fail!\n");
        conn->close(conn);
        return;
    }

    if (strncmp("CONNECT", buf, 7) == 0) {
        do_fake_connect(conn, addr.host, addr.port);
    } else {
        struct netloop_conn_t *remote = do_http(conn, addr.host, addr.port);
        if (remote) {
            remote->send(remote, buf, len);
        }
    }
}


int main(int argc, char **argv)
{
    int r;
    struct netloop_server_t *server;
    struct netloop_ssl_server_t *ssl_server;
    struct netloop_conn_t *listener;
    struct mitm_data_t md;

    DEBUG_PRINTF("%s build: %s, %s\n", argv[0], __DATE__, __TIME__);

    signal(SIGPIPE, SIG_IGN);

    md.ca.x509 = import_x509_ca(CERT_FILE);
    if (!md.ca.x509) {
        SSL_DUMP_ERRORS();
        return -1;
    }

    md.ca.pkey = import_pem_key(KEY_FILE);
    if (!md.ca.pkey) {
        SSL_DUMP_ERRORS();
        return -1;
    }

    server = netloop_init();
    if (!server) {
        ERROR_PRINTF("netloop init fail!\n");
        return -1;
    }

    ssl_server = netloop_ssl_init_by_server(server);
    if (!ssl_server) {
        ERROR_PRINTF("netloop ssl init fail!\n");
        return -1;
    }

    listener = server->new_server(server, &(struct netloop_opt_t){
        .host = EXAMPLE_ADDR,
        .port = EXAMPLE_PORT,
        .connect_cb = tcp_connect_callback,
        .recv_cb = tcp_pre_recv_callback,
        .close_cb = NULL,
        .full_cb = tcp_full_callback,
        .drain_cb = tcp_drain_callback,
        .data = &md,
    });
    if (!listener) {
        ERROR_PRINTF("new_server fail!\n");
        return -1;
    }

    listener = server->new_server(server, &(struct netloop_opt_t){
        .host = EXAMPLE_ADDR,
        .port = EXAMPLE_PORT + 1,
        .connect_cb = tcp_connect_callback,
        .recv_cb = tcp_pre_recv_callback,
        .close_cb = NULL,
        .full_cb = tcp_full_callback,
        .drain_cb = tcp_drain_callback,
        .data = &md,
    });
    if (!listener) {
        ERROR_PRINTF("new_server fail!\n");
        return -1;
    }

    r = server->start(server);
    if (r < 0) {
        ERROR_PRINTF("netloop start fail!\n");
        return -1;
    }
    DEBUG_PRINTF("netloop init ok!\n");

    while(1) {
        sleep(9999);
    }
    
    return 0;
}
