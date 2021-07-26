/*
 * netutils_ssl.c of netloop
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
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "netutils.h"


#include "log.h"
#define NONE_PRINTF    LOG_NONE
#define DEBUG_PRINTF  LOG_DEBUG
#define WARN_PRINTF   LOG_WARN
#define ERROR_PRINTF  LOG_ERROR
#define ASSERT(if_true)     while(!(if_true)) {  \
    ERROR_PRINTF("assert(%s) failed at %s, %s:%d\n",  \
     #if_true, __FILE__, __FUNCTION__, __LINE__); exit(-1);};


int ssl_library_init(void)
{
    DEBUG_PRINTF("SSL Version: %s\n", SSLeay_version(SSLEAY_VERSION));
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
    return 0;
}


static X509 *import_x509_ca(const char *cert)
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

static EVP_PKEY *import_pem_key(const char *key)
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



int import_x509_pem(struct ssl_cert_t *pem, const char *cert, const char *key)
{
    pem->x509 = import_x509_ca(cert);
    if (!pem->x509) {
        SSL_DUMP_ERRORS();
        return -1;
    }

    pem->pkey = import_pem_key(key);
    if (!pem->pkey) {
        SSL_DUMP_ERRORS();
        return -1;
    }
    return 0;
}

int free_x509_pem(struct ssl_cert_t *pem)
{
    X509_free(pem->x509);
    EVP_PKEY_free(pem->pkey);
    return 0;
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

/* Set the key and cert */
SSL_CTX *create_ssl_ctx(const char *cert, const char *key)
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

SSL_CTX *create_ssl_self_ctx(struct ssl_cert_t *ca, const char *domain, const char *key)
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

SSL_CTX *create_ssl_self_ca_ctx(const char *domain, const char *ca, const char *key)
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
        struct ssl_cert_t ca_pem;
        r = import_x509_pem(&ca_pem, ca, key);
        if (r < 0) {
            free(cert);
            return NULL;
        }

        r = create_x509_certificate(&ca_pem, domain);
        free_x509_pem(&ca_pem);
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

SSL *create_ssl_by_fd(SSL_CTX *ctx, int sockfd)
{
    SSL *ssl = SSL_new(ctx);
    if (!ssl) {
        SSL_DUMP_ERRORS();
        return NULL;
    }
    SSL_set_fd(ssl, sockfd);
    SSL_set_mode(ssl, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
    return ssl;
}

SSL *create_ssl(struct netloop_main_t *nm, SSL_CTX *ctx, int if_bind, const char *host, int port)
{
    int sockfd = tcp_socket_create(nm, if_bind, host, port);
    if (sockfd < 0) {
        return NULL;
    }

    SSL *ssl = create_ssl_by_fd(ctx, sockfd);
    if (!ssl) {
        close(sockfd);
        return NULL;
    }
    return ssl;
}

void close_ssl(SSL *ssl)
{
    close(SSL_get_fd(ssl));
    SSL_free(ssl);
}
