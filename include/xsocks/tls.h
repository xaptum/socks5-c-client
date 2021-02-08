#ifndef SOCKS5_C_CLIENT_TLS_H
#define SOCKS5_C_CLIENT_TLS_H
#pragma once

#include <openssl/ssl.h>

struct xsocks_openssl_ctx {
    SSL_CTX* ssl_ctx;
    SSL* ssl;
};

int
xsocks_openssl_init(struct xsocks_openssl_ctx *ctx,
                    const char *cert_file,
                    const char *key_file,
                    const char *cacert_file);

void
xsocks_openssl_free(struct xsocks_openssl_ctx* ctx);

int
xsocks_tls_handshake(int sockfd, struct xsocks_openssl_ctx* tls);

#endif
