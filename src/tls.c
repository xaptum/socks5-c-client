#include "xsocks/tls.h"

int
xsocks_openssl_init(struct xsocks_openssl_ctx *ctx,
                    const char *cert_file,
                    const char *key_file,
                    const char *cacert_file)
{
    ctx->ssl_ctx = SSL_CTX_new(TLS_client_method());

    if (!ctx->ssl_ctx)
        return -1;

    if (!SSL_CTX_load_verify_locations(ctx->ssl_ctx, cacert_file, NULL))
        return -1;

    if (!(SSL_CTX_use_certificate_file(ctx->ssl_ctx, cert_file, SSL_FILETYPE_PEM) ||
          SSL_CTX_use_certificate_file(ctx->ssl_ctx, cert_file, SSL_FILETYPE_ASN1)))
        return -1;

    if (!(SSL_CTX_use_PrivateKey_file(ctx->ssl_ctx, key_file, SSL_FILETYPE_PEM) ||
          SSL_CTX_use_PrivateKey_file(ctx->ssl_ctx, key_file, SSL_FILETYPE_ASN1)))
        return -1;

    if (!SSL_CTX_check_private_key(ctx->ssl_ctx))
        return -1;

    return 0;
}

void
xsocks_openssl_free(struct xsocks_openssl_ctx* ctx)
{
    SSL_CTX_free(ctx->ssl_ctx);
}

int
xsocks_tls_handshake(SOCKET sockfd, struct xsocks_openssl_ctx* tls)
{
    int ret;

    tls->ssl = SSL_new(tls->ssl_ctx);
    if (!tls->ssl)
        return -1;

    if (SSL_set_min_proto_version(tls->ssl, TLS1_2_VERSION) != 1)
        goto free_ssl;

    // Nb. We have to explicitly cast to int for Windows (where Socket is unsigned).
    if (SSL_set_fd(tls->ssl, (int)sockfd) != 1)
        goto free_ssl;

    SSL_set_connect_state(tls->ssl);
    SSL_set_verify(tls->ssl, SSL_VERIFY_PEER, NULL);

    ret = SSL_do_handshake(tls->ssl);
    if (ret != 1)
        goto free_ssl;

    goto out;

free_ssl:
    SSL_free(tls->ssl);

out:
    return 0;
}
