#include "xsocks/tls.h"

int
xsocks_openssl_init(struct xsocks_openssl_ctx *ctx,
                    const char *cert_file,
                    const char *key_file,
                    const char *cacert_file)
{
    ctx->ssl_ctx = SSL_CTX_new(TLS_client_method());

    if (!ctx->ssl_ctx)
    {
        fprintf(stderr, "Error allocating OpenSSL SSL_CTX\n");
        return -1;
    }

    if (!SSL_CTX_load_verify_locations(ctx->ssl_ctx, cacert_file, NULL))
    {
        fprintf(stderr, "Failed to load server TLS certificate %s",
                        cacert_file);
        return -1;
    }
    printf("Loaded server TLS certificate %s\n", cacert_file);

    if (!(SSL_CTX_use_certificate_file(ctx->ssl_ctx, cert_file, SSL_FILETYPE_PEM) ||
          SSL_CTX_use_certificate_file(ctx->ssl_ctx, cert_file, SSL_FILETYPE_ASN1)))
    {
        fprintf(stderr, "Failed to load client TLS certificate %s:",
                        cert_file);
        return -1;
    }
    printf("Loaded client TLS certificate %s\n", cert_file);

    if (!(SSL_CTX_use_PrivateKey_file(ctx->ssl_ctx, key_file, SSL_FILETYPE_PEM) ||
          SSL_CTX_use_PrivateKey_file(ctx->ssl_ctx, key_file, SSL_FILETYPE_ASN1)))
    {
        fprintf(stderr, "Failed to load client TLS key %s:", key_file);
        return -1;
    }
    printf("Loaded client TLS private key %s\n", key_file);

    if (!SSL_CTX_check_private_key(ctx->ssl_ctx))
    {
        fprintf(stderr, "Failed to validate client TLS cert and private key:");
        return -1;
    }
    printf("Validated client TLS cert and private key\n");

    return 0;
}

void
xsocks_openssl_free(struct xsocks_openssl_ctx* ctx)
{
    SSL_CTX_free(ctx->ssl_ctx);
}

int
xsocks_tls_handshake(int sockfd, struct xsocks_openssl_ctx* tls)
{
    int ret;

    tls->ssl = SSL_new(tls->ssl_ctx);
    if (!tls->ssl)
    {
        fprintf(stderr, "Failed to allocate SSL structure:");
        return -1;
    }

    if (SSL_set_min_proto_version(tls->ssl, TLS1_2_VERSION) != 1)
    {
        fprintf(stderr, "Cannot set min proto version:");
        goto free_ssl;
    }

    if (SSL_set_fd(tls->ssl, sockfd) != 1)
    {
        fprintf(stderr, "Failed to set SSL file descriptor (%d):",
                        sockfd);
        goto free_ssl;
    }

    SSL_set_connect_state(tls->ssl);
    SSL_set_verify(tls->ssl, SSL_VERIFY_PEER, NULL);

    ret = SSL_do_handshake(tls->ssl);
    if (ret != 1)
    {
        fprintf(stderr, "Failed to do TLS handshake\n");
        goto free_ssl;
    }

    printf("Completed TLS handshake\n");
    goto out;

free_ssl:
    SSL_free(tls->ssl);

out:
    return 0;
}
