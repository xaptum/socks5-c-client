#include "xsocks/socks5.h"
#include "xsocks/tcp.h"
#include "xsocks/tls.h"

#include <stdio.h>
#include <string.h>

#define XAPTUM_HOST "23.147.128.113"
#define XAPTUM_PORT "443"

int main(int argc, char *argv[])
{
    if (6 != argc) {
        fprintf(stderr, "usage: %s <cert> <key> <CA cert> <remote ipv6> <remote port>\n", argv[0]);
        return 1;
    }

    const char *cert_file = argv[1];
    const char *key_file = argv[2];
    const char *cacert_file = argv[3];
    const char *remote_ip6 = argv[4];
    int remote_port = atoi(argv[5]);

    struct xsocks_openssl_ctx ssl = {};
    if (0 != xsocks_openssl_init(&ssl, cert_file, key_file, cacert_file))
        return 1;

    int sockfd = tcp_connect(XAPTUM_HOST, XAPTUM_PORT);
    if (sockfd < 0)
        return 1;

    if (0 != xsocks_tls_handshake(sockfd, &ssl))
        return 1;

    if (0 != xsocks_socks5_connect(&ssl, remote_ip6, remote_port))
        return 1;

    //
    // Send and receive application traffic as usual
    // (except, you have to use the `SSL_[read,write]` functions).
    //
    const char *send_buf = "hi!";
    const size_t send_len = strlen(send_buf);
    if (send_len != SSL_write(ssl.ssl, send_buf, send_len)) {
        fprintf(stderr, "Failed writing message\n");
        return 1;
    }

    xsocks_openssl_free(&ssl);
}
