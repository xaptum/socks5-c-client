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

    if (0 != tcp_init()) {
	    fprintf(stderr, "Failed to initialize networking library\n");
	    return 1;
    }

    struct xsocks_openssl_ctx ssl = {0};
    if (0 != xsocks_openssl_init(&ssl, cert_file, key_file, cacert_file)) {
	    fprintf(stderr, "Failed to initialize TLS context\n");
        return 1;
    } else {
        printf("Validated client TLS cert and private key\n");
    }

    SOCKET sockfd = tcp_connect(XAPTUM_HOST, XAPTUM_PORT);
    if (INVALID_SOCKET == sockfd) {
	    fprintf(stderr, "Failed to make TCP connection\n");
        return 1;
    } else {
        printf("TCP connection successful\n");
    }

    if (0 != xsocks_tls_handshake(sockfd, &ssl)) {
	    fprintf(stderr, "Failed to run TLS handshake\n");
        return 1;
    } else {
        printf("Completed TLS handshake\n");
    }

    char bound_addr[INET6_ADDRSTRLEN] = {0};
    int bound_port = 0;
    if (0 != xsocks_socks5_connect(&ssl, remote_ip6, remote_port, bound_addr, &bound_port)) {
	    fprintf(stderr, "Failed to establish SOCKS session\n");
        return 1;
    } else {
        printf("SOCKS5 success. Bound to %s on port %d\n", bound_addr, bound_port);
    }

    //
    // Send and receive application traffic as usual
    // (except, you have to use the `SSL_[read,write]` functions).
    //
    const char *send_buf = "hi!";
    const int send_len = (int)strlen(send_buf);
    if (send_len != SSL_write(ssl.ssl, send_buf, send_len)) {
        fprintf(stderr, "Failed writing message\n");
        return 1;
    }

    xsocks_openssl_free(&ssl);

    sock_close(sockfd);

    tcp_free();
}
