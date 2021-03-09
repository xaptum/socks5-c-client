#include "xsocks/socks5.h"

#ifdef _WIN32
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#endif

#define SOCKS5_VERSION     0x05
#define SOCKS5_NOAUTH      0x00
#define SOCKS5_CONNECT     0x01
#define SOCKS5_IPV6        0x04
#define SOCKS5_SUCCEEDED   0x00

/*
 * Start SOCKS5 negotiation with authentication negotiation.
 */
static int
send_auth_req(struct xsocks_openssl_ctx* tls)
{
    // For Xaptum, only the "NO AUTHENTICATION REQUIRED" method is supported.
    const unsigned char auth_req[] = {SOCKS5_VERSION,   // SOCKS version 5
                                      0x01,             // One authentication method offered
                                      SOCKS5_NOAUTH};   // method = "No authentication required"

    if (sizeof(auth_req) != SSL_write(tls->ssl, auth_req, sizeof(auth_req)))
        return -1;

    return 0;
}

/*
 * Read response after authentication request (and validate the response).
 */
static int
read_auth_resp(struct xsocks_openssl_ctx* tls)
{
    // Always 2 bytes (per RFC).
    unsigned char auth_resp[2] = {0};
    if (sizeof(auth_resp) != SSL_read(tls->ssl, auth_resp, sizeof(auth_resp)))
        return -1;

    // For Xaptum, first byte must be version5.
    if (SOCKS5_VERSION != auth_resp[0])
        return -1;

    // For Xaptum, second byte must be "NO AUTHENTICATION REQUIRED".
    if (SOCKS5_NOAUTH != auth_resp[1])
        return -1;

    return 0;
}

/*
 * Send request to establish a proxied TCP connection
 * to the given Xaptum IPv6 address at the given port.
 */
static int
send_conn_req(struct xsocks_openssl_ctx* tls,
              const char *xap_v6_addr,
              int xap_v6_port)
{
    // 1) Build request preamble.
    unsigned char conn_req[] = {SOCKS5_VERSION,     // SOCKS version 5
                                SOCKS5_CONNECT,     // Request an outbound connection
                                0x00,               // Reserved byte
                                SOCKS5_IPV6,        // Address is IPv6
                                0,0,0,0,0,0,0,0,    // placeholder for IPv6 address (below)
                                0,0,0,0,0,0,0,0,
                                0,0};               // placeholder for port (below)

    // 2) Convert string IPv6 address to binary
    const size_t addr_offset = 4;
    if (1 != inet_pton(AF_INET6, xap_v6_addr, &conn_req[addr_offset]))
        return -1;

    // 3) Convert port to network byte-order
    const size_t port_offset = 20;
    uint16_t *port_write = (uint16_t*)(&conn_req[port_offset]);
    *port_write = htons((uint16_t)xap_v6_port);

    // 4) Write connection request
    if (sizeof(conn_req) != SSL_write(tls->ssl, conn_req, sizeof(conn_req)))
        return -1;

    return 0;
}

/*
 * Receive response after connection request,
 * validate it,
 * and read out bound address:port information.
 */
static int
read_conn_resp(struct xsocks_openssl_ctx* tls,
               char *bound_addr_out,
               int *bound_port_out)
{
    // 1) Receive connection response.
    unsigned char conn_resp_preamble[4] = {0};
    if (sizeof(conn_resp_preamble) != SSL_read(tls->ssl, conn_resp_preamble, sizeof(conn_resp_preamble)))
        return -1;

    // 2) First byte must be version5
    if (SOCKS5_VERSION != conn_resp_preamble[0])
        return -1;

    // 3) If second byte isn't "SUCCEEDED", something's wrong.
    //    The values of these codes are defined in the RFC.
    if (SOCKS5_SUCCEEDED != conn_resp_preamble[1])
        return -1;

    // 4) Fourth byte must be ATYP_IPV6
    if (SOCKS5_IPV6 != conn_resp_preamble[3])
        return -1;

    // 6) Receive the address and port assigned to us.
    unsigned char conn_resp_bound[18] = {0};
    if (sizeof(conn_resp_bound) != SSL_read(tls->ssl, conn_resp_bound, sizeof(conn_resp_bound)))
        return -1;

    // 6) Read out the address assigned to us for the TCP connection
    //    (should be our Xaptum IPv6 address, as given in our TLS certificate).
    if (NULL == inet_ntop(AF_INET6, &conn_resp_bound[0], bound_addr_out, INET6_ADDRSTRLEN))
        return -1;

    // 7) Read out the port assigned to us for the TCP connection.
    const size_t port_offset = 16;
    uint16_t *bound_port_read = (uint16_t*)&conn_resp_bound[port_offset];
    *bound_port_out = ntohs(*bound_port_read);

    return 0;
}

int
xsocks_socks5_connect(struct xsocks_openssl_ctx* tls,
                      const char *xap_v6_addr,
                      int xap_v6_port,
                      char bound_addr_out[INET6_ADDRSTRLEN],
                      int *bound_port_out)
{
    if (0 != send_auth_req(tls))
        return -1;

    if (0 != read_auth_resp(tls))
        return -1;

    if (0 != send_conn_req(tls, xap_v6_addr, xap_v6_port))
        return -1;

    if (0 != read_conn_resp(tls, bound_addr_out, bound_port_out))
        return -1;

    return 0;
}
