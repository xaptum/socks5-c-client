#ifndef SOCKS5_C_CLIENT_SOCKS5_H
#define SOCKS5_C_CLIENT_SOCKS5_H
#pragma once

#include "xsocks/tls.h"

int
xsocks_socks5_connect(struct xsocks_openssl_ctx* tls,
                      const char *xap_v6_addr,
                      int xap_v6_port,
                      char bound_addr_out[INET6_ADDRSTRLEN],
                      int *bound_port_out);

#endif
