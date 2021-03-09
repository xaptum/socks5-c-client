#ifndef SOCKS5_C_CLIENT_TCP_H
#define SOCKS5_C_CLIENT_TCP_H
#pragma once

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#else
	typedef int SOCKET;
#include <unistd.h>
#include <netdb.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#define INVALID_SOCKET -1
#define SOCKET_ERROR -1
#endif

int
tcp_init(void);

int
tcp_free(void);

SOCKET
tcp_connect(const char *host, const char *port);

void
sock_close(SOCKET sock);

#endif
