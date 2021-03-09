#include "xsocks/tcp.h"

#include <string.h>

static void
*get_in_addr(struct sockaddr *sa)
{
	if (sa->sa_family == AF_INET) {
		return &(((struct sockaddr_in*)sa)->sin_addr);
	}

	return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

int
tcp_init(void)
{
#ifdef _WIN32
	WSADATA wsa_data;
	return WSAStartup(MAKEWORD(2,2), &wsa_data);
#else
	return 0;
#endif
}

int
tcp_free(void)
{
#ifdef _WIN32
	return WSACleanup();
#else
	return 0;
#endif
}

SOCKET
tcp_connect(const char *host, const char *port)
{
    SOCKET sockfd = INVALID_SOCKET;
	struct addrinfo hints, *servinfo, *p;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	if (0 != getaddrinfo(host, port, &hints, &servinfo))
		return INVALID_SOCKET;

	// loop through all the results and connect to the first we can
	for(p = servinfo; p != NULL; p = p->ai_next) {
		if ((sockfd = socket(p->ai_family, p->ai_socktype,
				p->ai_protocol)) == INVALID_SOCKET)
			continue;

		if (connect(sockfd, p->ai_addr, (socklen_t)(p->ai_addrlen)) == SOCKET_ERROR) {
			sock_close(sockfd);
			sockfd = INVALID_SOCKET;
			continue;
		}

		break;
	}

	freeaddrinfo(servinfo);

	if (INVALID_SOCKET == sockfd)
		return INVALID_SOCKET;

    return sockfd;
}

void
sock_close(SOCKET sock)
{
#ifdef _WIN32
	closesocket(sock);
#else
	close(sock);
#endif
}
