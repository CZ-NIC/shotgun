/*  conntest.c - tool to test bind before connect for establishing TCP connections
    Copyright (C) 2019  CZ.NIC, z.s.p.o <knot-resolver@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <assert.h>

#define MAX_CONN_PER_IP 30000
#define NUMBER_OF_IPS 16
#define CLIENT_IP_STRFORMAT "fd8d:fbca:f789:166::%d"
#define SERVER_IP_STR "fd8d:fbca:f789:166::cafe"
#define SERVER_PORT 4242
#define MAX_CONN (MAX_CONN_PER_IP * NUMBER_OF_IPS)


int create_connection(struct sockaddr_in6* src, struct sockaddr_in6* dest) {
	int s = socket(AF_INET6, SOCK_STREAM, 0);
	int bind_address_no_port = 1;
	char str[INET6_ADDRSTRLEN];

	if (s == -1) {
		perror("socket()");
		return -1;
	}

	if (setsockopt(s, IPPROTO_IP, IP_BIND_ADDRESS_NO_PORT,
		(const void *) &bind_address_no_port, sizeof(int)) == -1) {
		perror("failed to set IP_BIND_ADDRESS_NO_PORT");
		return -1;
	}

	int enable = 1;
	if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0) {
    		perror("setsockopt(SO_REUSEADDR) failed");
		return -1;
	}

	int flags = fcntl(s, F_GETFL, 0);
	assert(flags != -1);

	if (fcntl(s, F_SETFL, flags | O_NONBLOCK) == -1) {
		perror("failed to set O_NONBLOCK");
		return -1;
	}

	if (bind(s, (struct sockaddr*)src, sizeof(struct sockaddr_in6)) == -1) {
		perror("bind()");
		inet_ntop(AF_INET6, &(src->sin6_addr), str, INET6_ADDRSTRLEN);
		printf("%s\n", str);
		return -1;
	}

	if (connect(s, (struct sockaddr*)dest, sizeof(struct sockaddr_in6)) == -1) {
		if (errno == EINPROGRESS) {
			return s;
		}
		perror("failed to connect()");
		return -1;
	}

	return s;
}

int main()
{
	struct sockaddr_in6 src_addr[NUMBER_OF_IPS];
	struct sockaddr_in6 dest_addr;
	char str[INET6_ADDRSTRLEN];

	for (int i = 0; i < NUMBER_OF_IPS; ++i) {
		src_addr[i].sin6_family = AF_INET6;
		src_addr[i].sin6_port = htons(0);

		char *src_ip;
		asprintf(&src_ip, CLIENT_IP_STRFORMAT, i + 1);
		assert(inet_pton(AF_INET6, src_ip, &src_addr[i].sin6_addr) == 1);
		free(src_ip);
	}

	for (int i = 0; i < NUMBER_OF_IPS; ++i) {
		inet_ntop(AF_INET6, &(src_addr[i].sin6_addr), str, INET6_ADDRSTRLEN);
		printf("%s\n", str);
	}

	dest_addr.sin6_family = AF_INET6;
	dest_addr.sin6_port = htons(SERVER_PORT);
	inet_pton(AF_INET6, SERVER_IP_STR, &dest_addr.sin6_addr);

	int fds[MAX_CONN];
	// fd_set wfds, rfds;
	int ret;

	/*
	FD_ZERO(&wfds);
	FD_ZERO(&rfds);

	printf("connect() start\n");
	*/

	for (int i = 0; i < MAX_CONN; ++i) {
		if (i%1000==0) {
			printf("conn: %d\n", i);
		}
		ret = create_connection(&src_addr[i%NUMBER_OF_IPS], &dest_addr);
		if (ret < 0) {
			continue;
		}
		fds[i] = ret;
		//FD_SET(ret, &wfds);
	}

	/*
	struct timeval tv;
	tv.tv_sec = 5;
	tv.tv_usec = 0;

	printf("sleeping...\n");
	sleep(1);

	unsigned char tcp_dnswire[] =
		"\x00\x28\xfa\x80\x01\x20\x00\x01\x00\x00\x00\x00\x00\x01\x00\x00"
		"\x01\x00\x01\x00\x00\x29\x10\x00\x00\x00\x00\x00\x00\x0c\x00\x0a"
		"\x00\x08\x03\x1d\x11\xf5\x53\xda\x33\xdb";

	ret = select(MAX_CONN, NULL, &wfds, NULL, &tv);
	printf("select(): %d\n", ret);

	for (int j = 0; j < MAX_CONN; ++j) {
		if (FD_ISSET(fds[j], &wfds)) {
			send(fds[j], tcp_dnswire, sizeof(tcp_dnswire) / sizeof(*tcp_dnswire), 0);
			FD_SET(fds[j], &rfds);
		}
	}

	tv.tv_sec = 5;
	tv.tv_usec = 0;

	printf("sent. sleeping...\n");
	sleep(3);

	ret = select(MAX_CONN, &rfds, NULL, NULL, &tv);
	printf("read select(): %d\n", ret);
	*/

	for (int j = 0; j < MAX_CONN; ++j) {
		shutdown(fds[j], SHUT_RDWR);
		close(fds[j]);
	}

	return 0;
}
