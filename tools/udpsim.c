/*  udpsim.c - output layer for dnsjit that simulates independent UDP clients
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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <uv.h>

#define CLIENT_IP_STR "::1"
#define SERVER_IP_STR "::1"


static void
_uv_udp_alloc_cb(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf) {
	buf->base = malloc(suggested_size);
	buf->len = suggested_size;
}

static void
_uv_udp_recv_cb(uv_udp_t* handle, ssize_t nread, const uv_buf_t* buf,
		const struct sockaddr* addr, unsigned flags) {
	if (nread == 0 && NULL == addr) {
		free(buf->base);
		printf("Freeing recvbuf\n");
	} else if (nread > 0) {
		printf("Received: %d\n", nread);
		for (int i = 0; i < nread; ++i) {
			printf("%c", buf->base[i]);
		}
		printf("\n");
		uv_udp_recv_stop(handle);
	}
}

int main() {
	uv_loop_t *loop = malloc(sizeof(uv_loop_t));
	uv_loop_init(loop);

	uv_udp_t handle;

	uv_buf_t buf;

	struct sockaddr_in6 src;
	struct sockaddr_in6 dst;

	uv_udp_send_t udp_send_req;

	uv_ip6_addr(CLIENT_IP_STR, 0, &src);
	uv_ip6_addr(SERVER_IP_STR, 53, &dst);

	uv_udp_init(loop, &handle);
	uv_udp_bind(&handle, (const struct sockaddr*)&src, 0);

	int addr_len = sizeof(src);
	uv_udp_getsockname(&handle, (struct sockaddr*)&src, &addr_len);

	printf("srcport: %d\n", ntohs(src.sin6_port));

	unsigned char dnswire[] =
		// "\x00\x28"  // TCP length
		"\xfa\x80\x01\x20\x00\x01\x00\x00\x00\x00\x00\x01\x00\x00"
		"\x01\x00\x01\x00\x00\x29\x10\x00\x00\x00\x00\x00\x00\x0c\x00\x0a"
		"\x00\x08\x03\x1d\x11\xf5\x53\xda\x33\xdb";

	// start listening for the reply
	uv_udp_recv_start(&handle, _uv_udp_alloc_cb, _uv_udp_recv_cb);
	// TODO erro checking

	buf = uv_buf_init(dnswire, sizeof(dnswire));
	uv_udp_send(&udp_send_req, &handle, &buf, 1, (struct sockaddr*)&dst, NULL);

	uv_run(loop, UV_RUN_DEFAULT);

	uv_close((uv_handle_t*)&handle, NULL);
	uv_loop_close(loop);
	free(loop);
	return 0;
}
