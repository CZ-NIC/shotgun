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
#include <uv.h>

int main() {
	uv_loop_t *loop = malloc(sizeof(uv_loop_t));
	uv_loop_init(loop);

	uv_udp_t udp_socket;

	struct sockaddr_in6 src;
	struct sockaddr_in6 dst;


	printf("Now quitting.\n");
	uv_run(loop, UV_RUN_DEFAULT);

	uv_loop_close(loop);
	free(loop);
	return 0;
}
