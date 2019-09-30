#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ipv6.h>
#include <linux/udp.h>

#include <endian.h>
#include <string.h>
#include <libknot/consts.h>
#include <libknot/packet/wire.h>

#include "bpf_endian.h"
#include "parsing_helpers.h"

#ifndef UDP_PORT
#define UDP_PORT 53
#endif

static inline uint16_t from32to16(uint32_t sum)
{
	sum = (sum & 0xffff) + (sum >> 16);
	sum = (sum & 0xffff) + (sum >> 16);
	return sum;
}

__attribute__((section("xdp_reflect_udp"), used))
int xdp_reflect_udp_func(struct xdp_md *ctx)
{
	// Start parsing headers, and XDP_PASS everything but UDP to Linux stack.
	struct ethhdr *eth;
	struct iphdr *iphdr;
	struct ipv6hdr *ipv6hdr;
	struct udphdr *udphdr;

	void *data_end = (void *)(long)ctx->data_end;
	struct hdr_cursor nh = { .pos = (void *)(long)ctx->data };

	const int eth_type = parse_ethhdr(&nh, data_end, &eth);
	int ip_type;
	switch (eth_type) {
		case ETH_P_IP:
			ip_type = parse_iphdr(&nh, data_end, &iphdr);
			break;
		case ETH_P_IPV6:
			ip_type = parse_ip6hdr(&nh, data_end, &ipv6hdr);
			break;
		default:
			return XDP_PASS;
	}

	if (ip_type != IPPROTO_UDP)
		return XDP_PASS;
	const int dns_len = parse_udphdr(&nh, data_end, &udphdr);
	if (dns_len < 0 || udphdr->dest != __bpf_htons(UDP_PORT))
		return XDP_PASS;
	uint8_t *dns_wire = nh.pos;
	if (dns_len < KNOT_WIRE_HEADER_SIZE
	    || dns_wire + KNOT_WIRE_HEADER_SIZE > (uint8_t *)data_end) {
		return XDP_ABORTED;
	}
	// "Subtract" the interesting part of DNS header from the UDP checksum.
	// (It's the part with flags, RCODE and OPCODE.)
	const uint16_t *dns_wire_16 = (uint16_t *)dns_wire;
	const uint32_t udp_csum = (uint32_t)~__bpf_ntohs(udphdr->check)
				+ 0xffff1 // sufficiently large ones' complement 16-bit zero
				- __bpf_ntohs(dns_wire_16[1]);


	// Everything passed; now we prepare the answer.
	knot_wire_set_qr(dns_wire);
	knot_wire_set_rcode(dns_wire, KNOT_RCODE_NOERROR);


	// Now fixup all the boring stuff in headers.
	
	{ // swap port numbers and finish UDP checksum
		__typeof__(udphdr->source) tmp = udphdr->source;
		udphdr->source = udphdr->dest;
		udphdr->dest = tmp;

		udphdr->check = ~__bpf_htons(from32to16(
					udp_csum + __bpf_ntohs(dns_wire_16[1])
				));
	}
	/* Note: UDPv4, UDPv6, IPv4 and IPv6 header checksums are not affected
	 * by swapping bits over a distance divisible by 16 bits, so the only parts
	 * we needed to account was the change in DNS data.
	 */

	// IPvX: swap IP addresses
	if (eth_type == ETH_P_IP) {
		__typeof__(iphdr->saddr) tmp = iphdr->saddr;
		iphdr->saddr = iphdr->daddr;
		iphdr->daddr = tmp;

	} else if (eth_type == ETH_P_IPV6) {
		__typeof__(ipv6hdr->saddr) tmp = ipv6hdr->saddr;
		ipv6hdr->saddr = ipv6hdr->daddr;
		ipv6hdr->daddr = tmp;

	} else {
		return XDP_ABORTED; // impossible anyway
	}

	{ // swap MAC addresses; unfortunately these are defined as arrays
		__typeof__(eth->h_dest) tmp;
		memcpy(tmp,           eth->h_dest,   sizeof(tmp));
		memcpy(eth->h_dest,   eth->h_source, sizeof(tmp));
		memcpy(eth->h_source, tmp,           sizeof(tmp));
	}

	return XDP_TX; // transmit from the same interface
}

