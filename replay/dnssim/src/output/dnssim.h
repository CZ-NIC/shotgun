/*  Copyright (C) CZ.NIC, z.s.p.o. <knot-resolver@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#include <dnsjit/core/log.h>
#include <dnsjit/core/receiver.h>

#ifndef __dnsjit_output_dnssim_h
#define __dnsjit_output_dnssim_h

#include <stdbool.h>

typedef enum output_dnssim_transport {
    OUTPUT_DNSSIM_TRANSPORT_UDP_ONLY,
    OUTPUT_DNSSIM_TRANSPORT_UDP,
    OUTPUT_DNSSIM_TRANSPORT_TCP,
    OUTPUT_DNSSIM_TRANSPORT_TLS,
    OUTPUT_DNSSIM_TRANSPORT_HTTPS2,
    OUTPUT_DNSSIM_TRANSPORT_QUIC,
} output_dnssim_transport_t;

typedef enum output_dnssim_h2_method {
    OUTPUT_DNSSIM_H2_GET,
    OUTPUT_DNSSIM_H2_POST
} output_dnssim_h2_method_t;

typedef struct output_dnssim_stats output_dnssim_stats_t;
struct output_dnssim_stats {
    output_dnssim_stats_t* prev;
    output_dnssim_stats_t* next;

    uint64_t* latency;

    uint64_t since_ms;
    uint64_t until_ms;

    uint64_t requests;
    uint64_t ongoing;
    uint64_t answers;

    /* Number of connections that are open at the end of the stats interval. */
    uint64_t conn_active;

    /* Number of TCP/QUIC connection handshake attempts during the stats interval. */
    uint64_t conn_handshakes;

    /* Number of connections that have been resumed with TLS session resumption. */
    uint64_t conn_resumed;

    /* Number of QUIC connections that have used 0-RTT transport parameters to
     * initiate a new connection. */
    uint64_t conn_quic_0rtt_loaded;
    uint64_t quic_0rtt_sent;
    uint64_t quic_0rtt_answered;

    /* Number of timed out connection handshakes during the stats interval. */
    uint64_t conn_handshakes_failed;

    uint64_t rcode_noerror;
    uint64_t rcode_formerr;
    uint64_t rcode_servfail;
    uint64_t rcode_nxdomain;
    uint64_t rcode_notimp;
    uint64_t rcode_refused;
    uint64_t rcode_yxdomain;
    uint64_t rcode_yxrrset;
    uint64_t rcode_nxrrset;
    uint64_t rcode_notauth;
    uint64_t rcode_notzone;
    uint64_t rcode_badvers;
    uint64_t rcode_badkey;
    uint64_t rcode_badtime;
    uint64_t rcode_badmode;
    uint64_t rcode_badname;
    uint64_t rcode_badalg;
    uint64_t rcode_badtrunc;
    uint64_t rcode_badcookie;
    uint64_t rcode_other;
};

typedef struct output_dnssim {
    core_log_t _log;

    uint64_t processed;
    uint64_t discarded;
    uint64_t ongoing;

    output_dnssim_stats_t* stats_sum;
    output_dnssim_stats_t* stats_current;
    output_dnssim_stats_t* stats_first;

    size_t zero_rtt_data_initial_capacity;

    size_t max_clients;
    bool   free_after_use;
    bool   zero_rtt;

    uint64_t timeout_ms;
    uint64_t idle_timeout_ms;
    uint64_t handshake_timeout_ms;
    uint64_t stats_interval_ms;
} output_dnssim_t;

core_log_t* output_dnssim_log();

output_dnssim_t* output_dnssim_new(size_t max_clients);
void             output_dnssim_free(output_dnssim_t* self);

void output_dnssim_log_name(output_dnssim_t* self, const char* name);
void output_dnssim_set_transport(output_dnssim_t* self, output_dnssim_transport_t tr);
int  output_dnssim_target(output_dnssim_t* self, const char* ip, uint16_t port);
int  output_dnssim_bind(output_dnssim_t* self, const char* ip);
int  output_dnssim_tls_priority(output_dnssim_t* self, const char* priority, bool is_quic);
int  output_dnssim_run_nowait(output_dnssim_t* self);
void output_dnssim_timeout_ms(output_dnssim_t* self, uint64_t timeout_ms);
void output_dnssim_h2_uri_path(output_dnssim_t* self, const char* uri_path);
void output_dnssim_h2_method(output_dnssim_t* self, const char* method);
void output_dnssim_h2_zero_out_msgid(output_dnssim_t* self, bool zero_out_msgid);
void output_dnssim_stats_collect(output_dnssim_t* self, uint64_t interval_ms);
void output_dnssim_stats_finish(output_dnssim_t* self);

core_receiver_t output_dnssim_receiver();

#endif
