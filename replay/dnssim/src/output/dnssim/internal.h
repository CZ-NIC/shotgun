/*  Copyright (C) 2019-2021 CZ.NIC, z.s.p.o. <knot-resolver@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef __dnsjit_output_dnssim_internal_h
#define __dnsjit_output_dnssim_internal_h

#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>
#include <nghttp2/nghttp2.h>
#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <uv.h>
#include <dnsjit/core/object/dns.h>
#include <dnsjit/core/object/payload.h>

#include "../dnssim.h"

#define DNSSIM_MIN_GNUTLS_VERSION 0x030700
#define DNSSIM_MIN_GNUTLS_ERRORMSG "dnssim tls/https2/quic transport requires GnuTLS >= 3.7.0"
#ifndef DNSSIM_HAS_GNUTLS
#define DNSSIM_HAS_GNUTLS (GNUTLS_VERSION_NUMBER >= DNSSIM_MIN_GNUTLS_VERSION)
#endif

#ifdef __GNUC__
#define DNSSIM_MAYBE_UNUSED __attribute__((unused))
#else
#define DNSSIM_MAYBE_UNUSED
#endif

#define _self ((_output_dnssim_t*)self)
#define _ERR_MALFORMED -2
#define _ERR_MSGID -3
#define _ERR_TC -4
#define _ERR_QUESTION -5

#define _MAX_URI_LEN 65536
#define MAX_DNSMSG_SIZE 65535
#define WIRE_BUF_SIZE (MAX_DNSMSG_SIZE + 2 + 16384) /** max tcplen + 2b tcplen + 16kb tls record */
#define MAX_QUIC_TOKEN_LENGTH 1024

#define _OUTPUT_DNSSIM_CLIENT_MAX_0RTT_DATA 8

typedef struct _output_dnssim_request     _output_dnssim_request_t;
typedef struct _output_dnssim_connection  _output_dnssim_connection_t;
typedef struct _output_dnssim_client      _output_dnssim_client_t;

/*
 * Query-related structures.
 */

typedef struct _output_dnssim_query _output_dnssim_query_t;
struct _output_dnssim_query {
    /*
     * Next query in the list.
     *
     * Currently, next is used for TCP clients/connection, which makes it
     * impossible to use for tracking multiple queries of a single request.
     *
     * TODO: refactor the linked lists to allow query to be part of multiple lists
     */
    _output_dnssim_query_t* next;

    output_dnssim_transport_t transport;
    _output_dnssim_request_t* req;

    bool is_0rtt;

    /* Query state, currently used for TCP and QUIC. */
    enum {
        _OUTPUT_DNSSIM_QUERY_PENDING_WRITE,
        _OUTPUT_DNSSIM_QUERY_PENDING_WRITE_CB,
        _OUTPUT_DNSSIM_QUERY_PENDING_CLOSE,
        _OUTPUT_DNSSIM_QUERY_WRITE_FAILED,
        _OUTPUT_DNSSIM_QUERY_SENT,
    } state;
};

typedef struct _output_dnssim_query_udp _output_dnssim_query_udp_t;
struct _output_dnssim_query_udp {
    _output_dnssim_query_t qry;

    uv_udp_t* handle;
    uv_buf_t  buf;
};

typedef struct _output_dnssim_query_stream _output_dnssim_query_stream_t;
struct _output_dnssim_query_stream {
    _output_dnssim_query_t qry;

    /* Connection this query is assigned to. */
    _output_dnssim_connection_t* conn;

    uv_write_t write_req;

    /* Send buffers for libuv; 0 is for dnslen, 1 is for dnsmsg. */
    uv_buf_t bufs[2];

    /* HTTP/2 or QUIC stream id that was used to send this query. */
    int64_t stream_id;

    /* Receive buffer (currently used only by HTTP/2). */
    uint8_t* recv_buf;
    ssize_t  recv_buf_len;
};

struct _output_dnssim_request {
    /* List of queries associated with this request. */
    _output_dnssim_query_t* qry;

    /* Client this request belongs to. */
    _output_dnssim_client_t* client;

    /* The DNS question to be resolved. */
    core_object_payload_t* payload;
    core_object_dns_t*     dns_q;
    const uint8_t*         question;
    ssize_t                question_len;

    /* Timestamps for latency calculation. */
    uint64_t created_at;
    uint64_t ended_at;

    /* Timer for tracking timeout of the request. */
    uv_timer_t* timer;

    /* The output component of this request. */
    output_dnssim_t* dnssim;

    /* State of the request. */
    enum {
        _OUTPUT_DNSSIM_REQ_ONGOING,
        _OUTPUT_DNSSIM_REQ_CLOSING
    } state;

    /* When `true`, the request has been answered properly. */
    bool answered;

    /* Statistics interval in which this request is tracked. */
    output_dnssim_stats_t* stats;
};

/*
 * Connection-related structures.
 */

/* Read-state of connection's data stream. */
typedef enum _output_dnssim_read_state {
    _OUTPUT_DNSSIM_READ_STATE_CLEAN,
    _OUTPUT_DNSSIM_READ_STATE_DNSLEN, /* Expecting bytes of dnslen. */
    _OUTPUT_DNSSIM_READ_STATE_DNSMSG, /* Expecting bytes of dnsmsg. */
    _OUTPUT_DNSSIM_READ_STATE_INVALID
} _output_dnssim_read_state_t;

/* TLS-related data for a single connection. */
typedef struct _output_dnssim_tls_ctx {
    gnutls_session_t session;
    bool has_ticket;
    uint8_t*         buf;
    ssize_t          buf_len;
    ssize_t          buf_pos;
    size_t           write_queue_size;
} _output_dnssim_tls_ctx_t;

/* HTTP2 context for a single connection. */
typedef struct _output_dnssim_http2_ctx {
    nghttp2_session* session;

    /* Query to which the dnsbuf currently being processed belongs to. */
    _output_dnssim_query_stream_t* current_qry;

    /* Maximum number of concurrent and currently open streams. */
    uint32_t max_concurrent_streams;
    uint32_t open_streams;

    /* Flag indicating whether we received the peer's initial SETTINGS frame. */
    bool remote_settings_received;
} _output_dnssim_http2_ctx_t;

typedef struct _output_dnssim_quic_sent_payload _output_dnssim_quic_sent_payload_t;
struct _output_dnssim_quic_sent_payload {
    _output_dnssim_quic_sent_payload_t* next;
    uint16_t length;
    char data[];
};

typedef struct _output_dnssim_quic_deferred _output_dnssim_quic_deferred_t;
struct _output_dnssim_quic_deferred {
    _output_dnssim_quic_deferred_t* next;
    ngtcp2_vec vecs[2];
    int vecs_len;
    _output_dnssim_query_stream_t* qry;
};

/* QUIC context for a single connection. */
typedef struct _output_dnssim_quic_ctx {
    ngtcp2_conn* qconn;
    ngtcp2_crypto_conn_ref qconn_ref;
    ngtcp2_ccerr ccerr;

    _output_dnssim_quic_sent_payload_t* sent_payloads;
    _output_dnssim_quic_deferred_t* deferreds;
    bool bye;

    uint8_t secret[32];
} _output_dnssim_quic_ctx_t;

/* Linked list of stream buffers. */
typedef struct _output_dnssim_stream _output_dnssim_stream_t;
struct _output_dnssim_stream {
    _output_dnssim_stream_t* prev;
    _output_dnssim_stream_t* next;
    _output_dnssim_read_state_t read_state;
    bool data_free_after_use;
    int64_t stream_id;
    size_t data_len;
    size_t data_pos;
    char* data;
};

struct _output_dnssim_connection {
    _output_dnssim_connection_t* next;

    enum {
        _OUTPUT_DNSSIM_CONN_TRANSPORT_NULL = 0,
        _OUTPUT_DNSSIM_CONN_TRANSPORT_TCP,
        _OUTPUT_DNSSIM_CONN_TRANSPORT_UDP,
    } transport_type;

    union {
        uv_tcp_t* tcp;
        uv_udp_t* udp; /* (for QUIC) */
    } transport;

    /* Timeout timer for establishing the connection. */
    uv_timer_t* handshake_timer;

    /* Idle timer for connection reuse. rfc7766#section-6.2.3 */
    uv_timer_t* idle_timer;
    bool        is_idle;

    /* Whether the connection is in an early data state. */
    bool is_0rtt;
    bool had_0rtt_success;

    /* Timer that nudges the connection logic on expiry - e.g. ngtcp2. */
    uv_timer_t *expiry_timer;

    /* List of queries that have been queued (pending write callback). */
    _output_dnssim_query_t* queued;

    /* List of queries that have been sent over this connection. */
    _output_dnssim_query_t* sent;

    /* Client this connection belongs to. */
    _output_dnssim_client_t* client;

    /* State of the connection.
     * Numeric ordering of constants is significant and follows the typical connection lifecycle.
     * Ensure new states are added to a proper place. */
    enum {
        _OUTPUT_DNSSIM_CONN_INITIALIZED           = 0,
        _OUTPUT_DNSSIM_CONN_TRANSPORT_HANDSHAKE   = 10,
        _OUTPUT_DNSSIM_CONN_TLS_HANDSHAKE         = 20,
        _OUTPUT_DNSSIM_CONN_EARLY_DATA            = 25,
        _OUTPUT_DNSSIM_CONN_EARLY_DATA_CONGESTED  = 26,
        _OUTPUT_DNSSIM_CONN_ACTIVE                = 30,
        _OUTPUT_DNSSIM_CONN_CONGESTED             = 35,
        _OUTPUT_DNSSIM_CONN_CLOSE_REQUESTED       = 38,
        _OUTPUT_DNSSIM_CONN_GRACEFUL_CLOSING      = 39,
        _OUTPUT_DNSSIM_CONN_CLOSING               = 40,
        _OUTPUT_DNSSIM_CONN_CLOSED                = 50
    } state;

    /* Linked list of receive buffers for incomplete messages or dnslen. For
     * most transport protocols, this will only contain a single entry since
     * they only support a single stream of data per connection. There will be
     * multiple of these for e.g. QUIC, which supports multiple streams per
     * connection. */
    _output_dnssim_stream_t *streams;

    /* Statistics interval in which the handshake is tracked. */
    output_dnssim_stats_t* stats;

    /* TLS-related data. */
    _output_dnssim_tls_ctx_t* tls;

    /* HTTP/2-related data. */
    _output_dnssim_http2_ctx_t* http2;

    /* QUIC-related data. */
    _output_dnssim_quic_ctx_t* quic;

    /* Prevents immediate closure of connection. Instead, connection is moved
     * to CLOSE_REQUESTED state and setter of this flag is responsible for
     * closing the connection when clearing this flag. */
    bool prevent_close;
};

/*
 * Client structure.
 */

typedef struct _output_dnssim_0rtt_data _output_dnssim_0rtt_data_t;
struct _output_dnssim_0rtt_data {
    _output_dnssim_0rtt_data_t* next;

    size_t capacity;
    size_t used;
    uint8_t* data;
};


struct _output_dnssim_client {
    /* Dnssim component this client belongs to. */
    output_dnssim_t* dnssim;

    /* List of connections.
     * Multiple connections may be used (e.g. some are already closed for writing).
     */
    _output_dnssim_connection_t* conn;

    /* Stack of encoded 0-RTT data. */
    _output_dnssim_0rtt_data_t* zero_rtt_data;
    size_t zero_rtt_data_count;

    /* List of queries that are pending to be sent over any available connection. */
    _output_dnssim_query_t* pending;

    /* TLS-ticket for session resumption. */
    gnutls_datum_t tls_ticket;

    /* QUIC token. */
    uint8_t quic_token[MAX_QUIC_TOKEN_LENGTH];
    size_t quic_token_length;
};

/*
 * DnsSim-related structures.
 */

typedef struct _output_dnssim_source _output_dnssim_source_t;
struct _output_dnssim_source {
    _output_dnssim_source_t* next;
    struct sockaddr_storage  addr;
};

typedef struct _output_dnssim _output_dnssim_t;
struct _output_dnssim {
    output_dnssim_t pub;

    uv_loop_t  loop;
    uv_timer_t stats_timer;

    struct sockaddr_storage   target;
    _output_dnssim_source_t*  source;
    output_dnssim_transport_t transport;

    char                      h2_uri_authority[_MAX_URI_LEN];
    char                      h2_uri_path[_MAX_URI_LEN];
    bool                      h2_zero_out_msgid;
    output_dnssim_h2_method_t h2_method;

    /* Array of clients, mapped by client ID (ranges from 0 to max_clients). */
    _output_dnssim_client_t* client_arr;

    gnutls_priority_t*               tls_priority;
    gnutls_certificate_credentials_t tls_cred;
    char                             wire_buf[WIRE_BUF_SIZE]; /* thread-local buffer for processing tls input */
};

/* Provides data for HTTP/2 data frames. */
typedef struct {
    const uint8_t* buf;
    size_t         len;
} _output_dnssim_https2_data_provider_t;

/*
 * Forward function declarations.
 */

int  _output_dnssim_bind_before_connect(output_dnssim_t* self, uv_handle_t* handle);
int  _output_dnssim_create_query_udp(output_dnssim_t* self, _output_dnssim_request_t* req);
int  _output_dnssim_create_query_tcp(output_dnssim_t* self, _output_dnssim_request_t* req);
void _output_dnssim_close_query_udp(_output_dnssim_query_udp_t* qry);
void _output_dnssim_close_query_tcp(_output_dnssim_query_stream_t* qry);
int  _output_dnssim_answers_request(_output_dnssim_request_t* req, core_object_dns_t* response);
void _output_dnssim_request_answered(_output_dnssim_request_t* req, core_object_dns_t* msg, bool is_early);
void _output_dnssim_maybe_free_request(_output_dnssim_request_t* req);
void _output_dnssim_on_uv_alloc(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf);
int  _output_dnssim_append_to_query_buf(_output_dnssim_query_stream_t* qry, const uint8_t* data, size_t datalen);
void _output_dnssim_create_request(output_dnssim_t* self, _output_dnssim_client_t* client, core_object_payload_t* payload);
void _output_dnssim_close_request(_output_dnssim_request_t* req);
int  _output_dnssim_handle_pending_queries(_output_dnssim_client_t* client);
int  _output_dnssim_tcp_connect(output_dnssim_t* self, _output_dnssim_connection_t* conn);
void _output_dnssim_tcp_close(_output_dnssim_connection_t* conn);
void _output_dnssim_tcp_write_query(_output_dnssim_connection_t* conn, _output_dnssim_query_stream_t* qry);
void _output_dnssim_conn_close(_output_dnssim_connection_t* conn);
void _output_dnssim_conn_bye(_output_dnssim_connection_t* conn);
void _output_dnssim_conn_idle(_output_dnssim_connection_t* conn);
void _output_dnssim_conn_move_query_to_pending(_output_dnssim_query_stream_t* qry);
void _output_dnssim_conn_move_queries_to_pending(_output_dnssim_query_stream_t** qry_list);
int  _output_dnssim_handle_pending_queries(_output_dnssim_client_t* client);
void _output_dnssim_conn_early_data(_output_dnssim_connection_t* conn);
void _output_dnssim_conn_activate(_output_dnssim_connection_t* conn);
void _output_dnssim_conn_maybe_free(_output_dnssim_connection_t* conn);
void _output_dnssim_read_dns_stream(_output_dnssim_connection_t* conn, size_t len, const char* data, int64_t stream_id);
void _output_dnssim_read_dnsmsg(_output_dnssim_connection_t* conn, size_t len, const char* data);
_output_dnssim_query_stream_t* _output_dnssim_get_stream_query(_output_dnssim_connection_t* conn, int64_t stream_id);
void _output_dnssim_0rtt_data_push(_output_dnssim_client_t* client,
                                   _output_dnssim_0rtt_data_t* zero_rtt_data);
void _output_dnssim_0rtt_data_pop_and_free(_output_dnssim_client_t* client);


#if DNSSIM_HAS_GNUTLS
void _output_dnssim_rand(void *data, size_t len);

int  _output_dnssim_create_query_tls(output_dnssim_t* self, _output_dnssim_request_t* req);
void _output_dnssim_close_query_tls(_output_dnssim_query_stream_t* qry);
int  _output_dnssim_tls_init(_output_dnssim_connection_t* conn, bool has_0rtt);
void _output_dnssim_tls_process_input_data(_output_dnssim_connection_t* conn);
void _output_dnssim_tls_close(_output_dnssim_connection_t* conn);
void _output_dnssim_tls_write_query(_output_dnssim_connection_t* conn, _output_dnssim_query_stream_t* qry);

int  _output_dnssim_create_query_https2(output_dnssim_t* self, _output_dnssim_request_t* req);
void _output_dnssim_close_query_https2(_output_dnssim_query_stream_t* qry);
int  _output_dnssim_https2_init(_output_dnssim_connection_t* conn);
int  _output_dnssim_https2_setup(_output_dnssim_connection_t* conn);
void _output_dnssim_https2_process_input_data(_output_dnssim_connection_t* conn, size_t len, const char* data);
void _output_dnssim_https2_close(_output_dnssim_connection_t* conn);
void _output_dnssim_https2_write_query(_output_dnssim_connection_t* conn, _output_dnssim_query_stream_t* qry);

int  _output_dnssim_create_query_quic(output_dnssim_t* self, _output_dnssim_request_t* req);
void _output_dnssim_close_query_quic(_output_dnssim_query_stream_t* qry);
int  _output_dnssim_quic_connect(output_dnssim_t* self, _output_dnssim_connection_t* conn);
int  _output_dnssim_quic_init(_output_dnssim_connection_t* conn);
int  _output_dnssim_quic_setup(_output_dnssim_connection_t* conn);
void _output_dnssim_quic_process_input_data(_output_dnssim_connection_t* conn,
                                            const struct sockaddr *remote_sa,
                                            size_t len, const char* data);
void _output_dnssim_quic_close(_output_dnssim_connection_t* conn);
void _output_dnssim_quic_bye(_output_dnssim_connection_t* conn);
void _output_dnssim_quic_write_query(_output_dnssim_connection_t* conn, _output_dnssim_query_stream_t* qry);
#endif

#endif
