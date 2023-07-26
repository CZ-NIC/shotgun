/*  Copyright (C) 2019-2021 CZ.NIC, z.s.p.o. <knot-resolver@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "config.h"

#include "output/dnssim.h"
#include "output/dnssim/internal.h"
#include "output/dnssim/ll.h"

#include <string.h>

static core_log_t _log = LOG_T_INIT("output.dnssim");

static bool _conn_is_connecting(const _output_dnssim_connection_t* conn)
{
    return (conn->state >= _OUTPUT_DNSSIM_CONN_TRANSPORT_HANDSHAKE && conn->state <= _OUTPUT_DNSSIM_CONN_ACTIVE);
}

static bool _conn_has_transport(const _output_dnssim_connection_t* conn)
{
    switch (conn->transport_type) {
    case _OUTPUT_DNSSIM_CONN_TRANSPORT_TCP:
        return conn->transport.tcp != NULL;
    case _OUTPUT_DNSSIM_CONN_TRANSPORT_UDP:
        return conn->transport.udp != NULL;
    default:
        return false;
    }
}

void _output_dnssim_conn_maybe_free(_output_dnssim_connection_t* conn)
{
    mlassert(conn, "conn can't be nil");
    mlassert(conn->client, "conn must belong to a client");
    if (!_conn_has_transport(conn) && conn->handshake_timer == NULL && conn->idle_timer == NULL && conn->nudge_timer == NULL) {
        _ll_try_remove(conn->client->conn, conn);
        if (conn->tls != NULL) {
            free(conn->tls);
            conn->tls = NULL;
        }
        if (conn->http2 != NULL) {
            free(conn->http2);
            conn->http2 = NULL;
        }
        if (conn->quic != NULL) {
            free(conn->quic);
            conn->quic = NULL;
        }

        _output_dnssim_stream_t* stream = conn->streams;
        while (stream) {
            _output_dnssim_stream_t* to_free = stream;
            stream = to_free->next;
            if (to_free->data_free_after_use)
                free(to_free->data);
            free(to_free);
        }

        free(conn);
    }
}

static void _on_handshake_timer_closed(uv_handle_t* handle)
{
    _output_dnssim_connection_t* conn = (_output_dnssim_connection_t*)handle->data;
    mlassert(conn, "conn is nil");
    mlassert(conn->handshake_timer, "conn must have handshake timer when closing it");
    free(conn->handshake_timer);
    conn->handshake_timer = NULL;
    _output_dnssim_conn_maybe_free(conn);
}

static void _on_idle_timer_closed(uv_handle_t* handle)
{
    _output_dnssim_connection_t* conn = (_output_dnssim_connection_t*)handle->data;
    mlassert(conn, "conn is nil");
    mlassert(conn->idle_timer, "conn must have idle timer when closing it");
    free(conn->idle_timer);
    conn->is_idle    = false;
    conn->idle_timer = NULL;
    _output_dnssim_conn_maybe_free(conn);
}

static void _on_nudge_timer_closed(uv_handle_t* handle)
{
    _output_dnssim_connection_t* conn = (_output_dnssim_connection_t*)handle->data;
    mlassert(conn, "conn is nil");
    mlassert(conn->nudge_timer, "conn must have nudge timer when closing it");
    free(conn->nudge_timer);
    conn->nudge_timer = NULL;
    _output_dnssim_conn_maybe_free(conn);
}

void _output_dnssim_conn_close(_output_dnssim_connection_t* conn)
{
    mlassert(conn, "conn can't be nil");
    mlassert(conn->stats, "conn must have stats");
    mlassert(conn->client, "conn must have client");
    mlassert(conn->client->dnssim, "client must have dnssim");

    output_dnssim_t* self = conn->client->dnssim;

    switch (conn->state) {
    case _OUTPUT_DNSSIM_CONN_CLOSING:
    case _OUTPUT_DNSSIM_CONN_CLOSED:
        return;
    case _OUTPUT_DNSSIM_CONN_TRANSPORT_HANDSHAKE:
    case _OUTPUT_DNSSIM_CONN_TLS_HANDSHAKE:
        conn->stats->conn_handshakes_failed++;
        self->stats_sum->conn_handshakes_failed++;
        break;
    case _OUTPUT_DNSSIM_CONN_ACTIVE:
    case _OUTPUT_DNSSIM_CONN_CONGESTED:
        self->stats_current->conn_active--;
        break;
    case _OUTPUT_DNSSIM_CONN_INITIALIZED:
    case _OUTPUT_DNSSIM_CONN_CLOSE_REQUESTED:
    case _OUTPUT_DNSSIM_CONN_GRACEFUL_CLOSING:
        break;
    default:
        lfatal("unknown conn state: %d", conn->state);
    }
    if (conn->prevent_close) {
        lassert(conn->state <= _OUTPUT_DNSSIM_CONN_CLOSE_REQUESTED, "conn already closing");
        conn->state = _OUTPUT_DNSSIM_CONN_CLOSE_REQUESTED;
        return;
    }
    conn->state = _OUTPUT_DNSSIM_CONN_CLOSING;

    if (conn->handshake_timer != NULL) {
        uv_timer_stop(conn->handshake_timer);
        uv_close((uv_handle_t*)conn->handshake_timer, _on_handshake_timer_closed);
    }
    if (conn->nudge_timer != NULL) {
        uv_timer_stop(conn->nudge_timer);
        uv_close((uv_handle_t*)conn->nudge_timer, _on_nudge_timer_closed);
    }
    if (conn->idle_timer != NULL) {
        conn->is_idle = false;
        uv_timer_stop(conn->idle_timer);
        uv_close((uv_handle_t*)conn->idle_timer, _on_idle_timer_closed);
    }

    switch (_self->transport) {
    case OUTPUT_DNSSIM_TRANSPORT_TCP:
        _output_dnssim_tcp_close(conn);
        break;
    case OUTPUT_DNSSIM_TRANSPORT_TLS:
#if GNUTLS_VERSION_NUMBER >= DNSSIM_MIN_GNUTLS_VERSION
        _output_dnssim_tls_close(conn);
#else
        lfatal(DNSSIM_MIN_GNUTLS_ERRORMSG);
#endif
        break;
    case OUTPUT_DNSSIM_TRANSPORT_HTTPS2:
#if GNUTLS_VERSION_NUMBER >= DNSSIM_MIN_GNUTLS_VERSION
        _output_dnssim_https2_close(conn);
#else
        lfatal(DNSSIM_MIN_GNUTLS_ERRORMSG);
#endif
        break;
    case OUTPUT_DNSSIM_TRANSPORT_QUIC:
#if GNUTLS_VERSION_NUMBER >= DNSSIM_MIN_GNUTLS_VERSION
        _output_dnssim_quic_close(conn);
#else
        lfatal(DNSSIM_MIN_GNUTLS_ERRORMSG);
#endif
        break;
    default:
        lfatal("unsupported transport");
        break;
    }
}

void _output_dnssim_conn_bye(_output_dnssim_connection_t* conn)
{
    mlassert(conn, "conn can't be nil");
    mlassert(conn->stats, "conn must have stats");
    mlassert(conn->client, "conn must have client");
    mlassert(conn->client->dnssim, "client must have dnssim");

    output_dnssim_t* self = conn->client->dnssim;

    switch (conn->state) {
    case _OUTPUT_DNSSIM_CONN_INITIALIZED:
    case _OUTPUT_DNSSIM_CONN_TRANSPORT_HANDSHAKE:
    case _OUTPUT_DNSSIM_CONN_TLS_HANDSHAKE:
        _output_dnssim_conn_close(conn);
        return;

    case _OUTPUT_DNSSIM_CONN_ACTIVE:
    case _OUTPUT_DNSSIM_CONN_CONGESTED:
    case _OUTPUT_DNSSIM_CONN_CLOSE_REQUESTED:
        break;

    case _OUTPUT_DNSSIM_CONN_CLOSING:
    case _OUTPUT_DNSSIM_CONN_CLOSED:
    case _OUTPUT_DNSSIM_CONN_GRACEFUL_CLOSING:
        return;

    default:
        lfatal("unknown conn state: %d", conn->state);
    }

    conn->state = _OUTPUT_DNSSIM_CONN_GRACEFUL_CLOSING;

    /* Only QUIC supports a graceful closure right now.
     * TODO: TLS could (and maybe should) as well */
    switch (_self->transport) {
    case OUTPUT_DNSSIM_TRANSPORT_TCP:
    case OUTPUT_DNSSIM_TRANSPORT_TLS:
    case OUTPUT_DNSSIM_TRANSPORT_HTTPS2:
        _output_dnssim_conn_close(conn);
        break;
    case OUTPUT_DNSSIM_TRANSPORT_QUIC:
#if GNUTLS_VERSION_NUMBER >= DNSSIM_MIN_GNUTLS_VERSION
        _output_dnssim_quic_bye(conn);
#else
        lfatal(DNSSIM_MIN_GNUTLS_ERRORMSG);
#endif
        break;
    default:
        lfatal("unsupported transport");
        break;
    }
}

/* Close connection or run idle timer when there are no more outstanding queries. */
void _output_dnssim_conn_idle(_output_dnssim_connection_t* conn)
{
    mlassert(conn, "conn can't be nil");

    if (conn->queued == NULL && conn->sent == NULL) {
        if (conn->idle_timer == NULL)
            _output_dnssim_conn_close(conn);
        else if (!conn->is_idle) {
            conn->is_idle = true;
            uv_timer_again(conn->idle_timer);
        }
    }
}

void _output_dnssim_conn_move_queries_to_pending(_output_dnssim_query_stream_t* qry)
{
    _output_dnssim_query_stream_t* qry_tmp;
    while (qry != NULL) {
        mlassert(qry->conn, "query must be associated with conn");
        mlassert(qry->conn->state == _OUTPUT_DNSSIM_CONN_CLOSED, "conn must be closed");
        mlassert(qry->conn->client, "conn must be associated with client");
        qry_tmp       = (_output_dnssim_query_stream_t*)qry->qry.next;
        qry->qry.next = NULL;
        _ll_append(qry->conn->client->pending, &qry->qry);
        qry->conn         = NULL;
        qry->qry.state    = _OUTPUT_DNSSIM_QUERY_ORPHANED;
        qry->stream_id    = -1;
        qry->recv_buf_len = 0;
        if (qry->recv_buf != NULL) {
            free(qry->recv_buf);
            qry->recv_buf = NULL;
        }
        qry = qry_tmp;
    }
}

static void _send_pending_queries(_output_dnssim_connection_t* conn)
{
    _output_dnssim_query_stream_t* qry;
    mlassert(conn, "conn is nil");
    mlassert(conn->client, "conn->client is nil");
    qry = (_output_dnssim_query_stream_t*)conn->client->pending;

    while (qry != NULL && conn->state == _OUTPUT_DNSSIM_CONN_ACTIVE) {
        _output_dnssim_query_stream_t* next = (_output_dnssim_query_stream_t*)qry->qry.next;
        if (qry->qry.state == _OUTPUT_DNSSIM_QUERY_PENDING_WRITE) {
            switch (qry->qry.transport) {
            case OUTPUT_DNSSIM_TRANSPORT_TCP:
                _output_dnssim_tcp_write_query(conn, qry);
                break;
            case OUTPUT_DNSSIM_TRANSPORT_TLS:
#if GNUTLS_VERSION_NUMBER >= DNSSIM_MIN_GNUTLS_VERSION
                _output_dnssim_tls_write_query(conn, qry);
#else
                mlfatal(DNSSIM_MIN_GNUTLS_ERRORMSG);
#endif
                break;
            case OUTPUT_DNSSIM_TRANSPORT_HTTPS2:
#if GNUTLS_VERSION_NUMBER >= DNSSIM_MIN_GNUTLS_VERSION
                _output_dnssim_https2_write_query(conn, qry);
#else
                mlfatal(DNSSIM_MIN_GNUTLS_ERRORMSG);
#endif
                break;
            case OUTPUT_DNSSIM_TRANSPORT_QUIC:
#if GNUTLS_VERSION_NUMBER >= DNSSIM_MIN_GNUTLS_VERSION
                _output_dnssim_quic_write_query(conn, qry);
#else
                mlfatal(DNSSIM_MIN_GNUTLS_ERRORMSG);
#endif
                break;
            default:
                mlfatal("unsupported protocol");
                break;
            }
        }
        qry = next;
    }
}

int _output_dnssim_handle_pending_queries(_output_dnssim_client_t* client)
{
    int ret = 0;
    mlassert(client, "client is nil");

    if (client->pending == NULL)
        return ret;

    output_dnssim_t* self = client->dnssim;
    mlassert(self, "client must belong to dnssim");

    /* Get active connection or find out whether new connection has to be opened. */
    bool                         is_connecting = false;
    _output_dnssim_connection_t* conn          = client->conn;
    while (conn != NULL) {
        if (conn->state == _OUTPUT_DNSSIM_CONN_ACTIVE)
            break;
        else if (_conn_is_connecting(conn))
            is_connecting = true;
        conn = conn->next;
    }

    if (conn != NULL) { /* Send data right away over active connection. */
        _send_pending_queries(conn);
    } else if (!is_connecting) { /* No active or connecting connection -> open a new one. */
        lfatal_oom(conn = calloc(1, sizeof(_output_dnssim_connection_t)));
        conn->state  = _OUTPUT_DNSSIM_CONN_INITIALIZED;
        conn->client = client;
        conn->stats  = self->stats_current;
        if (_self->transport == OUTPUT_DNSSIM_TRANSPORT_TLS) {
#if GNUTLS_VERSION_NUMBER >= DNSSIM_MIN_GNUTLS_VERSION
            ret = _output_dnssim_tls_init(conn);
            if (ret < 0) {
                free(conn);
                return ret;
            }
#else
            lfatal(DNSSIM_MIN_GNUTLS_ERRORMSG);
#endif
        } else if (_self->transport == OUTPUT_DNSSIM_TRANSPORT_HTTPS2) {
#if GNUTLS_VERSION_NUMBER >= DNSSIM_MIN_GNUTLS_VERSION
            ret = _output_dnssim_https2_init(conn);
            if (ret < 0) {
                free(conn);
                return ret;
            }
#else
            lfatal(DNSSIM_MIN_GNUTLS_ERRORMSG);
#endif
        } else if (_self->transport == OUTPUT_DNSSIM_TRANSPORT_QUIC) {
#if GNUTLS_VERSION_NUMBER >= DNSSIM_MIN_GNUTLS_VERSION
            ret = _output_dnssim_quic_init(conn);
            if (ret < 0) {
                free(conn);
                return ret;
            }
#else
            lfatal(DNSSIM_MIN_GNUTLS_ERRORMSG);
#endif
        }

        if (_self->transport == OUTPUT_DNSSIM_TRANSPORT_QUIC)
            ret = _output_dnssim_quic_connect(self, conn);
        else
            ret = _output_dnssim_tcp_connect(self, conn);
        if (ret < 0)
            return ret;
        _ll_append(client->conn, conn);
    } /* Otherwise, pending queries wil be sent after connected callback. */

    return ret;
}

static _output_dnssim_stream_t*
_output_dnssim_conn_find_stream(_output_dnssim_connection_t* conn,
                                int64_t stream_id, bool create)
{
    _output_dnssim_stream_t* prev = NULL;
    _output_dnssim_stream_t** target = &conn->streams;

    /* Find stream with the specified id */
    while (*target) {
        if ((*target)->stream_id == stream_id)
            return *target;

        prev = *target;
        target = &prev->next;
    }

    /* Stream not found and we do not want to create it */
    if (!create)
        return NULL;

    mlfatal_oom(*target = calloc(1, sizeof(**target)));
    (*target)->prev = prev;
    (*target)->read_state = _OUTPUT_DNSSIM_READ_STATE_DNSLEN;
    (*target)->stream_id = stream_id;
    (*target)->data_len = 2;
    return *target;
}

void _output_dnssim_conn_activate(_output_dnssim_connection_t* conn)
{
    mlassert(conn, "conn is nil");
    mlassert(conn->client, "conn must be associated with a client");
    mlassert(conn->client->dnssim, "client must be associated with dnssim");

    if (conn->state >= _OUTPUT_DNSSIM_CONN_ACTIVE)
        return;

    if (conn->handshake_timer)
        uv_timer_stop(conn->handshake_timer);

    conn->state = _OUTPUT_DNSSIM_CONN_ACTIVE;
    conn->client->dnssim->stats_current->conn_active++;

    _send_pending_queries(conn);
    _output_dnssim_conn_idle(conn);
}

static int _process_dnsmsg(_output_dnssim_connection_t* conn,
                           _output_dnssim_stream_t* stream)
{
    mlassert(conn, "conn can't be nil");
    mlassert(conn->client, "conn must have client");
    mlassert(conn->client->dnssim, "client must have dnssim");

    output_dnssim_t* self = conn->client->dnssim;

    core_object_payload_t payload = CORE_OBJECT_PAYLOAD_INIT(NULL);
    core_object_dns_t     dns_a   = CORE_OBJECT_DNS_INIT(&payload);

    payload.payload = (uint8_t*)stream->data;
    payload.len     = stream->data_len;

    dns_a.obj_prev = (core_object_t*)&payload;
    int ret        = core_object_dns_parse_header(&dns_a);
    if (ret != 0) {
        lwarning("stream response malformed");
        return _ERR_MALFORMED;
    }
    ldebug("stream recv dnsmsg id: %04x", dns_a.id);

    _output_dnssim_query_t* qry;

    if (_self->transport == OUTPUT_DNSSIM_TRANSPORT_HTTPS2) {
        lassert(conn->http2, "conn must have http2 ctx");
        lassert(conn->http2->current_qry, "http2 has no current_qry");
        lassert(conn->http2->current_qry->qry.req, "current_qry has no req");
        lassert(conn->http2->current_qry->qry.req->dns_q, "req has no dns_q");

        ret = _output_dnssim_answers_request(conn->http2->current_qry->qry.req, &dns_a);
        switch (ret) {
        case 0:
            _output_dnssim_request_answered(conn->http2->current_qry->qry.req, &dns_a);
            break;
        case _ERR_MSGID:
            lwarning("https2 QID mismatch: request=0x%04x, response=0x%04x",
                conn->http2->current_qry->qry.req->dns_q->id, dns_a.id);
            break;
        case _ERR_QUESTION:
        default:
            lwarning("https2 response question mismatch");
            break;
        }
    } else if (_self->transport == OUTPUT_DNSSIM_TRANSPORT_QUIC) {
        lassert(conn->quic, "conn must have quic ctx");
        lassert(stream->stream_id >= 0, "quic stream must have a non-negative id");

        /* TODO - maybe assign the query pointer to the stream? */
        qry = &_output_dnssim_get_stream_qry(conn, stream->stream_id)->qry;
        if (qry) {
            ret = _output_dnssim_answers_request(qry->req, &dns_a);
            switch (ret) {
            case 0:
                _output_dnssim_request_answered(qry->req, &dns_a);
                break;

            default:
                    lwarning("response question mismatch");
            }
        } else {
            lwarning("could not find qry for stream_id");
        }
    } else {
        qry = conn->sent;
        while (qry != NULL) {
            if (qry->req->dns_q->id == dns_a.id) {
                ret = _output_dnssim_answers_request(qry->req, &dns_a);
                if (ret != 0) {
                    lwarning("response question mismatch");
                } else {
                    _output_dnssim_request_answered(qry->req, &dns_a);
                }
                break;
            }
            qry = qry->next;
        }
    }

    return 0;
}

static int _parse_dnsbuf_data(_output_dnssim_connection_t* conn,
                              _output_dnssim_stream_t* stream)
{
    mlassert(conn, "conn can't be nil");
    mlassert(stream, "stream can't be nil (parse_dnsbuf_data)");
    mlassert(stream->data_pos == stream->data_len, "attempt to parse incomplete dnsbuf_data");

    int ret = 0;

    switch (stream->read_state) {
    case _OUTPUT_DNSSIM_READ_STATE_DNSLEN: {
        uint16_t dnslen;
        uint16_t* p_dnslen = (uint16_t*)stream->data;
        memcpy(&dnslen, p_dnslen, sizeof(uint16_t)); /* Avoid misalignment */
        stream->data_len = ntohs(dnslen);
        if (stream->data_len == 0) {
            mlwarning("invalid dnslen received: 0");
            stream->data_len = 2;
            stream->read_state = _OUTPUT_DNSSIM_READ_STATE_DNSLEN;
        } else if (stream->data_len < 12) {
            mldebug("invalid dnslen received: %d", stream->data_len);
            ret = -1;
        } else {
            mldebug("dnslen: %d", stream->data_len);
            stream->read_state = _OUTPUT_DNSSIM_READ_STATE_DNSMSG;
        }
        break;
    }
    case _OUTPUT_DNSSIM_READ_STATE_DNSMSG:
        ret = _process_dnsmsg(conn, stream);
        if (ret) {
            stream->read_state = _OUTPUT_DNSSIM_READ_STATE_INVALID;
        } else {
            stream->data_len = 2;
            stream->read_state = _OUTPUT_DNSSIM_READ_STATE_DNSLEN;
        }
        break;
    default:
        mlfatal("tcp invalid connection read_state");
        break;
    }

    stream->data_pos = 0;
    if (stream->data_free_after_use) {
//        if (stream->prev) {
//            stream->prev->next = stream->next;
//        } else {
//            conn->streams = stream->next;
//        }
//        if (stream->next) {
//            stream->next->prev = stream->prev;
//        }

        stream->data_free_after_use = false;
        free(stream->data);
        stream->data = NULL;
//        free(stream);
    }

    return ret;
}

static unsigned int _read_dns_stream_chunk(_output_dnssim_connection_t* conn,
                                           _output_dnssim_stream_t* stream,
                                           size_t len, const char* data)
{
    mlassert(conn, "conn can't be nil");
    mlassert(data, "data can't be nil");
    mlassert(len > 0, "no data to read");
    mlassert(stream, "stream can't be nil");
    mlassert((stream->read_state == _OUTPUT_DNSSIM_READ_STATE_DNSLEN
              || stream->read_state == _OUTPUT_DNSSIM_READ_STATE_DNSMSG),
        "connection has invalid read_state");

    int          ret = 0;
    unsigned int nread;
    size_t       expected = stream->data_len - stream->data_pos;
    mlassert(expected > 0, "no data expected");

    if (stream->data_free_after_use == false && expected > len) {
        /* Start of partial read. */
        mlassert(stream->data_pos == 0, "stream->data_pos must be 0 at start of partial read");
        mlassert(stream->data_len > 0, "stream->data_len must be set at start of partial read");
        mlassert(stream->data, "stream->data is already allocated");
        mlfatal_oom(stream->data = malloc(stream->data_len));
        stream->data_free_after_use = true;
    }

    if (stream->data_free_after_use) { /* Partial read is in progress. */
        char* dest = stream->data + stream->data_pos;
        if (expected < len)
            len = expected;
        memcpy(dest, data, len);
        stream->data_pos += len;
        nread = len;
    } else { /* Complete and clean read. */
        mlassert(expected <= len, "not enough data to perform complete read");
        stream->data = (char*)data;
        stream->data_pos  = stream->data_len;
        nread             = expected;
    }

    /* If entire dnslen/dnsmsg was read, attempt to parse it. */
    if (stream->data_pos == stream->data_len) {
        ret = _parse_dnsbuf_data(conn, stream);
        if (ret < 0)
            return ret;
    }

    return nread;
}

void _output_dnssim_read_dns_stream(_output_dnssim_connection_t* conn,
                                    size_t len, const char* data,
                                    int64_t stream_id)
{
    mlassert(conn, "conn can't be nil");
    _output_dnssim_stream_t* stream =
        _output_dnssim_conn_find_stream(conn, stream_id, true);
    mlassert(stream, "stream can't be nil (read_dns_stream)");

    int pos   = 0;
    int chunk = 0;
    while (pos < len) {
        chunk = _read_dns_stream_chunk(conn, stream, len - pos, data + pos);
        if (chunk < 0) {
            mlwarning("lost orientation in DNS stream, closing");
            _output_dnssim_conn_close(conn);
            break;
        } else {
            pos += chunk;
        }
    }
    mlassert((pos == len) || (chunk < 0), "dns stream read invalid, pos != len");
}

void _output_dnssim_read_dnsmsg(_output_dnssim_connection_t* conn, size_t len, const char* data)
{
    mlassert(conn, "conn is nil");
    mlassert(len > 0, "len is zero");
    mlassert(data, "no data");

    _output_dnssim_stream_t* stream =
        _output_dnssim_conn_find_stream(conn, -1, true);
    mlassert(stream, "stream can't be nil (read_dnsmsg)");
    mlassert(stream->data_pos == 0, "dnsbuf not empty");
    mlassert(stream->data_free_after_use == false, "dnsbuf read in progress");

    /* Read dnsmsg of given length from input data. */
    stream->data_len = len;
    stream->read_state = _OUTPUT_DNSSIM_READ_STATE_DNSMSG;
    int nread        = _read_dns_stream_chunk(conn, stream, len, data);

    if (nread != len) {
        mlwarning("failed to read received dnsmsg");
        if (stream->data_free_after_use) {
            free(stream->data);
            stream->data = NULL;
        }
    }

    /* Clean state afterwards. */
    stream->read_state          = _OUTPUT_DNSSIM_READ_STATE_DNSLEN;
    stream->data_len            = 2;
    stream->data_pos            = 0;
    stream->data_free_after_use = false;
}

_output_dnssim_query_stream_t* _output_dnssim_get_stream_qry(
        _output_dnssim_connection_t* conn, int64_t stream_id)
{
    mlassert(conn, "conn is nil");
    mlassert(stream_id >= 0, "invalid stream_id");

    _output_dnssim_query_stream_t* qry = (_output_dnssim_query_stream_t*)conn->sent;
    while (qry != NULL && qry->stream_id != stream_id) {
        qry = (_output_dnssim_query_stream_t*)qry->qry.next;
    }

    return qry;
}
