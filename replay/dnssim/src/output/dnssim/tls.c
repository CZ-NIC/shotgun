/*  Copyright (C) 2019-2021 CZ.NIC, z.s.p.o. <knot-resolver@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "output/dnssim.h"
#include "output/dnssim/internal.h"
#include "output/dnssim/ll.h"

#include <string.h>

#if DNSSIM_HAS_GNUTLS

#ifndef MIN
#define MIN(a, b) (((a) < (b)) ? (a) : (b)) /** Minimum of two numbers **/
#endif

static core_log_t _log = LOG_T_INIT("output.dnssim");

struct async_write_ctx {
    uv_write_t                   write_req;
    _output_dnssim_connection_t* conn;
    char                         buf[];
};

static int _tls_handshake(_output_dnssim_connection_t* conn)
{
    mlassert(conn, "conn is nil");
    mlassert(conn->tls, "conn must have tls context");
    mlassert(conn->client, "conn must belong to a client");
    mlassert(conn->state <= _OUTPUT_DNSSIM_CONN_TLS_HANDSHAKE, "conn in invalid state");

    conn->state = _OUTPUT_DNSSIM_CONN_TLS_HANDSHAKE;

    return gnutls_handshake(conn->tls->session);
}

void _output_dnssim_tls_process_input_data(_output_dnssim_connection_t* conn)
{
    mlassert(conn, "conn is nil");
    mlassert(conn->client, "conn must have client");
    mlassert(conn->client->dnssim, "client must have dnssim");
    mlassert(conn->tls, "conn must have tls ctx");

    if (conn->state >= _OUTPUT_DNSSIM_CONN_CLOSING)
        return;

    output_dnssim_t* self = conn->client->dnssim;

    /* Ensure TLS handshake is performed before receiving data.
     * See https://www.gnutls.org/manual/html_node/TLS-handshake.html */
    while (conn->state <= _OUTPUT_DNSSIM_CONN_TLS_HANDSHAKE) {
        int err = _tls_handshake(conn);
        mldebug("tls handshake returned: %s", gnutls_strerror(err));
        if (err == GNUTLS_E_SUCCESS) {
            if (gnutls_session_is_resumed(conn->tls->session)) {
                conn->stats->conn_resumed++;
                self->stats_sum->conn_resumed++;
            }
            if (_self->transport == OUTPUT_DNSSIM_TRANSPORT_HTTPS2) {
                if (_output_dnssim_https2_setup(conn) < 0) {
                    _output_dnssim_conn_bye(conn);
                    return;
                }
            }
            _output_dnssim_conn_activate(conn);
            break;
        } else if (err == GNUTLS_E_AGAIN) {
            return; /* Wait for more data */
        } else if (err == GNUTLS_E_FATAL_ALERT_RECEIVED) {
            gnutls_alert_description_t alert = gnutls_alert_get(conn->tls->session);
            mlwarning("gnutls_handshake failed: %s", gnutls_alert_get_name(alert));
            _output_dnssim_conn_close(conn);
            return;
        } else if (gnutls_error_is_fatal(err)) {
            mlwarning("gnutls_handshake failed: %s", gnutls_strerror_name(err));
            _output_dnssim_conn_close(conn);
            return;
        }
    }

    /* See https://gnutls.org/manual/html_node/Data-transfer-and-termination.html#Data-transfer-and-termination */
    while (true) {
        /* Connection might have been closed due to an error, don't try to use it. */
        if (conn->state < _OUTPUT_DNSSIM_CONN_ACTIVE || conn->state >= _OUTPUT_DNSSIM_CONN_CLOSING)
            return;

        ssize_t count = gnutls_record_recv(conn->tls->session, _self->wire_buf, WIRE_BUF_SIZE);
        if (count > 0) {
            switch (_self->transport) {
            case OUTPUT_DNSSIM_TRANSPORT_TLS:
                _output_dnssim_read_dns_stream(conn, count, _self->wire_buf, -1);
                break;
            case OUTPUT_DNSSIM_TRANSPORT_HTTPS2:
                _output_dnssim_https2_process_input_data(conn, count, _self->wire_buf);
                break;
            default:
                lfatal("unsupported transport layer");
                break;
            }
        } else if (count == GNUTLS_E_AGAIN) {
            if (conn->tls->buf_pos == conn->tls->buf_len) {
                /* See https://www.gnutls.org/manual/html_node/Asynchronous-operation.html */
                break; /* No more data available in this libuv buffer */
            }
            continue;
        } else if (count == GNUTLS_E_INTERRUPTED) {
            continue;
        } else if (count == GNUTLS_E_REHANDSHAKE) {
            continue; /* Ignore rehandshake request. */
        } else if (count < 0) {
            mlwarning("gnutls_record_recv failed: %s", gnutls_strerror_name(count));
            _output_dnssim_conn_close(conn);
            return;
        } else if (count == 0) {
            break;
        }
    }
    mlassert(conn->tls->buf_len == conn->tls->buf_pos, "tls didn't read the entire buffer");
}

static ssize_t _tls_pull(gnutls_transport_ptr_t ptr, void* buf, size_t len)
{
    _output_dnssim_connection_t* conn = (_output_dnssim_connection_t*)ptr;
    mlassert(conn != NULL, "conn is null");
    mlassert(conn->tls != NULL, "conn must have tls ctx");

    ssize_t avail = conn->tls->buf_len - conn->tls->buf_pos;
    if (avail <= 0) {
        mldebug("tls pull: no more data");
        errno = EAGAIN;
        return -1;
    }

    ssize_t transfer = MIN(avail, len);
    memcpy(buf, conn->tls->buf + conn->tls->buf_pos, transfer);
    conn->tls->buf_pos += transfer;
    return transfer;
}

static void _tls_on_write_complete(uv_write_t* req, int status)
{
    mlassert(req->data != NULL, "uv_write req has no data pointer");
    struct async_write_ctx*      async_ctx = (struct async_write_ctx*)req->data;
    _output_dnssim_connection_t* conn      = async_ctx->conn;
    mlassert(conn, "conn is nil");
    mlassert(conn->tls, "conn must have tls ctx");
    mlassert(conn->tls->write_queue_size > 0, "invalid write_queue_size: %d", conn->tls->write_queue_size);
    conn->tls->write_queue_size -= 1;
    free(req->data);

    if (status < 0)
        _output_dnssim_conn_close(conn);
}

static ssize_t _tls_vec_push(gnutls_transport_ptr_t ptr, const giovec_t* iov, int iovcnt)
{
    _output_dnssim_connection_t* conn = (_output_dnssim_connection_t*)ptr;
    mlassert(conn != NULL, "conn is null");
    mlassert(conn->transport_type == _OUTPUT_DNSSIM_CONN_TRANSPORT_TCP, "conn transport type must be tcp");
    mlassert(conn->tls != NULL, "conn must have tls ctx");

    if (iovcnt == 0)
        return 0;

    /*
     * This is a little bit complicated. There are two different writes:
     * 1. Immediate, these don't need to own the buffered data and return immediately
     * 2. Asynchronous, these need to own the buffers until the write completes
     * In order to avoid copying the buffer, an immediate write is tried first if possible.
     * If it isn't possible to write the data without queueing, an asynchronous write
     * is created (with copied buffered data).
     */

    size_t   total_len = 0;
    uv_buf_t uv_buf[iovcnt];
    int      i;
    for (i = 0; i < iovcnt; ++i) {
        uv_buf[i].base = iov[i].iov_base;
        uv_buf[i].len  = iov[i].iov_len;
        total_len += iov[i].iov_len;
    }

    /* Try to perform the immediate write first to avoid copy */
    int ret = 0;
    if (conn->tls->write_queue_size == 0) {
        ret = uv_try_write((uv_stream_t*)conn->transport.tcp, uv_buf, iovcnt);
        /* from libuv documentation -
           uv_try_write will return either:
           > 0: number of bytes written (can be less than the supplied buffer size).
           < 0: negative error code (UV_EAGAIN is returned if no data can be sent immediately).
           */
        if (ret == total_len) {
            /* All the data were buffered by libuv.
             * Return. */
            return ret;
        }

        if (ret < 0 && ret != UV_EAGAIN) {
            /* uv_try_write() has returned error code other then UV_EAGAIN.
             * Return. */
            errno = EIO;
            return -1;
        }
        /* Since we are here expression below is true
         * (ret != total_len) && (ret >= 0 || ret == UV_EAGAIN)
         * or the same
         * (ret != total_len && ret >= 0) || (ret != total_len && ret == UV_EAGAIN)
         * i.e. either occurs partial write or UV_EAGAIN.
         * Proceed and copy data amount to owned memory and perform async write.
         */
        if (ret == UV_EAGAIN) {
            /* No data were buffered, so we must buffer all the data. */
            ret = 0;
        }
    }

    /* Fallback when the queue is full, and it's not possible to do an immediate write */
    char* p = malloc(sizeof(struct async_write_ctx) + total_len - ret);
    if (p != NULL) {
        struct async_write_ctx* async_ctx = (struct async_write_ctx*)p;
        async_ctx->conn                   = conn;
        char* buf                         = async_ctx->buf;
        /* Skip data written in the partial write */
        size_t to_skip = ret;
        /* Copy the buffer into owned memory */
        size_t off = 0;
        int    i;
        for (i = 0; i < iovcnt; ++i) {
            if (to_skip > 0) {
                /* Ignore current buffer if it's all skipped */
                if (to_skip >= uv_buf[i].len) {
                    to_skip -= uv_buf[i].len;
                    continue;
                }
                /* Skip only part of the buffer */
                uv_buf[i].base += to_skip;
                uv_buf[i].len -= to_skip;
                to_skip = 0;
            }
            memcpy(buf + off, uv_buf[i].base, uv_buf[i].len);
            off += uv_buf[i].len;
        }
        uv_buf[0].base = buf;
        uv_buf[0].len  = off;

        /* Create an asynchronous write request */
        uv_write_t* write_req = &async_ctx->write_req;
        memset(write_req, 0, sizeof(uv_write_t));
        write_req->data = p;

        /* Perform an asynchronous write with a callback */
        if (uv_write(write_req, (uv_stream_t*)conn->transport.tcp, uv_buf, 1, _tls_on_write_complete) == 0) {
            ret = total_len;
            conn->tls->write_queue_size += 1;
        } else {
            free(p);
            errno = EIO;
            ret   = -1;
        }
    } else {
        errno = ENOMEM;
        ret   = -1;
    }

    return ret;
}

int _tls_pull_timeout(gnutls_transport_ptr_t ptr, unsigned int ms)
{
    _output_dnssim_connection_t* conn = (_output_dnssim_connection_t*)ptr;
    mlassert(conn != NULL, "conn is null");
    mlassert(conn->tls != NULL, "conn must have tls ctx");

    ssize_t avail = conn->tls->buf_len - conn->tls->buf_pos;
    if (avail <= 0) {
        errno = EAGAIN;
        return -1;
    }
    return avail;
}

int  _output_dnssim_tls_init(_output_dnssim_connection_t* conn, bool has_0rtt)
{
    mlassert(conn, "conn is nil");
    mlassert(conn->client, "conn does not have client");
    mlassert(conn->tls == NULL, "conn already has tls context");

    int ret;
    mlfatal_oom(conn->tls = malloc(sizeof(_output_dnssim_tls_ctx_t)));
    conn->tls->has_ticket       = false;
    conn->tls->buf              = NULL;
    conn->tls->buf_len          = 0;
    conn->tls->buf_pos          = 0;
    conn->tls->write_queue_size = 0;

    unsigned int flags = GNUTLS_CLIENT | GNUTLS_NONBLOCK;

    if (has_0rtt && conn->client->tls_ticket.size != 0) {
        flags |= GNUTLS_ENABLE_EARLY_DATA
            | GNUTLS_NO_END_OF_EARLY_DATA;
    }

    ret = gnutls_init(&conn->tls->session, flags);
    if (ret < 0) {
        mldebug("failed gnutls_init() (%s)", gnutls_strerror(ret));
        free(conn->tls);
        conn->tls = 0;
        return ret;
    }

    output_dnssim_t* self = conn->client->dnssim;
    if (_self->tls_priority == NULL) {
        ret = gnutls_set_default_priority(conn->tls->session);
        if (ret < 0) {
            mldebug("failed gnutls_set_default_priority() (%s)", gnutls_strerror(ret));
            gnutls_deinit(conn->tls->session);
            free(conn->tls);
            conn->tls = 0;
            return ret;
        }
    } else {
        ret = gnutls_priority_set(conn->tls->session, *_self->tls_priority);
        if (ret < 0) {
            mldebug("failed gnutls_priority_set() (%s)", gnutls_strerror(ret));
            gnutls_deinit(conn->tls->session);
            free(conn->tls);
            conn->tls = 0;
            return ret;
        }
    }

    ret = gnutls_credentials_set(conn->tls->session, GNUTLS_CRD_CERTIFICATE, _self->tls_cred);
    if (ret < 0) {
        mldebug("failed gnutls_credentials_set() (%s)", gnutls_strerror(ret));
        gnutls_deinit(conn->tls->session);
        free(conn->tls);
        conn->tls = 0;
        return ret;
    }

    /* Set TLS session resumption ticket if available. */
    if (conn->client->tls_ticket.size != 0) {
        gnutls_datum_t* ticket = &conn->client->tls_ticket;
        gnutls_session_set_data(conn->tls->session, ticket->data, ticket->size);
        gnutls_free(conn->client->tls_ticket.data);
        conn->client->tls_ticket.size = 0;
        conn->tls->has_ticket = true;
    }

    gnutls_transport_set_pull_function(conn->tls->session, _tls_pull);
    gnutls_transport_set_pull_timeout_function(conn->tls->session, _tls_pull_timeout);
    gnutls_transport_set_vec_push_function(conn->tls->session, _tls_vec_push);
    gnutls_transport_set_ptr(conn->tls->session, conn);

    return 0;
}

int _output_dnssim_create_query_tls(output_dnssim_t* self, _output_dnssim_request_t* req)
{
    mlassert_self();
    lassert(req, "req is nil");
    lassert(req->client, "request must have a client associated with it");

    _output_dnssim_query_stream_t* qry;

    lfatal_oom(qry = calloc(1, sizeof(_output_dnssim_query_stream_t)));

    qry->qry.transport = OUTPUT_DNSSIM_TRANSPORT_TLS;
    qry->qry.req       = req;
    qry->qry.state     = _OUTPUT_DNSSIM_QUERY_PENDING_WRITE;
    req->qry           = &qry->qry; // TODO change when adding support for multiple Qs for req
    _ll_append(req->client->pending, &qry->qry);

    return _output_dnssim_handle_pending_queries(req->client);
}

void _output_dnssim_close_query_tls(_output_dnssim_query_stream_t* qry)
{
    mlassert(qry, "qry can't be null");
    mlassert(qry->qry.req, "query must be part of a request");
    _output_dnssim_request_t* req = qry->qry.req;
    mlassert(req->client, "request must belong to a client");

    _ll_try_remove(req->client->pending, &qry->qry);
    if (qry->conn) {
        _output_dnssim_connection_t* conn = qry->conn;
        _ll_try_remove(conn->sent, &qry->qry);
        qry->conn = NULL;
        _output_dnssim_conn_idle(conn);
    }

    _ll_remove(req->qry, &qry->qry);
    free(qry);
}

void _output_dnssim_tls_close(_output_dnssim_connection_t* conn)
{
    mlassert(conn, "conn can't be nil");
    mlassert(conn->tls, "conn must have tls ctx");
    mlassert(conn->client, "conn must belong to a client");

    /* Try and get a TLS session ticket for potential resumption. */
    int ret;
    if (gnutls_session_get_flags(conn->tls->session) & GNUTLS_SFLAGS_SESSION_TICKET) {
        ret = gnutls_session_get_data2(conn->tls->session, &conn->client->tls_ticket);
        if (ret < 0) {
            mldebug("gnutls_session_get_data2 failed: %s", gnutls_strerror(ret));
            conn->client->tls_ticket.size = 0;
        }
    }

    gnutls_deinit(conn->tls->session);
    if (conn->transport_type == _OUTPUT_DNSSIM_CONN_TRANSPORT_TCP)
        _output_dnssim_tcp_close(conn);
}

void _output_dnssim_tls_write_query(_output_dnssim_connection_t* conn, _output_dnssim_query_stream_t* qry)
{
    mlassert(qry, "qry can't be null");
    mlassert(qry->qry.state == _OUTPUT_DNSSIM_QUERY_PENDING_WRITE, "qry must be pending write");
    mlassert(qry->qry.req, "req can't be null");
    mlassert(qry->qry.req->dns_q, "dns_q can't be null");
    mlassert(qry->qry.req->dns_q->obj_prev, "payload can't be null");
    mlassert(conn, "conn can't be null");
    mlassert(conn->state == _OUTPUT_DNSSIM_CONN_ACTIVE, "connection state != ACTIVE");
    mlassert(conn->tls, "conn must have tls ctx");
    mlassert(conn->client, "conn must be associated with client");
    mlassert(conn->client->pending, "conn has no pending queries");

    core_object_payload_t* payload = (core_object_payload_t*)qry->qry.req->dns_q->obj_prev;
    uint16_t               len     = htons(payload->len);

    gnutls_record_cork(conn->tls->session);
    ssize_t count = 0;
    if ((count = gnutls_record_send(conn->tls->session, &len, sizeof(len)) < 0) || (count = gnutls_record_send(conn->tls->session, payload->payload, payload->len) < 0)) {
        mlwarning("gnutls_record_send failed: %s", gnutls_strerror_name(count));
        _output_dnssim_conn_close(conn);
        return;
    }

    const ssize_t submitted = sizeof(len) + payload->len;

    int ret = gnutls_record_uncork(conn->tls->session, GNUTLS_RECORD_WAIT);
    if (gnutls_error_is_fatal(ret)) {
        mlinfo("gnutls_record_uncorck failed: %s", gnutls_strerror_name(ret));
        _output_dnssim_conn_close(conn);
        return;
    }

    if (ret != submitted) {
        mlwarning("gnutls_record_uncork didn't send all data");
        _output_dnssim_conn_close(conn);
        return;
    }

    qry->conn = conn;
    _ll_remove(conn->client->pending, &qry->qry);
    _ll_append(conn->sent, &qry->qry);

    /* Stop idle timer, since there are queries to answer now. */
    if (conn->idle_timer != NULL) {
        conn->is_idle = false;
        uv_timer_stop(conn->idle_timer);
    }

    qry->qry.state = _OUTPUT_DNSSIM_QUERY_SENT;
}

#endif
