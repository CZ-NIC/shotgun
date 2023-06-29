/*  Copyright (C) CZ.NIC, z.s.p.o. <knot-resolver@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "config.h"

#include "output/dnssim.h"
#include "output/dnssim/internal.h"
#include "output/dnssim/ll.h"

#include <string.h>
#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_gnutls.h>

#if GNUTLS_VERSION_NUMBER >= DNSSIM_MIN_GNUTLS_VERSION

#define OUTPUT_DNSSIM_QUIC_INITIAL_MAX_CONCURRENT_STREAMS 100
#define OUTPUT_DNSSIM_QUIC_DEFAULT_MAX_CONCURRENT_STREAMS 0xffffffffu

#define OUTPUT_DNSSIM_QUIC_ALPN "doq"

static core_log_t _log = LOG_T_INIT("output.dnssim");

typedef void (*_output_dnssim_quic_send_cb)(_output_dnssim_connection_t* conn,
                                            int status, void* baton);

typedef struct {
    uv_udp_send_t req;
    uint8_t buffer[];
} _output_dnssim_quic_send_wrapper_t;

static inline _output_dnssim_quic_send_wrapper_t*
_output_dnssim_quic_send_wrapper_new(size_t buflen)
{
    _output_dnssim_quic_send_wrapper_t* sw;
    mlfatal_oom(sw = malloc(sizeof(*sw) + buflen));
    memset(sw, 0, sizeof(*sw));
    sw->req.data = sw;
    return sw;
}

/* Forward decls **************************************************************/

static int quic_send(_output_dnssim_connection_t *conn, uint32_t flags,
                     int64_t stream_id);
static int quic_send_data(_output_dnssim_connection_t *conn, uint32_t flags,
                          ngtcp2_vec *vecs, ngtcp2_ssize vecs_len,
                          int64_t stream_id);


/* Callbacks for LibUV ********************************************************/

static void udp_alloc_cb(uv_handle_t* handle, size_t suggested_size,
                         uv_buf_t* buf)
{
    void *data;
    mlfatal_oom(data = malloc(suggested_size));
    buf->base = data;
    buf->len = suggested_size;
}

static void udp_recv_cb(uv_udp_t* udp, ssize_t nread, const uv_buf_t* buf,
                        const struct sockaddr* addr, unsigned flags)
{
    if (nread < 0) {
        mlwarning("quic nread error: %s (%s)", uv_strerror((int)nread), uv_err_name((int)nread));
        return;
    }

    _output_dnssim_connection_t* conn = udp->data;
    char ntop_buf[INET6_ADDRSTRLEN];
    const char *ntop;
    if (addr) {
        ntop = inet_ntop(addr->sa_family, addr, ntop_buf, sizeof(ntop_buf));
        if (!ntop)
            ntop = strerror(errno);
    } else {
        ntop = "(NONE)";
    }

    mldebug("quic udp_recv %zd bytes from %s", nread, ntop);
    if (nread)
        _output_dnssim_quic_process_input_data(conn, addr, nread, buf->base);
    uv_update_time(uv_default_loop());
    quic_send(conn, NGTCP2_STREAM_DATA_FLAG_NONE, -1);
    free(buf->base);
}

static void udp_send_cb(uv_udp_send_t* req, int status)
{
    if (status)
        mlwarning("failed to send udp packet: %s", uv_strerror(status));
    _output_dnssim_quic_send_wrapper_t *sw = req->data;
    free(sw);
}

static void nudge_timer_cb(uv_timer_t *timer)
{
    _output_dnssim_connection_t* conn = timer->data;
    quic_send(conn, NGTCP2_STREAM_DATA_FLAG_NONE, -1);
}

static void conn_timer_cb(uv_timer_t* handle)
{
    _output_dnssim_connection_t* conn = (_output_dnssim_connection_t*)handle->data;
    _output_dnssim_conn_close(conn, true);
}


/* Callbacks for NGTCP2 *******************************************************/

static void rand_cb(uint8_t *dest, size_t destlen,
                    const ngtcp2_rand_ctx *rand_ctx)
{
    (void)rand_ctx;
    _output_dnssim_rand(dest, destlen);
}

static int quic_generate_secret(uint8_t *buf, size_t buflen)
{
    mlassert(buf, "buf not provided");
    mlassert(buflen > 0 && buflen <= 32, "buflen must be >0 and <=32");
    uint8_t rand[16], hash[32];
    _output_dnssim_rand(rand, sizeof(rand));
    int ret = gnutls_hash_fast(GNUTLS_DIG_SHA256, rand, sizeof(rand), hash);
    if (ret)
        return ret;
    memcpy(buf, hash, buflen);
    return 0;
}

static int get_new_connection_id_cb(ngtcp2_conn *qconn, ngtcp2_cid *cid,
                                    uint8_t *token, size_t cidlen,
                                    void *user_data)
{
    _output_dnssim_connection_t* conn = user_data;

    _output_dnssim_rand(cid->data, cidlen);
    cid->datalen = cidlen;

    if (ngtcp2_crypto_generate_stateless_reset_token(token,
                conn->quic->secret, sizeof(conn->quic->secret), cid) != 0)
    {
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }

    return 0;
}

static ngtcp2_conn* get_conn_cb(ngtcp2_crypto_conn_ref* qconn_ref)
{
    return ((_output_dnssim_connection_t*)qconn_ref->user_data)->quic->qconn;
}

static void debug_log_printf(void* user_data, const char* fmt, ...)
{
    va_list vl;
    va_start(vl, fmt);
    vprintf(fmt, vl);
    va_end(vl);
    printf("\n");
}

static int handshake_confirmed_cb(ngtcp2_conn *qconn, void *user_data)
{
    _output_dnssim_connection_t* conn = user_data;
    _output_dnssim_conn_activate(conn);
    return 0;
}

static int recv_stream_data_cb(ngtcp2_conn* qconn, uint32_t flags,
                               int64_t stream_id, uint64_t offset,
                               const uint8_t* data, size_t datalen,
                               void* user_data, void* stream_user_data)
{
    _output_dnssim_connection_t* conn = (_output_dnssim_connection_t*)user_data;
    mlassert(conn, "conn is nil");

    _output_dnssim_query_stream_t* qry = _output_dnssim_get_stream_qry(conn, stream_id);
    mldebug("quic: data chunk recv, qconn=%p, len=%d", qconn, datalen);
    if (!qry) {
        mldebug("no query associated with this stream id, ignoring");
        return 0;
    }

    int ret = _output_dnssim_append_to_query_buf(qry, data, datalen);
    if (ret)
        return ret;

    if (flags & NGTCP2_STREAM_DATA_FLAG_FIN && qry->recv_buf_len)
        _output_dnssim_read_dns_stream(conn, qry->recv_buf_len, (char*)qry->recv_buf);

    return 0;
}

static int stream_close_cb(ngtcp2_conn* qconn, uint32_t flags,
                           int64_t stream_id, uint64_t app_error_code,
                           void* user_data, void* stream_user_data)
{
    _output_dnssim_connection_t* conn = user_data;
    mlassert(conn, "conn is nil");

    _output_dnssim_query_stream_t* qry = _output_dnssim_get_stream_qry(conn, stream_id);
    mldebug("quic: stream closed, qconn=%p", qconn);
    if (!qry) {
        mldebug("no query associated with this stream id, ignoring");
        return 0;
    }

    if (qry->recv_buf_len) {
        _output_dnssim_read_dnsmsg(conn, qry->recv_buf_len, (char*)qry->recv_buf);
        qry->recv_buf_len = 0;
    }

    return 0;
}

static const ngtcp2_callbacks quic_client_callbacks = {
    // NGTCP2-provided callbacks
    .client_initial           = ngtcp2_crypto_client_initial_cb,
    .recv_crypto_data         = ngtcp2_crypto_recv_crypto_data_cb,
    .encrypt                  = ngtcp2_crypto_encrypt_cb,
    .decrypt                  = ngtcp2_crypto_decrypt_cb,
    .hp_mask                  = ngtcp2_crypto_hp_mask_cb,
    .recv_retry               = ngtcp2_crypto_recv_retry_cb,
    .update_key               = ngtcp2_crypto_update_key_cb,
    .delete_crypto_aead_ctx   = ngtcp2_crypto_delete_crypto_aead_ctx_cb,
    .delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb,
    .get_path_challenge_data  = ngtcp2_crypto_get_path_challenge_data_cb,
    .version_negotiation      = ngtcp2_crypto_version_negotiation_cb,

    // Our callbacks
    .rand                  = rand_cb,
    .get_new_connection_id = get_new_connection_id_cb,
    .handshake_confirmed   = handshake_confirmed_cb,
    .recv_stream_data      = recv_stream_data_cb,
    .stream_close          = stream_close_cb,
};


/* Internal QUIC API **********************************************************/

static uint64_t quic_timestamp(void)
{
	struct timespec ts;
	if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
		return 0;
	}

	return (uint64_t)ts.tv_sec * NGTCP2_SECONDS + (uint64_t)ts.tv_nsec;
}

static int quic_send_data(_output_dnssim_connection_t *conn, uint32_t flags,
                          ngtcp2_vec *vecs, ngtcp2_ssize vecs_len,
                          int64_t stream_id)
{
    output_dnssim_t* self = conn->client->dnssim;
    const size_t destlen = ngtcp2_conn_get_max_tx_udp_payload_size(conn->quic->qconn);
    _output_dnssim_quic_send_wrapper_t* sw =
        _output_dnssim_quic_send_wrapper_new(destlen);

    ngtcp2_ssize send_datalen = 0;
    ngtcp2_ssize write_ret = ngtcp2_conn_writev_stream(conn->quic->qconn,
            (ngtcp2_path *)ngtcp2_conn_get_path(conn->quic->qconn),
            &conn->quic->pi, sw->buffer, destlen, &send_datalen, flags,
            stream_id, vecs, vecs_len, quic_timestamp());
    if (write_ret == NGTCP2_ERR_DRAINING) {
        lwarning("ngtcp2_conn_writev_stream draining - force closing", ngtcp2_strerror(write_ret));
        _output_dnssim_conn_close(conn, true);

        free(sw);
        return -1;
    } else if (write_ret < 0) {
        lwarning("failed ngtcp2_conn_writev_stream: %s", ngtcp2_strerror(write_ret));
        _output_dnssim_conn_close(conn, true);

        free(sw);
        return -1;
    } else if (conn->state == _OUTPUT_DNSSIM_CONN_CLOSE_REQUESTED) {
        lwarning("close requested");
        _output_dnssim_conn_close(conn, false);

        free(sw);
        return -1;
    } else if (write_ret == 0) {
        free(sw);
        return 0;
    }

    ngtcp2_conn_update_pkt_tx_time(conn->quic->qconn, quic_timestamp());

    uv_buf_t uv_buf = { (char*)sw->buffer, write_ret };
    int send_ret = uv_udp_send(&sw->req, conn->transport.udp, &uv_buf, 1, NULL,
            udp_send_cb);
    if (send_ret < 0)
        lwarning("uv_udp_send error: (%d) %s", send_ret, uv_strerror(send_ret));

    return 0;
}

static int quic_send(_output_dnssim_connection_t *conn, uint32_t flags, int64_t stream_id)
{
    return quic_send_data(conn, flags, NULL, 0, stream_id);
}

static int quic_send_conn_close(_output_dnssim_connection_t *conn)
{
    output_dnssim_t* self = conn->client->dnssim;
    const size_t destlen = ngtcp2_conn_get_max_tx_udp_payload_size(conn->quic->qconn);
    _output_dnssim_quic_send_wrapper_t* sw =
        _output_dnssim_quic_send_wrapper_new(destlen);

    ngtcp2_ccerr ccerr = {
        .type = NGTCP2_CCERR_TYPE_TRANSPORT,
    };
    ngtcp2_ssize write_ret = ngtcp2_conn_write_connection_close(conn->quic->qconn,
            (ngtcp2_path *)ngtcp2_conn_get_path(conn->quic->qconn),
            &conn->quic->pi, sw->buffer, destlen, &ccerr, quic_timestamp());
    if (write_ret < 0) {
        lwarning("failed ngtcp2_conn_write_connection_close: %s", ngtcp2_strerror(write_ret));
        free(sw);
        return -1;
    } else if (write_ret == 0) {
        free(sw);
        return 0;
    }

    ngtcp2_conn_update_pkt_tx_time(conn->quic->qconn, quic_timestamp());

    uv_buf_t uv_buf = { (char*)sw->buffer, write_ret };
    int send_ret = uv_udp_send(&sw->req, conn->transport.udp, &uv_buf, 1, NULL,
            udp_send_cb);
    if (send_ret < 0)
        lwarning("uv_udp_send error: (%d) %s", send_ret, uv_strerror(send_ret));

    return 0;
}


/* DNSSIM API *****************************************************************/

int  _output_dnssim_quic_init(_output_dnssim_connection_t* conn)
{
    mlassert(conn, "conn is nil");
    mlassert(conn->tls == NULL, "conn already has tls context");
    mlassert(conn->quic == NULL, "conn already has quic context");
    mlassert(conn->client, "conn must be associated with a client");
    mlassert(conn->client->dnssim, "client must have dnssim");

    int                     ret = -1;
    output_dnssim_t*        self = conn->client->dnssim;

    /* Initialize TLS session. */
    ret = _output_dnssim_tls_init(conn); /* TODO: QUIC-related adaptations? */
    if (ret < 0)
        return ret;

    /* Configure ALPN to negotiate HTTP/2. */
    const gnutls_datum_t protos = {
        .data = (unsigned char *)OUTPUT_DNSSIM_QUIC_ALPN,
        .size = sizeof(OUTPUT_DNSSIM_QUIC_ALPN) - 1
    };
    ret = gnutls_alpn_set_protocols(conn->tls->session, &protos, 1,
            GNUTLS_ALPN_MANDATORY);
    if (ret < 0) {
        lwarning("failed to set ALPN protocol: %s", gnutls_strerror(ret));
        return ret;
    }

    lfatal_oom(conn->quic = calloc(1, sizeof(_output_dnssim_quic_ctx_t)));
    conn->quic->max_concurrent_streams = OUTPUT_DNSSIM_QUIC_INITIAL_MAX_CONCURRENT_STREAMS;
    ret = quic_generate_secret(conn->quic->secret, sizeof(conn->quic->secret));
    if (ret) {
        lwarning("failed to generate quic secret: %s", gnutls_strerror(ret));
        return ret;
    }

    ret = uv_timer_init(&_self->loop, &conn->quic->nudge_timer);
    if (ret) {
        lwarning("failed initialize quic nudge timer: %s", uv_strerror(ret));
        return ret;
    }
    conn->quic->nudge_timer.data = conn;

    return 0;
}

int  _output_dnssim_quic_connect(output_dnssim_t* self, _output_dnssim_connection_t* conn)
{
    int ret = -1;

    conn->transport_type = _OUTPUT_DNSSIM_CONN_TRANSPORT_UDP;
    lfatal_oom(conn->transport.udp = malloc(sizeof(*conn->transport.udp)));
    ret = uv_udp_init(&_self->loop, conn->transport.udp);
    conn->transport.udp->data = conn;
    if (ret)
        return ret;

    ret = _output_dnssim_bind_before_connect(self, (uv_handle_t*)conn->transport.udp);
    if (ret < 0)
        return ret;

    /* Settings and params */
    ngtcp2_settings         settings;
    ngtcp2_settings_default(&settings);
    settings.max_tx_udp_payload_size = 1452;
    settings.initial_ts = quic_timestamp();
//    settings.log_printf = debug_log_printf; /* lots of spam - enable when actually needed */

    ngtcp2_transport_params params;
    ngtcp2_transport_params_default(&params);
    params.initial_max_streams_uni = 0;
    params.initial_max_streams_bidi = 0;
    params.initial_max_stream_data_bidi_local = NGTCP2_MAX_VARINT;
    params.initial_max_data = NGTCP2_MAX_VARINT;

    /* CIDs */
    ngtcp2_cid dcid;
    ngtcp2_cid scid;

    dcid.datalen = NGTCP2_MAX_CIDLEN;
    _output_dnssim_rand(dcid.data, dcid.datalen);
    scid.datalen = NGTCP2_MAX_CIDLEN;
    _output_dnssim_rand(scid.data, scid.datalen);

    /* Path */
    ret = uv_udp_connect(conn->transport.udp, (struct sockaddr *)&_self->target);
    if (ret < 0) {
        lwarning("uv_udp_connect failed: %s", uv_strerror(ret));
        return ret;
    }

    ngtcp2_sockaddr_union src_addr;
    int src_addr_len = sizeof(src_addr);
    ret = uv_udp_getsockname(conn->transport.udp, (struct sockaddr *)&src_addr, &src_addr_len);
    if (ret < 0) {
        lwarning("uv_udp_getsockname failed: %s", uv_strerror(ret));
        return ret;
    }

    ngtcp2_path path = {
        .local = {
            .addrlen = src_addr_len,
            .addr = (ngtcp2_sockaddr*)&src_addr
        },
        .remote = {
            .addrlen = sizeof(ngtcp2_sockaddr_union),
            .addr = (ngtcp2_sockaddr*)&_self->target
        }
    };

    /* Client */
    ret = ngtcp2_conn_client_new(&conn->quic->qconn, &dcid, &scid,
            &path, NGTCP2_PROTO_VER_V1, &quic_client_callbacks,
            &settings, &params, NULL, conn);
    if (ret != 0) {
        lwarning("failed to create ngtcp2 conn");
        return ret;
    }

    ret = ngtcp2_crypto_gnutls_configure_client_session(conn->tls->session);
    if (ret < 0) {
        lwarning("failed to configure ngtcp2 crypto");
        ngtcp2_conn_del(conn->quic->qconn);
        return ret;
    }

    conn->quic->qconn_ref = (ngtcp2_crypto_conn_ref){
        .get_conn = get_conn_cb,
        .user_data = conn
    };
    gnutls_session_set_ptr(conn->tls->session, &conn->quic->qconn_ref);
    ngtcp2_conn_set_tls_native_handle(conn->quic->qconn, conn->tls->session);

    uv_timer_start(&conn->quic->nudge_timer, nudge_timer_cb, 0, 100);

    /* Set connection handshake timeout. */
    lfatal_oom(conn->handshake_timer = malloc(sizeof(uv_timer_t)));
    uv_timer_init(&_self->loop, conn->handshake_timer);
    conn->handshake_timer->data = (void*)conn;
    uv_timer_start(conn->handshake_timer, conn_timer_cb, self->handshake_timeout_ms, 0);

    /* Set idle connection timer. */
    if (self->idle_timeout_ms > 0) {
        lfatal_oom(conn->idle_timer = malloc(sizeof(uv_timer_t)));
        uv_timer_init(&_self->loop, conn->idle_timer);
        conn->idle_timer->data = (void*)conn;

        /* Start and stop the timer to set the repeat value without running the timer. */
        uv_timer_start(conn->idle_timer, conn_timer_cb, self->idle_timeout_ms, self->idle_timeout_ms);
        uv_timer_stop(conn->idle_timer);
    }

    ret = uv_udp_recv_start(conn->transport.udp, udp_alloc_cb, udp_recv_cb);
    if (ret) {
        lwarning("failed to start receiving quic msgs: %s", uv_strerror(ret));
        return ret;
    }

    ret = quic_send(conn, NGTCP2_WRITE_STREAM_FLAG_NONE, -1);
    if (ret) {
        lwarning("failed to send quic connection req");
        return ret;
    }

    conn->stats->conn_quic_handshakes++;
    self->stats_sum->conn_quic_handshakes++;
    conn->state = _OUTPUT_DNSSIM_CONN_TRANSPORT_HANDSHAKE;

    return 0;
}

void _output_dnssim_quic_process_input_data(_output_dnssim_connection_t* conn,
                                            const struct sockaddr *remote_sa,
                                            size_t len, const char* data)
{
    mlassert(conn, "conn is nil");
    mlassert(conn->transport_type == _OUTPUT_DNSSIM_CONN_TRANSPORT_UDP, "conn transport type must be UDP");
    mlassert(conn->quic, "conn must have quic ctx");
    mlassert(conn->quic->qconn, "conn must have quic connection");

    output_dnssim_t*        self = conn->client->dnssim;
    ssize_t ret = 0;

    const ngtcp2_path *conn_path = ngtcp2_conn_get_path(conn->quic->qconn);
    ngtcp2_path_storage ps;
    ngtcp2_path_storage_init(&ps, conn_path->local.addr,
            conn_path->local.addrlen, NULL, 0, NULL);

    ngtcp2_addr_copy_byte(&ps.path.remote, (const ngtcp2_sockaddr *)remote_sa,
            (remote_sa->sa_family == AF_INET6)
                ? sizeof(struct sockaddr_in6)
                : sizeof(struct sockaddr_in));

    conn->prevent_close = true;
    ret = ngtcp2_conn_read_pkt(conn->quic->qconn, &ps.path, &conn->quic->pi,
            (uint8_t*)data, len, quic_timestamp());
    conn->prevent_close = false;
    if (ret < 0) {
        lwarning("failed ngtcp2_conn_read_pkt: %s", ngtcp2_strerror(ret));
        _output_dnssim_conn_close(conn, true);
        return;
    } else if (conn->state == _OUTPUT_DNSSIM_CONN_CLOSE_REQUESTED) {
        ldebug("connection closure requested");
        _output_dnssim_conn_close(conn, false);
        return;
    }
    mlassert(ret == 0, "ngtcp2_conn_read_pkt returned non-zero");
}

static void _output_dnssim_quic_handle_on_close(uv_handle_t* handle)
{
    _output_dnssim_connection_t *conn = handle->data;
    free(conn->transport.udp);
    conn->transport.udp = NULL;
    conn->transport_type = _OUTPUT_DNSSIM_CONN_TRANSPORT_NULL;
}

void _output_dnssim_quic_close(_output_dnssim_connection_t* conn, bool force)
{
    mlassert(conn, "conn can't be nil");
    mlassert(conn->tls, "conn conn must have tls ctx");
    mlassert(conn->quic, "conn conn must have quic ctx");
    mlassert(conn->client, "conn conn must belong to a client");

    if (force) {
        ngtcp2_conn_del(conn->quic->qconn);
        _output_dnssim_tls_close(conn);

        if (conn->transport_type == _OUTPUT_DNSSIM_CONN_TRANSPORT_UDP) {
            mldebug("stopping UDP reception");
            uv_udp_connect(conn->transport.udp, NULL); /* disconnect */
            uv_udp_recv_stop(conn->transport.udp);
            uv_close((uv_handle_t*)conn->transport.udp, _output_dnssim_quic_handle_on_close);
            uv_timer_stop(&conn->quic->nudge_timer);
            uv_close((uv_handle_t*)&conn->quic->nudge_timer, NULL);
        } else {
            mlassert(conn->transport_type == _OUTPUT_DNSSIM_CONN_TRANSPORT_NULL,
                    "transport type of QUIC must be UDP or NULL");
        }
    } else if (!conn->quic->close_sent) {
        conn->quic->close_sent = true;
        quic_send_conn_close(conn);
    } else {
        mlwarning("Call to conn close, but close packet already sent");
    }
}

void _output_dnssim_quic_write_query(_output_dnssim_connection_t* conn, _output_dnssim_query_stream_t* qry)
{
    mlassert(qry, "qry can't be null");
    mlassert(qry->qry.state == _OUTPUT_DNSSIM_QUERY_PENDING_WRITE, "qry must be pending write");
    mlassert(conn, "conn can't be null");
    mlassert(conn->transport_type == _OUTPUT_DNSSIM_CONN_TRANSPORT_UDP, "conn transport type must be UDP");
    mlassert(conn->state == _OUTPUT_DNSSIM_CONN_ACTIVE, "connection state != ACTIVE");
    mlassert(conn->quic, "conn must have quic ctx");
    mlassert(conn->quic->qconn, "conn must have quic connection");
    mlassert(conn->client, "conn must be associated with client");
    mlassert(conn->client->pending, "conn has no pending queries");
    mlassert(conn->client->dnssim, "client must have dnssim");

    output_dnssim_t* self = conn->client->dnssim;

    int ret = quic_send(conn, NGTCP2_WRITE_STREAM_FLAG_NONE, -1);
    if (ret) {
        lwarning("failed to send pre-stream packet");
        return;
    }

    core_object_payload_t* content = qry->qry.req->payload;
    qry->quic_net_content_len = htons(content->len);
    ngtcp2_vec vecs[2] = {
        { (uint8_t*)&qry->quic_net_content_len, sizeof(qry->quic_net_content_len) },
        { (uint8_t*)content->payload, content->len }
    };

    ret = ngtcp2_conn_open_bidi_stream(conn->quic->qconn, &qry->stream_id, NULL);
    if (ret == NGTCP2_ERR_STREAM_ID_BLOCKED) {
        return;
    } else if (ret) {
        lwarning("failed to open bidi stream: %s", ngtcp2_strerror(ret));
        return;
    }

    lassert(qry->stream_id >= 0, "stream_id not assigned");
    ret = quic_send_data(conn, NGTCP2_WRITE_STREAM_FLAG_FIN, vecs, 2, qry->stream_id);
    if (ret) {
        lwarning("failed to send packet opening bidi stream: %s", ngtcp2_strerror(ret));
        return;
    }

    ldebug("opened bidi stream %" PRIu64, qry->stream_id);

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

int _output_dnssim_create_query_quic(output_dnssim_t* self, _output_dnssim_request_t* req)
{
    mlassert_self();
    lassert(req, "req is nil");
    lassert(req->client, "request must have a client associated with it");

    _output_dnssim_query_stream_t* qry;

    lfatal_oom(qry = calloc(1, sizeof(*qry)));

    qry->qry.transport = OUTPUT_DNSSIM_TRANSPORT_QUIC;
    qry->qry.req = req;
    qry->qry.state = _OUTPUT_DNSSIM_QUERY_PENDING_WRITE;
    qry->stream_id     = -1;
    req->qry = &qry->qry;
    _ll_append(req->client->pending, &qry->qry);

    return _output_dnssim_handle_pending_queries(req->client);
}

void _output_dnssim_close_query_quic(_output_dnssim_query_stream_t* qry)
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

    free(qry->recv_buf);

    _ll_remove(req->qry, &qry->qry);
    free(qry);
}

#endif
