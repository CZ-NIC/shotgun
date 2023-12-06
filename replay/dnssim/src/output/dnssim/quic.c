/*  Copyright (C) CZ.NIC, z.s.p.o. <knot-resolver@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "output/dnssim.h"
#include "output/dnssim/internal.h"
#include "output/dnssim/ll.h"

#include <string.h>
#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_gnutls.h>

#if DNSSIM_HAS_GNUTLS

#define OUTPUT_DNSSIM_QUIC_ALPN "doq"

static core_log_t _log = LOG_T_INIT("output.dnssim");

typedef void (*_output_dnssim_quic_send_cb)(_output_dnssim_connection_t* conn,
                                            int status, void* baton);


/* DoQ error decls ************************************************************/

/** Enumeration generator macro for DNS-over-QUIC application errors. The first
 * parameter is the numeric code for the error, the second parameter is the
 * error identifier without the `DOQ_` prefix.
 *
 * Specified by Section 4.3. of RFC-9250. */
#define DOQ_ERROR_MAP(XX) \
    XX(0x00000000, NO_ERROR) \
    XX(0x00000001, INTERNAL_ERROR) \
    XX(0x00000002, PROTOCOL_ERROR) \
    XX(0x00000003, REQUEST_CANCELLED) \
    XX(0x00000004, EXCESSIVE_LOAD) \
    XX(0x00000005, UNSPECIFIED_ERROR) \
    XX(0xd098ea5e, ERROR_RESERVED) \
    //

/** Enumeration of DNS-over-QUIC application errors as specified by Section 4.3.
 * of RFC-9250. */
enum doq_error {
#define XX(code, cid) DOQ_##cid = (code),
    DOQ_ERROR_MAP(XX)
#undef XX
};


/* Forward decls **************************************************************/

static const char* quic_strerror(int err);
static int quic_send(_output_dnssim_connection_t *conn, bool bye);
static int quic_send_data(_output_dnssim_connection_t *conn,
                          ngtcp2_vec *vecs, ngtcp2_ssize vecs_len,
                          _output_dnssim_query_stream_t* qry, bool bye);
static uint64_t quic_timestamp(void);
static void quic_update_expiry_timer(_output_dnssim_connection_t *conn);
static void quic_check_max_streams(_output_dnssim_connection_t* conn);


/* Callbacks for LibUV ********************************************************/

static void udp_recv_cb(uv_udp_t* udp, ssize_t nread, const uv_buf_t* buf,
                        const struct sockaddr* addr, unsigned flags)
{
    if (nread < 0) {
        mlwarning("quic nread error: %s (%s)", uv_strerror((int)nread), uv_err_name((int)nread));
        return;
    }
    if (nread == 0)
        return;

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
    _output_dnssim_quic_process_input_data(conn, addr, nread, buf->base);
    free(buf->base);

    quic_check_max_streams(conn);
    quic_update_expiry_timer(conn);
}

typedef struct _output_dnssim_quic_packet {
    uv_udp_send_t req;
    uint8_t data[];
} _output_dnssim_quic_packet_t;

static void udp_send_cb(uv_udp_send_t* req, int status)
{
    if (status && status != UV_ECANCELED)
        mlwarning("failed to send udp packet: %s", uv_strerror(status));
    _output_dnssim_quic_packet_t* pkt = (_output_dnssim_quic_packet_t*)req;
    free(pkt);
}

static void expiry_timer_cb(uv_timer_t *timer)
{
    _output_dnssim_connection_t* conn = timer->data;
    int ret = ngtcp2_conn_handle_expiry(conn->quic->qconn, quic_timestamp());
    if (ret) {
        if (ret == NGTCP2_ERR_IDLE_CLOSE) {
            _output_dnssim_conn_close(conn);
            return;
        }
        mlwarning("handle_expiry: %s", ngtcp2_strerror(ret));
        return;
    }
    ret = quic_send(conn, false);
    if (ret)
        mlwarning("could not send quic data in expiry timer: %s", ngtcp2_strerror(ret));
}

static void handshake_timer_cb(uv_timer_t* handle)
{
    _output_dnssim_connection_t* conn = (_output_dnssim_connection_t*)handle->data;
    ngtcp2_ccerr_set_liberr(&conn->quic->ccerr, NGTCP2_ERR_HANDSHAKE_TIMEOUT, NULL, 0);
    _output_dnssim_conn_bye(conn);
}

static void idle_timer_cb(uv_timer_t* handle)
{
    _output_dnssim_connection_t* conn = (_output_dnssim_connection_t*)handle->data;
    ngtcp2_ccerr_default(&conn->quic->ccerr);
    _output_dnssim_conn_bye(conn);
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

    int ret = ngtcp2_crypto_generate_stateless_reset_token(token,
            conn->quic->secret, sizeof(conn->quic->secret), cid);
    if (ret)
    {
        mlfatal("could not generate stateless reset token: %s", ngtcp2_strerror(ret));
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }

    return 0;
}

static ngtcp2_conn* get_conn_cb(ngtcp2_crypto_conn_ref* qconn_ref)
{
    return ((_output_dnssim_connection_t*)qconn_ref->user_data)->quic->qconn;
}

DNSSIM_MAYBE_UNUSED
static void debug_log_printf(void* user_data, const char* fmt, ...)
{
    printf("NGTCP2: ");
    va_list vl;
    va_start(vl, fmt);
    vprintf(fmt, vl);
    va_end(vl);
    printf("\n");
}

static int handshake_completed_cb(ngtcp2_conn *qconn, void *user_data)
{
    _output_dnssim_connection_t* conn = user_data;
    // Activate for 0-RTT or 1-RTT
    if (conn->tls->has_ticket)
        _output_dnssim_conn_early_data(conn);
    quic_check_max_streams(conn);
    return 0;
}

static int handshake_confirmed_cb(ngtcp2_conn *qconn, void *user_data)
{
    _output_dnssim_connection_t* conn = user_data;
    output_dnssim_t* self = conn->client->dnssim;
    if (gnutls_session_is_resumed(conn->tls->session)) {
        conn->stats->conn_resumed++;
        self->stats_sum->conn_resumed++;
    }

    if (conn->is_0rtt) {
        conn->stats->conn_quic_0rtt_loaded++;
        self->stats_sum->conn_quic_0rtt_loaded++;
    }

    conn->is_0rtt = false;

    /* Store 0-RTT data */
    if (conn->client->dnssim->zero_rtt) {
        _output_dnssim_0rtt_data_t* zrttd;
        mlfatal_oom(zrttd = calloc(1, sizeof(*zrttd)));
        for (;;) {
            zrttd->capacity = conn->client->dnssim->zero_rtt_data_initial_capacity;
            mlfatal_oom(zrttd->data = malloc(zrttd->capacity));
            ngtcp2_ssize ssize = ngtcp2_conn_encode_0rtt_transport_params(conn->quic->qconn, zrttd->data, zrttd->capacity);
            if (ssize == NGTCP2_ERR_NOBUF) {
                free(zrttd->data);
                conn->client->dnssim->zero_rtt_data_initial_capacity *= 2;
                continue;
            }
            if (ssize < 0) {
                mlwarning("Could not encode 0-RTT data: %s", ngtcp2_strerror(ssize));
                free(zrttd->data);
                free(zrttd);
            } else {
                zrttd->used = ssize;
                _output_dnssim_0rtt_data_push(conn->client, zrttd);
            }
            break;
        }
    }

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

    _output_dnssim_query_stream_t* qry = _output_dnssim_get_stream_query(conn, stream_id);
    mldebug("quic: data chunk recv, qconn=%p, len=%d", qconn, datalen);
    if (!qry) {
        mldebug("no query associated with this stream id, ignoring");
        return 0;
    }

    int ret = _output_dnssim_append_to_query_buf(qry, data, datalen);
    if (ret)
        return ret;

    if (flags & NGTCP2_STREAM_DATA_FLAG_FIN) {
        mlassert(qry->recv_buf_len, "stream fin, but recv_buf_len is zero");
        _output_dnssim_read_dns_stream(conn, qry->recv_buf_len, (char*)qry->recv_buf, stream_id);
    }

    return 0;
}

static int stream_close_cb(ngtcp2_conn* qconn, uint32_t flags,
                           int64_t stream_id, uint64_t app_error_code,
                           void* user_data, void* stream_user_data)
{
    _output_dnssim_connection_t* conn = user_data;
    mlassert(conn, "conn is nil");

    /* This frees the `_output_dnssim_quic_sent_payload_t` allocated in
     * `_output_dnssim_quic_write_query`. When the connection is `_CLOSING` (or
     * later), this data has already been freed by `_output_dnssim_quic_close`,
     * so we skip this. */
    if (conn->state < _OUTPUT_DNSSIM_CONN_CLOSING) {
        _ll_try_remove(conn->quic->sent_payloads, (_output_dnssim_quic_sent_payload_t*)stream_user_data);
        free(stream_user_data);
    }

    quic_check_max_streams(conn);

    if (flags & NGTCP2_STREAM_CLOSE_FLAG_APP_ERROR_CODE_SET) {
        mlwarning("stream closed with %s (%" PRIu64")",
                quic_strerror(app_error_code), app_error_code);
        return 0;
    }

    return 0;
}

static int extend_max_local_streams_cb(ngtcp2_conn *qconn,
                                       uint64_t max_streams, void *user_data)
{
    _output_dnssim_connection_t* conn = user_data;
    mlassert(conn, "conn is nil");
    quic_check_max_streams(conn);
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
    .rand                          = rand_cb,
    .get_new_connection_id         = get_new_connection_id_cb,
    .handshake_completed           = handshake_completed_cb,
    .handshake_confirmed           = handshake_confirmed_cb,
    .recv_stream_data              = recv_stream_data_cb,
    .stream_close                  = stream_close_cb,
    .extend_max_local_streams_bidi = extend_max_local_streams_cb,
};


/* Internal QUIC API **********************************************************/

static const char* quic_strerror(int err)
{
    switch (err) {
#define XX(code, cid) case DOQ_##cid: return #cid;
    DOQ_ERROR_MAP(XX)
#undef XX
    default:
        return "(unknown)";
    }
}

static void quic_update_expiry_timer(_output_dnssim_connection_t *conn)
{
    ngtcp2_tstamp expiry = ngtcp2_conn_get_expiry(conn->quic->qconn);
    if (expiry == UINT64_MAX) {
        mlwarning("no expiry");
        return;
    }

    ngtcp2_tstamp now = quic_timestamp();
    if (expiry > now) {
        uv_timer_start(conn->expiry_timer, expiry_timer_cb,
                (expiry - now) / NGTCP2_MILLISECONDS, 0);
    } else {
        ngtcp2_conn_handle_expiry(conn->quic->qconn, now);
    }
}

static uint64_t quic_timestamp(void)
{
    return uv_hrtime() * NGTCP2_NANOSECONDS;
}

static void quic_send_bye(_output_dnssim_connection_t* conn)
{
    const size_t destlen = ngtcp2_conn_get_max_tx_udp_payload_size(conn->quic->qconn);
    _output_dnssim_quic_packet_t* pkt;
    mlfatal_oom(pkt = malloc(sizeof(*pkt) + destlen));
    ngtcp2_pkt_info pi = {0};

    ngtcp2_ssize write_ret = ngtcp2_conn_write_connection_close(conn->quic->qconn,
            (ngtcp2_path *)ngtcp2_conn_get_path(conn->quic->qconn),
            &pi, pkt->data, destlen, &conn->quic->ccerr, quic_timestamp());
    if (write_ret == 0) {
        _output_dnssim_conn_close(conn);
        return;
    }
    if (write_ret < 0) {
        mlwarning("write_connection_close: %s", ngtcp2_strerror(write_ret));
        return;
    }

    uv_buf_t uv_buf = { (char*)pkt->data, write_ret };
    int send_ret = uv_udp_send(&pkt->req, conn->transport.udp, &uv_buf, 1,
            NULL, udp_send_cb);
    if (send_ret < 0)
        mlwarning("uv_udp_send error: (%d) %s", send_ret, uv_strerror(send_ret));

    _output_dnssim_conn_close(conn);
}

/** Sends stream packets to server - returns NGTCP2 errors. */
static int quic_send_data(_output_dnssim_connection_t *conn,
                          ngtcp2_vec *vecs, ngtcp2_ssize vecs_len,
                          _output_dnssim_query_stream_t* qry, bool bye)
{
    if (ngtcp2_conn_in_closing_period(conn->quic->qconn))
        return 0;

    uv_timer_stop(conn->expiry_timer);
    if (!conn->transport_type)
        mlfatal("Attempt to send with no handle");

    mlassert(conn->transport_type == _OUTPUT_DNSSIM_CONN_TRANSPORT_UDP,
            "Transport type must be UDP");
    if (uv_is_closing((uv_handle_t *)conn->transport.udp))
        return 0;

    int ret = 0;
    const size_t destlen = ngtcp2_conn_get_max_tx_udp_payload_size(conn->quic->qconn);
    int64_t stream_id = (qry) ? qry->stream_id : -1;
    ngtcp2_pkt_info pi = {0};

    for (;;) {
        _output_dnssim_quic_packet_t* pkt;
        mlfatal_oom(pkt = malloc(sizeof(*pkt) + destlen));
        uint32_t flags = NGTCP2_WRITE_STREAM_FLAG_NONE;
        if (vecs_len)
            flags = NGTCP2_WRITE_STREAM_FLAG_FIN;
        ngtcp2_ssize send_datalen = 0;
        ngtcp2_ssize write_ret = ngtcp2_conn_writev_stream(conn->quic->qconn,
                (ngtcp2_path *)ngtcp2_conn_get_path(conn->quic->qconn), &pi,
                pkt->data, destlen, &send_datalen, flags, stream_id,
                vecs, vecs_len, quic_timestamp());
        if (write_ret <= 0) {
            switch (write_ret) {
            case 0:
            case NGTCP2_ERR_STREAM_SHUT_WR:
                goto end;
            case NGTCP2_ERR_WRITE_MORE:
                mlfatal("WRITE_MORE unsupported");
                ret = write_ret;
                goto end;
            case NGTCP2_ERR_DRAINING:
            case NGTCP2_ERR_CLOSING:
            case NGTCP2_ERR_DROP_CONN:
                _output_dnssim_conn_close(conn);
                return 0;
            default:
                ngtcp2_ccerr_set_liberr(&conn->quic->ccerr, write_ret, NULL, 0);
                bye = true;
                ret = write_ret;
                goto end;
            }
        }

        uv_buf_t uv_buf = { (char*)pkt->data, write_ret };
        int send_ret = uv_udp_send(&pkt->req, conn->transport.udp, &uv_buf, 1,
                NULL, udp_send_cb);
        if (send_ret < 0)
            mlwarning("uv_udp_send error: (%d) %s", send_ret, uv_strerror(send_ret));
    }

end:
    ngtcp2_conn_update_pkt_tx_time(conn->quic->qconn, quic_timestamp());
    quic_update_expiry_timer(conn);
    quic_check_max_streams(conn);
    if (bye)
        quic_send_bye(conn);
    return ret;
}

/** Sends technical QUIC packets to server - returns NGTCP2 errors. */
static int quic_send(_output_dnssim_connection_t *conn, bool bye)
{
    return quic_send_data(conn, NULL, 0, NULL, bye);
}

static void quic_check_max_streams(_output_dnssim_connection_t* conn)
{
    mlassert(conn, "conn is nil");
    mlassert(conn->quic, "conn->quic is nil");

    uint64_t left = ngtcp2_conn_get_streams_bidi_left(conn->quic->qconn);
    if (left) {
        if (conn->state == _OUTPUT_DNSSIM_CONN_CONGESTED) {
            mlinfo("congestion recovered");
            conn->state = _OUTPUT_DNSSIM_CONN_ACTIVE;
        }
    } else {
        switch (conn->state) {
        case _OUTPUT_DNSSIM_CONN_ACTIVE:
            mlinfo("reached maximum number of concurrent streams");
            conn->state = _OUTPUT_DNSSIM_CONN_CONGESTED;
            break;
        case _OUTPUT_DNSSIM_CONN_EARLY_DATA:
            mlinfo("reached maximum number of concurrent streams (early data)");
            conn->state = _OUTPUT_DNSSIM_CONN_EARLY_DATA_CONGESTED;
            break;
        default:
            break;
        }
    }
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
    ret = _output_dnssim_tls_init(conn, conn->client->dnssim->zero_rtt);
    if (ret < 0)
        return ret;

    /* Configure ALPN to negotiate DoQ. */
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
    ret = quic_generate_secret(conn->quic->secret, sizeof(conn->quic->secret));
    if (ret) {
        lwarning("failed to generate quic secret: %s", gnutls_strerror(ret));
        return ret;
    }

    lfatal_oom(conn->expiry_timer = calloc(1, sizeof(uv_timer_t)));
    ret = uv_timer_init(&_self->loop, conn->expiry_timer);
    if (ret) {
        lwarning("failed initialize quic expiry timer: %s", uv_strerror(ret));
        return ret;
    }
    conn->expiry_timer->data = conn;

    return 0;
}

int  _output_dnssim_quic_connect(output_dnssim_t* self, _output_dnssim_connection_t* conn)
{
    int ret = -1;

    conn->state = _OUTPUT_DNSSIM_CONN_TRANSPORT_HANDSHAKE;

    conn->transport_type = _OUTPUT_DNSSIM_CONN_TRANSPORT_UDP;
    lfatal_oom(conn->transport.udp = malloc(sizeof(*conn->transport.udp)));
    ret = uv_udp_init(&_self->loop, conn->transport.udp);
    if (ret) {
        lwarning("could not init UDP: %s", uv_strerror(ret));
        return ret;
    }
    conn->transport.udp->data = conn;

    ret = _output_dnssim_bind_before_connect(self, (uv_handle_t*)conn->transport.udp);
    if (ret < 0)
        return ret;

    /* Settings and params */
    ngtcp2_settings         settings;
    ngtcp2_settings_default(&settings);
    settings.handshake_timeout = self->handshake_timeout_ms * NGTCP2_MILLISECONDS;
    settings.initial_ts = quic_timestamp();
//    settings.log_printf = debug_log_printf; /* lots of spam - enable when actually needed */

    ngtcp2_transport_params params;
    ngtcp2_transport_params_default(&params);
    params.initial_max_streams_uni = 0;
    params.initial_max_streams_bidi = 0;
    params.initial_max_stream_data_bidi_local = NGTCP2_MAX_VARINT;
    params.initial_max_data = NGTCP2_MAX_VARINT;
    params.max_idle_timeout = self->idle_timeout_ms * NGTCP2_MILLISECONDS;

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

    /* Set up 0-RTT */
    if (conn->client->dnssim->zero_rtt && conn->client->zero_rtt_data && conn->tls->has_ticket) {
        ret = ngtcp2_conn_decode_and_set_0rtt_transport_params(
                conn->quic->qconn,
                conn->client->zero_rtt_data->data,
                conn->client->zero_rtt_data->used);
        if (ret) {
            lwarning("Unable to decode 0-RTT data: %s", ngtcp2_strerror(ret));
        } else {
            conn->is_0rtt = true;
        }
        _output_dnssim_0rtt_data_pop_and_free(conn->client);
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

    /* Set connection handshake timeout. */
    lfatal_oom(conn->handshake_timer = malloc(sizeof(uv_timer_t)));
    uv_timer_init(&_self->loop, conn->handshake_timer);
    conn->handshake_timer->data = (void*)conn;
    uv_timer_start(conn->handshake_timer, handshake_timer_cb, self->handshake_timeout_ms, 0);

    /* Set idle connection timer. */
    if (self->idle_timeout_ms > 0) {
        lfatal_oom(conn->idle_timer = malloc(sizeof(uv_timer_t)));
        uv_timer_init(&_self->loop, conn->idle_timer);
        conn->idle_timer->data = (void*)conn;

        /* Start and stop the timer to set the repeat value without running the timer. */
        uv_timer_start(conn->idle_timer, idle_timer_cb, self->idle_timeout_ms, self->idle_timeout_ms);
        uv_timer_stop(conn->idle_timer);
    }

    ret = uv_udp_recv_start(conn->transport.udp, _output_dnssim_on_uv_alloc, udp_recv_cb);
    if (ret) {
        lwarning("failed to start receiving quic msgs: %s", uv_strerror(ret));
        return ret;
    }

    ret = quic_send(conn, false);
    if (ret) {
        lwarning("failed to send quic connection req: %s", ngtcp2_strerror(ret));
        return ret;
    }

    conn->stats->conn_quic_handshakes++;
    self->stats_sum->conn_quic_handshakes++;

    if (conn->is_0rtt)
        _output_dnssim_conn_early_data(conn);

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
    ngtcp2_pkt_info pi = {0};

    ngtcp2_addr_copy_byte(&ps.path.remote, (const ngtcp2_sockaddr *)remote_sa,
            (remote_sa->sa_family == AF_INET6)
                ? sizeof(struct sockaddr_in6)
                : sizeof(struct sockaddr_in));

    ret = ngtcp2_conn_read_pkt(conn->quic->qconn, &ps.path, &pi,
            (uint8_t*)data, len, quic_timestamp());
    switch (ret) {
    case NGTCP2_ERR_DRAINING:
    case NGTCP2_ERR_CLOSING:
    case NGTCP2_ERR_DROP_CONN:
        _output_dnssim_conn_close(conn);
        return;

    case NGTCP2_ERR_CRYPTO:;
        uint8_t alert = ngtcp2_conn_get_tls_alert(conn->quic->qconn);
        if (alert) {
            lwarning("ngtcp2_conn_read_pkt TLS alert: %s",
                    gnutls_alert_get_name(alert));
        } else {
            lwarning("ngtcp2_conn_read_pkt crypto error without TLS alert");
        }
        ngtcp2_ccerr_set_tls_alert(&conn->quic->ccerr, alert, NULL, 0);
        _output_dnssim_conn_bye(conn);
        return;

    default:
        if (ret < 0) {
            lwarning("failed ngtcp2_conn_read_pkt: %s", ngtcp2_strerror(ret));
            ngtcp2_ccerr_set_liberr(&conn->quic->ccerr, ret, NULL, 0);
            _output_dnssim_conn_bye(conn);
            return;
        } else if (conn->state == _OUTPUT_DNSSIM_CONN_CLOSE_REQUESTED) {
            ldebug("connection closure requested");
            ngtcp2_ccerr_set_application_error(&conn->quic->ccerr, 0, NULL, 0);
            _output_dnssim_conn_bye(conn);
            return;
        }
    }
    mlassert(ret == 0, "ngtcp2_conn_read_pkt returned non-zero");

    ret = quic_send(conn, false);
    if (ret)
        mlwarning("could not send quic data after reception: %s", ngtcp2_strerror(ret));
}

static void _output_dnssim_quic_handle_on_close(uv_handle_t* handle)
{
    _output_dnssim_connection_t *conn = handle->data;
    free(conn->transport.udp);
    conn->transport.udp = NULL;
    conn->transport_type = _OUTPUT_DNSSIM_CONN_TRANSPORT_NULL;
    conn->state = _OUTPUT_DNSSIM_CONN_CLOSED;

    /* Orphan any queries that are still unresolved. */
    _output_dnssim_conn_move_queries_to_pending((_output_dnssim_query_stream_t**)&conn->sent);

    /* Delete connection */
    ngtcp2_conn_del(conn->quic->qconn);
    _output_dnssim_tls_close(conn);
    _output_dnssim_conn_maybe_free(conn);
}

void _output_dnssim_quic_close(_output_dnssim_connection_t* conn)
{
    mlassert(conn, "conn can't be nil");
    mlassert(conn->tls, "conn conn must have tls ctx");
    mlassert(conn->quic, "conn conn must have quic ctx");
    mlassert(conn->client, "conn conn must belong to a client");

    if (conn->transport_type == _OUTPUT_DNSSIM_CONN_TRANSPORT_UDP) {
        if (uv_is_closing((uv_handle_t*)conn->transport.udp))
            return;

        _output_dnssim_quic_sent_payload_t *pl = conn->quic->sent_payloads;
        while (pl) {
            _output_dnssim_quic_sent_payload_t *next = pl->next;
            free(pl);
            pl = next;
        }

        mldebug("stopping UDP reception");
        int ret = uv_udp_connect(conn->transport.udp, NULL); /* disconnect */
        if (ret)
            mlwarning("disconnect failure: %s", uv_strerror(ret));
        uv_udp_recv_stop(conn->transport.udp);
        uv_close((uv_handle_t*)conn->transport.udp, _output_dnssim_quic_handle_on_close);
    } else {
        mlassert(conn->transport_type == _OUTPUT_DNSSIM_CONN_TRANSPORT_NULL,
                "transport type of QUIC must be UDP or NULL");
    }
}

void _output_dnssim_quic_bye(_output_dnssim_connection_t* conn)
{
    mlassert(conn, "conn can't be nil");
    mlassert(conn->tls, "conn conn must have tls ctx");
    mlassert(conn->quic, "conn conn must have quic ctx");
    mlassert(conn->client, "conn conn must belong to a client");
    mlassert(conn->state <= _OUTPUT_DNSSIM_CONN_GRACEFUL_CLOSING, "state is already closing");

    int ret = quic_send(conn, true);
    if (ret)
        mlwarning("error sending bye: %s", ngtcp2_strerror(ret));
}

void _output_dnssim_quic_write_query(_output_dnssim_connection_t* conn, _output_dnssim_query_stream_t* qry)
{
    mlassert(qry, "qry can't be null");
    mlassert(qry->qry.state == _OUTPUT_DNSSIM_QUERY_PENDING_WRITE, "qry must be pending write");
    mlassert(conn, "conn can't be null");
    mlassert(conn->transport_type == _OUTPUT_DNSSIM_CONN_TRANSPORT_UDP, "conn transport type must be UDP");
    mlassert(conn->state == _OUTPUT_DNSSIM_CONN_ACTIVE || conn->state == _OUTPUT_DNSSIM_CONN_EARLY_DATA, "connection state != ACTIVE|EARLY_DATA");
    mlassert(conn->quic, "conn must have quic ctx");
    mlassert(conn->quic->qconn, "conn must have quic connection");
    mlassert(conn->client, "conn must be associated with client");
    mlassert(conn->client->pending, "conn has no pending queries");
    mlassert(conn->client->dnssim, "client must have dnssim");

    output_dnssim_t* self = conn->client->dnssim;

    quic_check_max_streams(conn);
    if (conn->state != _OUTPUT_DNSSIM_CONN_ACTIVE && conn->state != _OUTPUT_DNSSIM_CONN_EARLY_DATA) {
        return;
    }

    int ret;

    core_object_payload_t* content = qry->qry.req->payload;
    _output_dnssim_quic_sent_payload_t *pl;
    mlfatal_oom(pl = malloc(sizeof(*pl) + content->len));

    ret = ngtcp2_conn_open_bidi_stream(conn->quic->qconn, &qry->stream_id, pl);
    if (ret == NGTCP2_ERR_STREAM_ID_BLOCKED) {
        mlfatal("blocked stream id should have been handled above!");
        return;
    } else if (ret) {
        lwarning("failed to open bidi stream: %s", ngtcp2_strerror(ret));
        return;
    }

    pl->next = NULL;
    pl->length = htons(content->len);

    /* Copy query but zero-out the msgid because DoQ mandates it to be zero */
    memcpy(pl->data + 2, content->payload + 2, content->len - 2);
    memset(pl->data, 0, 2);

    ngtcp2_vec vecs[2] = {
        { (uint8_t*)&pl->length, sizeof(pl->length) },
        { (uint8_t*)pl->data, content->len }
    };

    _ll_append(conn->quic->sent_payloads, pl);

    mldebug("stream %" PRIi64 " send id: %04x",
            qry->stream_id, qry->qry.req->dns_q->id);

    lassert(qry->stream_id >= 0, "stream_id not assigned");
    ret = quic_send_data(conn, vecs, 2, qry, false);
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
    quic_check_max_streams(conn);
}

int _output_dnssim_create_query_quic(output_dnssim_t* self, _output_dnssim_request_t* req)
{
    mlassert_self();
    lassert(req, "req is nil");
    lassert(req->client, "request must have a client associated with it");

    _output_dnssim_query_stream_t* qry;

    lfatal_oom(qry = calloc(1, sizeof(*qry)));

    req->dns_q->id = 0; /* DoQ mandates that ID is zero */
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
