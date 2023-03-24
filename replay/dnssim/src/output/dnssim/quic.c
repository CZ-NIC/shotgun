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

static core_log_t _log = LOG_T_INIT("output.dnssim");

static void rand_cb(uint8_t *dest, size_t destlen, const ngtcp2_rand_ctx *rand_ctx)
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

static int stream_close_cb(ngtcp2_conn *qconn, uint32_t flags,
                           int64_t stream_id, uint64_t app_error_code,
                           void *user_data, void *stream_user_data)
{
    _output_dnssim_connection_t* conn = user_data;
    if (stream_id == conn->quic->stream_id)
        conn->quic->stream_id = -1;
    return 0;
}

static void alloc_cb(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf)
{
    void *data;
    mlfatal_oom(data = malloc(suggested_size));
    buf->base = data;
    buf->len = suggested_size;
}

static void recv_cb(uv_udp_t* udp, ssize_t nread, const uv_buf_t* buf,
                    const struct sockaddr* addr, unsigned flags)
{
    _output_dnssim_connection_t* conn = udp->data;
    _output_dnssim_quic_process_input_data(conn, nread, buf->base);
    free(buf->base);
}

static void send_cb(uv_udp_send_t* req, int status)
{
    if (status)
        mlwarning("failed to send udp packet: %s", uv_strerror(status));
    free(req->data);
    free(req);
}

static ngtcp2_conn* get_conn_cb(ngtcp2_crypto_conn_ref* qconn_ref)
{
    return ((_output_dnssim_connection_t*)qconn_ref->user_data)->quic->qconn;
}


static const ngtcp2_callbacks quic_client_callbacks = {
    .client_initial = ngtcp2_crypto_client_initial_cb,
    .recv_crypto_data = ngtcp2_crypto_recv_crypto_data_cb,
    .encrypt = ngtcp2_crypto_encrypt_cb,
    .decrypt = ngtcp2_crypto_decrypt_cb,
    .hp_mask = ngtcp2_crypto_hp_mask_cb,
    .recv_retry = ngtcp2_crypto_recv_retry_cb,
    .rand = rand_cb,
    .get_new_connection_id = get_new_connection_id_cb,
    .update_key = ngtcp2_crypto_update_key_cb,
    .delete_crypto_aead_ctx = ngtcp2_crypto_delete_crypto_aead_ctx_cb,
    .delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb,
    .get_path_challenge_data = ngtcp2_crypto_get_path_challenge_data_cb,
    .version_negotiation = ngtcp2_crypto_version_negotiation_cb,
};

static int quic_send_data(_output_dnssim_connection_t *conn, uint32_t flags,
                          ngtcp2_vec *vecs, ngtcp2_ssize vecs_len,
                          int64_t stream_id)
{
    output_dnssim_t* self = conn->client->dnssim;
    const size_t destlen = ngtcp2_conn_get_max_tx_udp_payload_size(conn->quic->qconn);
    uint8_t *dest_buf;
    lfatal_oom(dest_buf = malloc(destlen));

    ngtcp2_ssize send_datalen = 0;
    ngtcp2_ssize write_ret = ngtcp2_conn_writev_stream(conn->quic->qconn,
            (ngtcp2_path *)ngtcp2_conn_get_path(conn->quic->qconn), NULL,
            dest_buf, destlen, &send_datalen, flags, stream_id, vecs, vecs_len,
            uv_hrtime());
    ngtcp2_conn_update_pkt_tx_time(conn->quic->qconn, uv_hrtime());
    if (write_ret < 0) {
        mlwarning("failed ngtcp2_conn_writev_stream: %s", ngtcp2_strerror(write_ret));
        _output_dnssim_conn_close(conn);
        free(dest_buf);
        return -1;
    } else if (conn->state == _OUTPUT_DNSSIM_CONN_CLOSE_REQUESTED) {
        mlwarning("close requested");
        _output_dnssim_conn_close(conn);
        free(dest_buf);
        return -1;
    } else if (write_ret == 0) {
        /* TODO: (ngtcp2 docs) This function returns 0 if it cannot write any
         *       frame because buffer is too small, or packet is congestion
         *       limited. Application should keep reading and wait for
         *       congestion window to grow. */
        mlwarning("buf2smol");
        free(dest_buf);
        return 0;
    }

    uv_udp_send_t *req;
    lfatal_oom(req = malloc(sizeof(*req)));
    req->data = dest_buf;

    uv_buf_t uv_buf = { (char*)dest_buf, write_ret };
    int send_ret = uv_udp_send(req, conn->transport.udp, &uv_buf, 1,
            conn->quic->path.remote.addr, send_cb);

    return 0;
}

static int quic_send(_output_dnssim_connection_t *conn, uint32_t flags, int64_t stream_id)
{
    return quic_send_data(conn, flags, NULL, 0, stream_id);
}


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
    const gnutls_datum_t protos[] = {
        { (unsigned char*)"doq", 3 }
    };
    ret = gnutls_alpn_set_protocols(conn->tls->session, protos, 1, 0);
    if (ret < 0) {
        lwarning("failed to set ALPN protocol: %s", gnutls_strerror(ret));
        return ret;
    }

    lfatal_oom(conn->quic = calloc(1, sizeof(_output_dnssim_quic_ctx_t)));
    conn->quic->max_concurrent_streams = OUTPUT_DNSSIM_QUIC_INITIAL_MAX_CONCURRENT_STREAMS;
    conn->quic->stream_id = -1;
    ret = quic_generate_secret(conn->quic->secret, sizeof(conn->quic->secret));
    if (ret) {
        lwarning("failed to generate quic secret: %s", gnutls_strerror(ret));
        return ret;
    }

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
    ngtcp2_transport_params params;

    ngtcp2_settings_default(&settings);
    settings.initial_ts = uv_hrtime();
    ngtcp2_transport_params_default(&params);

    /* CIDs */
    ngtcp2_cid dcid;
    ngtcp2_cid scid;

    dcid.datalen = 18;
    _output_dnssim_rand(dcid.data, dcid.datalen);
    scid.datalen = NGTCP2_MAX_CIDLEN;
    _output_dnssim_rand(scid.data, scid.datalen);

    /* Path */
    memset(&conn->quic->sa_local, 0, sizeof(conn->quic->sa_local));
    memcpy(&conn->quic->sa_remote, &_self->target, sizeof(conn->quic->sa_remote));

    conn->quic->path = (ngtcp2_path){
        .local = {
            .addrlen = sizeof(conn->quic->sa_local),
            .addr = (ngtcp2_sockaddr*)&conn->quic->sa_local
        },
        .remote = {
            .addrlen = sizeof(conn->quic->sa_remote),
            .addr = (ngtcp2_sockaddr*)&conn->quic->sa_remote
        }
    };

    /* Client */
    ret = ngtcp2_conn_client_new(&conn->quic->qconn, &dcid, &scid,
            &conn->quic->path, NGTCP2_PROTO_VER_V1, &quic_client_callbacks,
            &settings, &params, NULL, conn);
    if (ret < 0) {
        mlwarning("failed to create ngtcp2 conn");
        return ret;
    }

    ret = ngtcp2_crypto_gnutls_configure_client_session(conn->tls->session);
    if (ret < 0) {
        mlwarning("failed to configure ngtcp2 crypto");
        ngtcp2_conn_del(conn->quic->qconn);
        return ret;
    }
    conn->quic->qconn_ref = (ngtcp2_crypto_conn_ref){
        .get_conn = get_conn_cb,
        .user_data = conn
    };
    gnutls_session_set_ptr(conn->tls->session, &conn->quic->qconn_ref);
    ngtcp2_conn_set_tls_native_handle(conn->quic->qconn, conn->tls->session);

    ret = uv_udp_recv_start(conn->transport.udp, alloc_cb, recv_cb);
    if (ret) {
        mlwarning("failed to start receiving quic msgs: %s", uv_strerror(ret));
        return ret;
    }

    ret = quic_send(conn, NGTCP2_WRITE_STREAM_FLAG_NONE, -1);
    if (ret) {
        mlwarning("failed to send quic connection req");
        return ret;
    }

    conn->stats->conn_quic_handshakes++;
    self->stats_sum->conn_quic_handshakes++;
    conn->state = _OUTPUT_DNSSIM_CONN_TRANSPORT_HANDSHAKE;

    return 0;
}

void _output_dnssim_quic_process_input_data(_output_dnssim_connection_t* conn,
                                            size_t len, const char* data)
{
    mlassert(conn, "conn is nil");
    mlassert(conn->transport_type == _OUTPUT_DNSSIM_CONN_TRANSPORT_UDP, "conn transport type must be UDP");
    mlassert(conn->quic, "conn must have quic ctx");
    mlassert(conn->quic->qconn, "conn must have quic connection");

    ssize_t ret = 0;
    conn->prevent_close = true;
    ret = ngtcp2_conn_read_pkt(conn->quic->qconn, &conn->quic->path,
            NULL, (uint8_t*)data, len, uv_hrtime());
    conn->prevent_close = false;
    if (ret < 0) {
        mlwarning("failed ngtcp2_conn_read_pkt: %s", ngtcp2_strerror(ret));
        _output_dnssim_conn_close(conn);
        return;
    } else if (conn->state == _OUTPUT_DNSSIM_CONN_CLOSE_REQUESTED) {
        _output_dnssim_conn_close(conn);
        return;
    }
    mlassert(ret == 0, "ngtcp2_conn_read_pkt returned non-zero");

    quic_send(conn, NGTCP2_WRITE_STREAM_FLAG_FIN, conn->quic->stream_id);
}

void _output_dnssim_quic_on_close(uv_handle_t* handle)
{
    _output_dnssim_connection_t *conn = handle->data;
    free(conn->transport.udp);
    conn->transport.udp = NULL;
    conn->transport_type = _OUTPUT_DNSSIM_CONN_TRANSPORT_NULL;
}

void _output_dnssim_quic_close(_output_dnssim_connection_t* conn)
{
    mlassert(conn, "conn can't be nil");
    mlassert(conn->tls, "conn conn must have tls ctx");
    mlassert(conn->quic, "conn conn must have quic ctx");
    mlassert(conn->client, "conn conn must belong to a client");

    ngtcp2_conn_del(conn->quic->qconn);
    _output_dnssim_tls_close(conn);

    if (conn->transport_type == _OUTPUT_DNSSIM_CONN_TRANSPORT_UDP) {
        uv_udp_recv_stop(conn->transport.udp);
        uv_close((uv_handle_t*)conn->transport.udp, _output_dnssim_quic_on_close);
    }
}

void _output_dnssim_quic_write_query(_output_dnssim_connection_t* conn, _output_dnssim_query_tcp_t* qry)
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
    core_object_payload_t* content = qry->qry.req->payload;
    uint16_t contentlen = htons(content->len);
    ngtcp2_vec vecs[2] = {
        { (uint8_t*)&contentlen, sizeof(contentlen) },
        { (uint8_t*)content->payload, content->len }
    };

    if (conn->quic->stream_id == -1) {
        int ret = ngtcp2_conn_open_bidi_stream(conn->quic->qconn, &conn->quic->stream_id, NULL);
        if (ret) {
            lwarning("failed to open bidi stream: %s", ngtcp2_strerror(ret));
            return;
        }

        mlassert(conn->quic->stream_id >= 0, "stream_id not assigned");
        quic_send_data(conn, NGTCP2_WRITE_STREAM_FLAG_NONE, vecs, 2, conn->quic->stream_id);
    } else {
        lwarning("could not write query, there is still an open stream (and we don't yet support multiple at once)");
    }
}

int  _output_dnssim_create_query_quic(output_dnssim_t* self, _output_dnssim_request_t* req)
{
    mlassert_self();
    lassert(req, "req is nil");
    lassert(req->client, "request must have a client associated with it");

    _output_dnssim_query_quic_t* qry;

    lfatal_oom(qry = calloc(1, sizeof(*qry)));

    qry->qry.transport = OUTPUT_DNSSIM_TRANSPORT_QUIC;
    qry->qry.req = req;
    qry->qry.state = _OUTPUT_DNSSIM_QUERY_PENDING_WRITE;
    req->qry = &qry->qry;
    _ll_append(req->client->pending, &qry->qry);

    return _output_dnssim_handle_pending_queries(req->client);
}

void _output_dnssim_close_query_quic(_output_dnssim_query_quic_t* qry)
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

#endif
