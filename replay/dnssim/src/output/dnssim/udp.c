/*  Copyright (C) 2019-2021 CZ.NIC, z.s.p.o. <knot-resolver@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "output/dnssim.h"
#include "output/dnssim/internal.h"
#include "output/dnssim/ll.h"

static core_log_t _log = LOG_T_INIT("output.dnssim");

static int _process_udp_response(uv_udp_t* handle, ssize_t nread, const uv_buf_t* buf)
{
    _output_dnssim_query_udp_t* qry = (_output_dnssim_query_udp_t*)handle->data;
    _output_dnssim_request_t*   req;
    core_object_payload_t       payload = CORE_OBJECT_PAYLOAD_INIT(NULL);
    core_object_dns_t           dns_a   = CORE_OBJECT_DNS_INIT(&payload);
    mlassert(qry, "qry is nil");
    mlassert(qry->qry.req, "query must be part of a request");
    req = qry->qry.req;

    payload.payload = (uint8_t*)buf->base;
    payload.len     = nread;

    dns_a.obj_prev = (core_object_t*)&payload;
    int ret        = core_object_dns_parse_header(&dns_a);
    if (ret != 0) {
        mldebug("udp response malformed");
        return _ERR_MALFORMED;
    }
    if (dns_a.id != req->dns_q->id) {
        mldebug("udp response msgid mismatch %x(q) != %x(a)", req->dns_q->id, dns_a.id);
        return _ERR_MSGID;
    }
    if (dns_a.tc == 1) {
        mldebug("udp response has TC=1");
        return _ERR_TC;
    }
    ret = _output_dnssim_answers_request(req, &dns_a);
    if (ret != 0) {
        mlwarning("udp reponse question mismatch");
        return _ERR_QUESTION;
    }

    _output_dnssim_request_answered(req, &dns_a, false);
    return 0;
}

static void _on_udp_query_recv(uv_udp_t* handle, ssize_t nread, const uv_buf_t* buf, const struct sockaddr* addr, unsigned flags)
{
    if (nread > 0) {
        mldebug("udp recv: %d", nread);

        // TODO handle TC=1
        _process_udp_response(handle, nread, buf);
    }

    if (buf->base != NULL) {
        free(buf->base);
    }
}

static void _on_query_udp_closed(uv_handle_t* handle)
{
    _output_dnssim_query_udp_t* qry = (_output_dnssim_query_udp_t*)handle->data;
    _output_dnssim_request_t*   req;
    mlassert(qry, "qry is nil");
    mlassert(qry->qry.req, "query must be part of a request");
    req = qry->qry.req;

    free(qry->handle);

    _ll_remove(req->qry, &qry->qry);
    free(qry);

    if (req->qry == NULL)
        _output_dnssim_maybe_free_request(req);
}

void _output_dnssim_close_query_udp(_output_dnssim_query_udp_t* qry)
{
    int ret;
    mlassert(qry, "qry is nil");

    ret = uv_udp_recv_stop(qry->handle);
    if (ret < 0) {
        mldebug("failed uv_udp_recv_stop(): %s", uv_strerror(ret));
    }

    uv_close((uv_handle_t*)qry->handle, _on_query_udp_closed);
}

int _output_dnssim_create_query_udp(output_dnssim_t* self, _output_dnssim_request_t* req)
{
    int                         ret;
    _output_dnssim_query_udp_t* qry;
    core_object_payload_t*      payload;
    mlassert_self();
    lassert(req, "req is nil");
    payload = (core_object_payload_t*)req->dns_q->obj_prev;

    lfatal_oom(qry = calloc(1, sizeof(_output_dnssim_query_udp_t)));
    lfatal_oom(qry->handle = malloc(sizeof(uv_udp_t)));

    qry->qry.transport = OUTPUT_DNSSIM_TRANSPORT_UDP;
    qry->qry.req       = req;
    qry->buf           = uv_buf_init((char*)payload->payload, payload->len);
    qry->handle->data  = (void*)qry;
    ret                = uv_udp_init(&_self->loop, qry->handle);
    if (ret < 0) {
        lwarning("failed to init uv_udp_t");
        goto failure;
    }
    _ll_append(req->qry, &qry->qry);

    ret = _output_dnssim_bind_before_connect(self, (uv_handle_t*)qry->handle);
    if (ret < 0)
        return ret;

    ret = uv_udp_try_send(qry->handle, &qry->buf, 1, (struct sockaddr*)&_self->target);
    if (ret < 0) {
        lwarning("failed to send udp packet: %s", uv_strerror(ret));
        return ret;
    }

    // listen for reply
    ret = uv_udp_recv_start(qry->handle, _output_dnssim_on_uv_alloc, _on_udp_query_recv);
    if (ret < 0) {
        lwarning("failed uv_udp_recv_start(): %s", uv_strerror(ret));
        return ret;
    }

    return 0;
failure:
    free(qry->handle);
    free(qry);
    return ret;
}
