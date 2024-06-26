/*  Copyright (C) 2019-2021 CZ.NIC, z.s.p.o. <knot-resolver@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "output/dnssim.h"
#include "output/dnssim/internal.h"
#include "output/dnssim/ll.h"

#include <string.h>

#define MAX_LABELS 127

static core_log_t _log = LOG_T_INIT("output.dnssim");

static void _on_request_timeout(uv_timer_t* handle)
{
    _output_dnssim_close_request(handle->data);
}

static ssize_t parse_qsection(core_object_dns_t* dns)
{
    core_object_dns_q_t            q;
    static core_object_dns_label_t labels[MAX_LABELS];
    const uint8_t*                 start;
    int                            i;
    int                            ret;

    if (!dns || !dns->have_qdcount)
        return -1;

    start = dns->at;

    for (i = 0; i < dns->qdcount; i++) {
        ret = core_object_dns_parse_q(dns, &q, labels, MAX_LABELS);
        if (ret < 0)
            return -1;
    }

    return (dns->at - start);
}

int _output_dnssim_answers_request(_output_dnssim_request_t* req, core_object_dns_t* response)
{
    const uint8_t* question;
    ssize_t        len;

    if (!response->have_id || !response->have_qdcount)
        return _ERR_MALFORMED;

    if (req->dns_q->id != response->id)
        return _ERR_MSGID;

    if (req->dns_q->qdcount != response->qdcount)
        return _ERR_QUESTION;

    question = response->at;
    len      = parse_qsection(response);

    if (req->question_len != len)
        return _ERR_QUESTION;

    if (memcmp(req->question, question, len) != 0)
        return _ERR_QUESTION;

    return 0;
}

void _output_dnssim_create_request(output_dnssim_t* self, _output_dnssim_client_t* client, core_object_payload_t* payload)
{
    int                       ret;
    _output_dnssim_request_t* req;
    mlassert_self();
    lassert(client, "client is nil");
    lassert(payload, "payload is nil");

    lfatal_oom(req = calloc(1, sizeof(_output_dnssim_request_t)));
    req->dnssim          = self;
    req->client          = client;
    req->payload         = payload;
    req->dns_q           = core_object_dns_new();
    req->dns_q->obj_prev = (core_object_t*)req->payload;
    req->dnssim->ongoing++;
    req->state = _OUTPUT_DNSSIM_REQ_ONGOING;
    req->stats = self->stats_current;

    ret = core_object_dns_parse_header(req->dns_q);
    if (ret != 0) {
        ldebug("discarded malformed dns query: couldn't parse header");
        goto failure;
    }

    req->question     = req->dns_q->at;
    req->question_len = parse_qsection(req->dns_q);
    if (req->question_len < 0) {
        ldebug("discarded malformed dns query: invalid question");
        goto failure;
    }

    req->dnssim->stats_sum->requests++;
    req->stats->requests++;

    switch (_self->transport) {
    case OUTPUT_DNSSIM_TRANSPORT_UDP_ONLY:
    case OUTPUT_DNSSIM_TRANSPORT_UDP:
        ret = _output_dnssim_create_query_udp(self, req);
        break;
    case OUTPUT_DNSSIM_TRANSPORT_TCP:
        ret = _output_dnssim_create_query_tcp(self, req);
        break;
#if DNSSIM_HAS_GNUTLS
    case OUTPUT_DNSSIM_TRANSPORT_TLS:
        ret = _output_dnssim_create_query_tls(self, req);
        break;
    case OUTPUT_DNSSIM_TRANSPORT_HTTPS2:
        ret = _output_dnssim_create_query_https2(self, req);
        break;
    case OUTPUT_DNSSIM_TRANSPORT_QUIC:
        ret = _output_dnssim_create_query_quic(self, req);
        break;
#else
    case OUTPUT_DNSSIM_TRANSPORT_TLS:
    case OUTPUT_DNSSIM_TRANSPORT_HTTPS2:
    case OUTPUT_DNSSIM_TRANSPORT_QUIC:
        lfatal(DNSSIM_MIN_GNUTLS_ERRORMSG);
        break;
#endif
    default:
        lfatal("unsupported dnssim transport");
        break;
    }
    if (ret < 0) {
        goto failure;
    }

    req->created_at = uv_now(&_self->loop);
    req->ended_at   = req->created_at + self->timeout_ms;
    lfatal_oom(req->timer = malloc(sizeof(uv_timer_t)));
    uv_timer_init(&_self->loop, req->timer);
    req->timer->data = req;
    uv_timer_start(req->timer, _on_request_timeout, self->timeout_ms, 0);

    return;
failure:
    self->discarded++;
    _output_dnssim_close_request(req);
    return;
}

static void _on_request_timer_closed(uv_handle_t* handle)
{
    _output_dnssim_request_t* req = (_output_dnssim_request_t*)handle->data;
    mlassert(req, "req is nil");
    free(handle);
    req->timer = NULL;
    _output_dnssim_maybe_free_request(req);
}

static void _close_query(_output_dnssim_query_t* qry)
{
    mlassert(qry, "qry is nil");

    switch (qry->transport) {
    case OUTPUT_DNSSIM_TRANSPORT_UDP:
        _output_dnssim_close_query_udp((_output_dnssim_query_udp_t*)qry);
        break;
    case OUTPUT_DNSSIM_TRANSPORT_TCP:
        _output_dnssim_close_query_tcp((_output_dnssim_query_stream_t*)qry);
        break;
#if DNSSIM_HAS_GNUTLS
    case OUTPUT_DNSSIM_TRANSPORT_TLS:
        _output_dnssim_close_query_tls((_output_dnssim_query_stream_t*)qry);
        break;
    case OUTPUT_DNSSIM_TRANSPORT_HTTPS2:
        _output_dnssim_close_query_https2((_output_dnssim_query_stream_t*)qry);
        break;
    case OUTPUT_DNSSIM_TRANSPORT_QUIC:
        _output_dnssim_close_query_quic((_output_dnssim_query_stream_t*)qry);
        break;
#else
    case OUTPUT_DNSSIM_TRANSPORT_TLS:
    case OUTPUT_DNSSIM_TRANSPORT_HTTPS2:
    case OUTPUT_DNSSIM_TRANSPORT_QUIC:
        mlfatal(DNSSIM_MIN_GNUTLS_ERRORMSG);
        break;
#endif
    default:
        mlfatal("invalid query transport");
        break;
    }
}

void _output_dnssim_close_request(_output_dnssim_request_t* req)
{
    if (req == NULL || req->state == _OUTPUT_DNSSIM_REQ_CLOSING)
        return;
    mlassert(req->state == _OUTPUT_DNSSIM_REQ_ONGOING, "request to be closed must be ongoing");
    req->state = _OUTPUT_DNSSIM_REQ_CLOSING;
    req->dnssim->ongoing--;

    /* Calculate latency. When the request was answered in time, this is set to
     * the actual time it took to answer it. If the request timed-out or failed
     * prematurely (e.g. because of stream reset), the latency is set to the
     * maximum timeout value to indicate that it was lost. */
    uint64_t latency;
    if (req->answered) {
        req->ended_at = uv_now(&((_output_dnssim_t*)req->dnssim)->loop);
        latency       = req->ended_at - req->created_at;
    }
    if (!req->answered || latency > req->dnssim->timeout_ms) {
        req->ended_at = req->created_at + req->dnssim->timeout_ms;
        latency       = req->dnssim->timeout_ms;
    }
    req->stats->latency[latency]++;
    req->dnssim->stats_sum->latency[latency]++;

    if (req->timer != NULL) {
        uv_timer_stop(req->timer);
        uv_close((uv_handle_t*)req->timer, _on_request_timer_closed);
    }

    /* Finish any queries in flight. */
    _output_dnssim_query_t* qry = req->qry;
    if (qry != NULL)
        _close_query(qry);

    _output_dnssim_maybe_free_request(req);
}

/* Bind before connect to be able to send from different source IPs. */
int _output_dnssim_bind_before_connect(output_dnssim_t* self, uv_handle_t* handle)
{
    mlassert_self();
    lassert(handle, "handle is nil");

    if (_self->source != NULL) {
        struct sockaddr* addr = (struct sockaddr*)&_self->source->addr;
        struct sockaddr* dest = (struct sockaddr*)&_self->target;
        int              ret  = -1;
        if (addr->sa_family != dest->sa_family) {
            lfatal("failed to bind: source/desitnation address family mismatch");
        }
        switch (handle->type) {
        case UV_UDP:
            ret = uv_udp_bind((uv_udp_t*)handle, addr, 0);
            break;
        case UV_TCP:
            ret = uv_tcp_bind((uv_tcp_t*)handle, addr, 0);
            break;
        default:
            lfatal("failed to bind: unsupported handle type");
            break;
        }
        if (ret < 0) {
            /* This typically happens when we run out of file descriptors.
             * Quit to prevent skewed results or unexpected behaviour. */
            lfatal("failed to bind: %s", uv_strerror(ret));
            return ret;
        }
        _self->source = _self->source->next;
    }
    return 0;
}

void _output_dnssim_maybe_free_request(_output_dnssim_request_t* req)
{
    mlassert(req, "req is nil");

    if (req->qry == NULL && req->timer == NULL) {
        if (req->dnssim->free_after_use) {
            core_object_payload_free(req->payload);
        }
        core_object_dns_free(req->dns_q);
        free(req);
    }
}

void _output_dnssim_request_answered(_output_dnssim_request_t* req, core_object_dns_t* msg, bool is_early)
{
    mlassert(req, "req is nil");
    mlassert(msg, "msg is nil");

    req->answered = true;
    req->dnssim->stats_sum->answers++;
    req->stats->answers++;
    if (is_early) {
        req->dnssim->stats_sum->quic_0rtt_answered++;
        req->stats->quic_0rtt_answered++;
    }

    switch (msg->rcode) {
    case CORE_OBJECT_DNS_RCODE_NOERROR:
        req->dnssim->stats_sum->rcode_noerror++;
        req->stats->rcode_noerror++;
        break;
    case CORE_OBJECT_DNS_RCODE_FORMERR:
        req->dnssim->stats_sum->rcode_formerr++;
        req->stats->rcode_formerr++;
        break;
    case CORE_OBJECT_DNS_RCODE_SERVFAIL:
        req->dnssim->stats_sum->rcode_servfail++;
        req->stats->rcode_servfail++;
        break;
    case CORE_OBJECT_DNS_RCODE_NXDOMAIN:
        req->dnssim->stats_sum->rcode_nxdomain++;
        req->stats->rcode_nxdomain++;
        break;
    case CORE_OBJECT_DNS_RCODE_NOTIMP:
        req->dnssim->stats_sum->rcode_notimp++;
        req->stats->rcode_notimp++;
        break;
    case CORE_OBJECT_DNS_RCODE_REFUSED:
        req->dnssim->stats_sum->rcode_refused++;
        req->stats->rcode_refused++;
        break;
    case CORE_OBJECT_DNS_RCODE_YXDOMAIN:
        req->dnssim->stats_sum->rcode_yxdomain++;
        req->stats->rcode_yxdomain++;
        break;
    case CORE_OBJECT_DNS_RCODE_YXRRSET:
        req->dnssim->stats_sum->rcode_yxrrset++;
        req->stats->rcode_yxrrset++;
        break;
    case CORE_OBJECT_DNS_RCODE_NXRRSET:
        req->dnssim->stats_sum->rcode_nxrrset++;
        req->stats->rcode_nxrrset++;
        break;
    case CORE_OBJECT_DNS_RCODE_NOTAUTH:
        req->dnssim->stats_sum->rcode_notauth++;
        req->stats->rcode_notauth++;
        break;
    case CORE_OBJECT_DNS_RCODE_NOTZONE:
        req->dnssim->stats_sum->rcode_notzone++;
        req->stats->rcode_notzone++;
        break;
    case CORE_OBJECT_DNS_RCODE_BADVERS:
        req->dnssim->stats_sum->rcode_badvers++;
        req->stats->rcode_badvers++;
        break;
    case CORE_OBJECT_DNS_RCODE_BADKEY:
        req->dnssim->stats_sum->rcode_badkey++;
        req->stats->rcode_badkey++;
        break;
    case CORE_OBJECT_DNS_RCODE_BADTIME:
        req->dnssim->stats_sum->rcode_badtime++;
        req->stats->rcode_badtime++;
        break;
    case CORE_OBJECT_DNS_RCODE_BADMODE:
        req->dnssim->stats_sum->rcode_badmode++;
        req->stats->rcode_badmode++;
        break;
    case CORE_OBJECT_DNS_RCODE_BADNAME:
        req->dnssim->stats_sum->rcode_badname++;
        req->stats->rcode_badname++;
        break;
    case CORE_OBJECT_DNS_RCODE_BADALG:
        req->dnssim->stats_sum->rcode_badalg++;
        req->stats->rcode_badalg++;
        break;
    case CORE_OBJECT_DNS_RCODE_BADTRUNC:
        req->dnssim->stats_sum->rcode_badtrunc++;
        req->stats->rcode_badtrunc++;
        break;
    case CORE_OBJECT_DNS_RCODE_BADCOOKIE:
        req->dnssim->stats_sum->rcode_badcookie++;
        req->stats->rcode_badcookie++;
        break;
    default:
        req->dnssim->stats_sum->rcode_other++;
        req->stats->rcode_other++;
    }

    _output_dnssim_close_request(req);
}

void _output_dnssim_on_uv_alloc(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf)
{
    mlfatal_oom(buf->base = malloc(suggested_size));
    buf->len = suggested_size;
}

int _output_dnssim_append_to_query_buf(_output_dnssim_query_stream_t* qry, const uint8_t* data, size_t datalen)
{
    if (datalen == 0)
        return 0;
    mlassert(data, "non-zero datalen with NULL data");

    mlassert(qry->recv_buf_len || !qry->recv_buf,
            "recv_buf was assigned while recv_buf_len was zero");
    size_t total_len = qry->recv_buf_len + datalen;
    if (total_len > MAX_DNSMSG_SIZE) {
        mlwarning("response exceeded maximum size of dns message");
        return -1;
    }
    if (qry->recv_buf_len < total_len)
        mlfatal_oom(qry->recv_buf = realloc(qry->recv_buf, total_len));

    memcpy(&qry->recv_buf[qry->recv_buf_len], data, datalen);
    qry->recv_buf_len = total_len;

    return 0;
}

#if DNSSIM_HAS_GNUTLS
void _output_dnssim_rand(void *data, size_t len)
{
    mlassert(data, "data must not be nil");

    int ret = gnutls_rnd(GNUTLS_RND_RANDOM, data, len);
    mlassert(!ret, "random number generation failed: %d %s", ret, gnutls_strerror(ret));
}
#endif
