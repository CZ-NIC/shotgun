#!/usr/bin/env python3
"""Run a bare AsyncDnsServer instance for manual/ad-hoc testing.

usage: ans.py [port]

Queries for QNAMEs of the form "<instr1>-<instr2>-...-<instrN>.test." are
handled specially: the response is synthesized according to the
"-"-separated instruction words found in the first label. Recognized
instruction words:

- "rcodeN"  - set RCODE to N (default 0/NOERROR if not present)
- "tc1"     - set the TC bit in the response
- "timeout" - send no response at all (simulate a timeout)
- "delayN"  - delay the response by N milliseconds

Example: "rcode3-tc1-delay500.test." sets RCODE=3, TC=1, and delays the
response by 500 ms.
"""
import re

import dns.flags
import dns.rcode

from asyncserver import (
    AsyncDnsServer,
    DnsResponseSend,
    DomainHandler,
    QueryContext,
    ResponseDrop,
)


class QnameInstructionHandler(DomainHandler):
    """
    Response handler controlled by encoding instructions in the QNAME.
    """

    domains = ["test."]

    _RCODE_RE = re.compile(r"^rcode(\d+)$")
    _DELAY_RE = re.compile(r"^delay(\d+)$")

    async def get_responses(self, qctx: QueryContext):
        instructions = qctx.qname.relativize(self.matched_domain).labels[0].decode(
            "ascii"
        )

        rcode = dns.rcode.NOERROR
        tc = False
        timeout = False
        delay_ms = 0

        for token in instructions.split("-"):
            if token == "tc1":
                tc = True
            elif token == "timeout":
                timeout = True
            elif match := self._RCODE_RE.match(token):
                rcode = int(match.group(1))
            elif match := self._DELAY_RE.match(token):
                delay_ms = int(match.group(1))
            else:
                raise ValueError(f"Unrecognized QNAME instruction token: {token}")

        if timeout:
            yield ResponseDrop()
            return

        qctx.prepare_new_response(with_zone_data=False)
        qctx.response.set_rcode(rcode)
        if tc:
            qctx.response.flags |= dns.flags.TC

        yield DnsResponseSend(qctx.response, delay=delay_ms / 1000.0)


if __name__ == "__main__":
    server = AsyncDnsServer()
    server.install_response_handler(QnameInstructionHandler())
    server.run()
