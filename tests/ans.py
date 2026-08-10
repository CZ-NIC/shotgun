#!/usr/bin/env python3
"""DNS test server controlled by QNAME instructions.

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

from collections.abc import Iterator
import contextlib
import os
import re
import socket
import subprocess
import sys
import time

import dns.exception
import dns.message
import dns.query
import dns.flags
import dns.rcode

from asyncserver import (
    AsyncDnsServer,
    DnsResponseSend,
    DomainHandler,
    QueryContext,
    ResponseDrop,
    ResponseHandler,
)


def _exit_on_unrecognized_query(qctx: QueryContext) -> None:
    """Print query and kill process; an unrecognized query means a fixture bug."""
    print(f"Unrecognized query, exiting:\n{qctx.query}", file=sys.stderr)
    os._exit(1)


class QnameInstructionHandler(DomainHandler):
    """
    Response handler controlled by encoding instructions in the QNAME.
    """

    domains = ["test."]

    _RCODE_RE = re.compile(r"^rcode(\d+)$")
    _DELAY_RE = re.compile(r"^delay(\d+)$")

    async def get_responses(self, qctx: QueryContext):
        instructions = (
            qctx.qname.relativize(self.matched_domain).labels[0].decode("ascii")
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
                rcode = dns.rcode.Rcode(int(match.group(1)))
            elif match := self._DELAY_RE.match(token):
                delay_ms = int(match.group(1))
            else:
                _exit_on_unrecognized_query(qctx)

        if timeout:
            yield ResponseDrop()
            return

        qctx.prepare_new_response(with_zone_data=False)
        qctx.response.set_rcode(rcode)
        if tc:
            qctx.response.flags |= dns.flags.TC

        yield DnsResponseSend(qctx.response, delay=delay_ms / 1000.0)


class UnrecognizedQueryHandler(ResponseHandler):
    """
    Catch-all fallback for any query not matched by QnameInstructionHandler
    (i.e. not under the "test." domain).
    """

    async def get_responses(self, qctx: QueryContext):
        _exit_on_unrecognized_query(qctx)
        yield ResponseDrop()  # unreachable; keeps this an async generator


def make_server() -> AsyncDnsServer:
    server = AsyncDnsServer()
    server.install_response_handler(QnameInstructionHandler())
    server.install_response_handler(UnrecognizedQueryHandler())
    return server


def _free_port() -> int:
    with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as s:
        s.bind(("::1", 0))
        return s.getsockname()[1]


def _wait_for_dns_answer_over_udp(port: int, timeout: float) -> None:
    query = dns.message.make_query("rcode0.test.", "A")
    deadline = time.monotonic() + timeout
    while (remaining := deadline - time.monotonic()) > 0:
        try:
            dns.query.udp(query, "::1", port=port, timeout=min(0.1, remaining))
            return
        except (OSError, dns.exception.Timeout):
            time.sleep(min(0.1, max(0, deadline - time.monotonic())))
    raise TimeoutError(f"ans.py did not start listening on port {port}")


@contextlib.contextmanager
def run_in_subprocess(timeout: float = 5.0) -> Iterator[int]:
    """Launch the server on a free port and yield that port."""
    port = _free_port()
    proc = subprocess.Popen([sys.executable, __file__, str(port)])
    try:
        _wait_for_dns_answer_over_udp(port, timeout)
        yield port
    finally:
        proc.terminate()
        proc.wait(timeout=timeout)


if __name__ == "__main__":
    make_server().run()
