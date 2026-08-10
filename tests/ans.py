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

import contextlib
import os
import re
import socket
import subprocess
import sys
import time

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
    """
    Print the offending query and kill the process. Any query ans.py cannot
    make sense of signals a bug in the test fixtures that generated it, so
    fail loudly and immediately rather than sending back some default
    response that would silently mask the bug.
    """
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
                rcode = int(match.group(1))
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


def _wait_for_udp_port(port: int, timeout: float) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as s:
            try:
                s.connect(("::1", port))
                s.send(b"")
                return
            except OSError:
                time.sleep(0.1)
    raise TimeoutError(f"ans.py did not start listening on port {port}")


@contextlib.contextmanager
def run_in_subprocess(timeout: float = 5.0):
    """
    Launch this module as a subprocess on a free port and wait until it is
    accepting UDP datagrams. Yields the port it is listening on.

    AsyncServer.run() installs signal handlers via loop.add_signal_handler(),
    which only works on the main thread of the process.
    """
    port = _free_port()
    proc = subprocess.Popen([sys.executable, __file__, str(port)])
    try:
        _wait_for_udp_port(port, timeout)
        yield port
    finally:
        proc.terminate()
        proc.wait(timeout=timeout)


if __name__ == "__main__":
    make_server().run()
