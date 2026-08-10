#!/usr/bin/env python3
"""Run a bare AsyncDnsServer instance for manual/ad-hoc testing.

usage: ans.py [port]

Queries for QNAMEs of the form "<instr1>-<instr2>-...-<instrN>.test." are
handled specially: the response is synthesized according to the
"-"-separated instruction words found in the first label. Recognized
instruction words:

- "rcodeN"        - set RCODE to N (default 0/NOERROR if not present)
- "tc1"           - set the TC bit in the response
- "timeout"       - send no response at all (simulate a timeout)
- "delayN"        - delay the response by N milliseconds
- "idmismatch"    - send back a random message ID that doesn't match the query
- "qcasemismatch" - flip the case of a random subset of QNAME letters in the
                     echoed question section
- "qr0"           - clear the QR bit in the response
- "opcodemismatch" - send back a random opcode that doesn't match the query
- "qtypemismatch" - send back a random QTYPE in the echoed question section
                     that doesn't match the query
- "qdcountmismatch" - either drop the question section entirely, or repeat
                       it 1-10 extra times, giving QDCOUNT 0 or 2-11

Example: "rcode3-tc1-delay500.test." sets RCODE=3, TC=1, and delays the
response by 500 ms.
"""

import contextlib
import os
import random
import re
import socket
import subprocess
import sys
import time

import dns.flags
import dns.name
import dns.opcode
import dns.rcode
import dns.rdatatype

from asyncserver import (
    AsyncDnsServer,
    DnsResponseSend,
    DomainHandler,
    QueryContext,
    ResponseDrop,
    ResponseHandler,
)


def _flip_case_subset(text: str) -> str:
    """Flip a random non-empty subset of the letters in `text`; result always differs."""
    alpha_indices = [i for i, c in enumerate(text) if c.isalpha()]
    assert alpha_indices, f"no letters to flip case on: {text!r}"
    chosen = random.sample(alpha_indices, random.randint(1, len(alpha_indices)))
    chars = list(text)
    for i in chosen:
        chars[i] = chars[i].swapcase()
    return "".join(chars)


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
        idmismatch = False
        qcasemismatch = False
        qr0 = False
        opcodemismatch = False
        qtypemismatch = False
        qdcountmismatch = False
        delay_ms = 0

        for token in instructions.split("-"):
            if token == "tc1":
                tc = True
            elif token == "timeout":
                timeout = True
            elif token == "idmismatch":
                idmismatch = True
            elif token == "qcasemismatch":
                qcasemismatch = True
            elif token == "qr0":
                qr0 = True
            elif token == "opcodemismatch":
                opcodemismatch = True
            elif token == "qtypemismatch":
                qtypemismatch = True
            elif token == "qdcountmismatch":
                qdcountmismatch = True
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
        if idmismatch:
            original_id = qctx.response.id
            new_id = original_id
            while new_id == original_id:
                new_id = random.randint(0, 65535)
            qctx.response.id = new_id
        if qcasemismatch:
            original_name = qctx.response.question[0].name
            flipped_text = _flip_case_subset(original_name.to_text())
            qctx.response.question[0].name = dns.name.from_text(flipped_text)
        if qr0:
            qctx.response.flags &= ~dns.flags.QR
        if opcodemismatch:
            original_opcode = qctx.response.opcode()
            new_opcode = original_opcode
            while new_opcode == original_opcode:
                new_opcode = random.randint(0, 15)
            qctx.response.flags = (qctx.response.flags & ~0x7800) | dns.opcode.to_flags(
                new_opcode
            )
        if qtypemismatch:
            original_rdtype = qctx.response.question[0].rdtype
            new_rdtype = original_rdtype
            while new_rdtype == original_rdtype:
                new_rdtype = random.randint(1, 65535)
            qctx.response.question[0].rdtype = new_rdtype
        if qdcountmismatch:
            if random.random() < 0.5:
                qctx.response.question = []
            else:
                qctx.response.question *= 1 + random.randint(1, 10)

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
    Launch this module as a subprocess on a free port, wait until it accepts
    UDP, yield the port. Out-of-process: AsyncServer.run() installs signal
    handlers via loop.add_signal_handler(), main-thread only.
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
