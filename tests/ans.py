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
- "delayN"        - delay the response by N milliseconds (this query only;
                     other connections keep being served meanwhile)
- "blockN"        - synchronously block the whole server process for N
                     milliseconds: no new connections accepted, no other
                     pending response sent, until it returns
- "idmismatch"    - send back a random message ID that doesn't match the query
- "qcasemismatch" - flip the case of a random subset of QNAME letters in the
                     echoed question section
- "qr0"           - clear the QR bit in the response
- "opcodemismatch" - send back a random opcode that doesn't match the query
- "qtypemismatch" - send back a random QTYPE in the echoed question section
                     that doesn't match the query
- "qdcountmismatch" - either drop the question section entirely, or repeat
                       it 1-10 extra times, giving QDCOUNT 0 or 2-11
- "cutshort"      - truncate the response wire format at a random offset
- "terminate"     - exit the server process immediately (os._exit), forcibly
                     closing all connections and dropping all pending queries

Example: "rcode3-tc1-delay500.test." sets RCODE=3, TC=1, and delays the
response by 500 ms.
"""

import contextlib
import os
import pathlib
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

from asyncserver import (
    AsyncDnsServer,
    BytesResponseSend,
    DnsResponseSend,
    DomainHandler,
    QueryContext,
    ResponseDrop,
    ResponseHandler,
)
from tls_cert import generate_cert


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
    _BLOCK_RE = re.compile(r"^block(\d+)$")

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
        cutshort = False
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
            elif token == "cutshort":
                cutshort = True
            elif token == "terminate":
                # os._exit, not sys.exit: skips asyncio/event-loop cleanup,
                # so open connections drop instead of closing gracefully.
                os._exit(0)
            elif match := self._RCODE_RE.match(token):
                rcode = int(match.group(1))
            elif match := self._DELAY_RE.match(token):
                delay_ms = int(match.group(1))
            elif match := self._BLOCK_RE.match(token):
                # time.sleep, not asyncio.sleep: blocks the whole event loop
                # thread, not just this response's task.
                time.sleep(int(match.group(1)) / 1000)
            else:
                _exit_on_unrecognized_query(qctx)

        if timeout:
            yield ResponseDrop()
            return

        qctx.prepare_new_response()
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

        if cutshort:
            wire = qctx.response.to_wire(max_size=65535)
            cut_at = random.randint(0, len(wire) - 1)
            yield BytesResponseSend(wire[:cut_at], delay=delay_ms / 1000.0)
            return

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
    tls_port = os.environ.get("TLS_PORT")
    doh_port = os.environ.get("DOH_PORT")
    doq_port = os.environ.get("DOQ_PORT")
    server = AsyncDnsServer(
        tls_port=int(tls_port) if tls_port else None,
        tls_certfile=os.environ.get("TLS_CERTFILE"),
        tls_keyfile=os.environ.get("TLS_KEYFILE"),
        doh_port=int(doh_port) if doh_port else None,
        doq_port=int(doq_port) if doq_port else None,
    )
    server.install_response_handler(QnameInstructionHandler())
    server.install_response_handler(UnrecognizedQueryHandler())
    return server


def _free_port() -> int:
    return _free_ports(1)[0]


def _free_ports(n: int) -> list[int]:
    # Bind all sockets before closing any, so the OS can't hand back a port
    # still held by an earlier one in this same call.
    socks = [socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) for _ in range(n)]
    try:
        for s in socks:
            s.bind(("::1", 0))
        return [s.getsockname()[1] for s in socks]
    finally:
        for s in socks:
            s.close()


def _wait_for_tcp_port(port: int, timeout: float) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("::1", port), timeout=0.1):
                return
        except OSError:
            time.sleep(0.1)
    raise TimeoutError(f"ans.py did not start listening on port {port}")


@contextlib.contextmanager
def run_in_subprocess(
    timeout: float = 5.0,
    cert_dir: pathlib.Path | None = None,
    doh: bool = False,
    doq: bool = False,
):
    """
    Launch this module as a subprocess on a free port, wait until it accepts
    TCP, yield the port. Out-of-process: AsyncServer.run() installs signal
    handlers via loop.add_signal_handler(), main-thread only.

    With cert_dir given, also sets up a DoT listener on a second free port
    with an ephemeral cert (see tls_cert.py) generated into cert_dir, and
    yields (port, tls_port) instead. With doh=True or doq=True (both require
    cert_dir) a third free port gets a DoH or DoQ listener (same cert)
    instead of DoT, yielding (port, doh_port) or (port, doq_port).
    """
    assert not (doh and doq), "doh and doq are mutually exclusive"
    tls_port: int | None = None
    doh_port: int | None = None
    doq_port: int | None = None
    env = os.environ.copy()

    if cert_dir is not None:
        if doh or doq:
            port, tls_port, extra_port = _free_ports(3)
            if doh:
                doh_port = extra_port
            else:
                doq_port = extra_port
        else:
            port, tls_port = _free_ports(2)
        cert, key = generate_cert(cert_dir)
        env["TLS_CERTFILE"] = str(cert)
        env["TLS_KEYFILE"] = str(key)
        env["TLS_PORT"] = str(tls_port)
        if doh_port is not None:
            env["DOH_PORT"] = str(doh_port)
        if doq_port is not None:
            env["DOQ_PORT"] = str(doq_port)
    else:
        port = _free_port()

    proc = subprocess.Popen([sys.executable, __file__, str(port)], env=env)
    try:
        _wait_for_tcp_port(port, timeout)
        if doq_port is not None:
            # No readiness probe: a DoQ listener is UDP-only, and nothing
            # answers a bare connect. AsyncServer binds it before the plain
            # TCP port, so the wait above already covers it.
            yield port, doq_port
        elif doh_port is not None:
            _wait_for_tcp_port(doh_port, timeout)
            yield port, doh_port
        elif tls_port is not None:
            _wait_for_tcp_port(tls_port, timeout)
            yield port, tls_port
        else:
            yield port
    finally:
        proc.terminate()
        proc.wait(timeout=timeout)


if __name__ == "__main__":
    make_server().run()
