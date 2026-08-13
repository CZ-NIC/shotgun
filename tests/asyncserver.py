"""
Copyright (C) Internet Systems Consortium, Inc. ("ISC")

SPDX-License-Identifier: MPL-2.0

This Source Code Form is subject to the terms of the Mozilla Public
License, v. 2.0.  If a copy of the MPL was not distributed with this
file, you can obtain one at https://mozilla.org/MPL/2.0/.

See the COPYRIGHT file distributed with this work for additional
information regarding copyright ownership.
"""

from collections.abc import AsyncGenerator, Callable, Coroutine
from dataclasses import dataclass, field
from typing import Any, cast

import abc
import asyncio
import base64
import binascii
import copy
import enum
import logging
import os
import signal
import ssl
import sys
import urllib.parse

import dns.exception
import dns.message
import dns.name
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import h2.config
import h2.connection
import h2.events
import h2.exceptions
import h2.settings

_UdpHandler = Callable[
    [bytes, tuple[str, int], asyncio.DatagramTransport], Coroutine[Any, Any, None]
]


_TcpHandler = Callable[
    [asyncio.StreamReader, asyncio.StreamWriter], Coroutine[Any, Any, None]
]


class _AsyncUdpHandler(asyncio.DatagramProtocol):
    """
    Protocol implementation for handling UDP traffic using asyncio.
    """

    def __init__(
        self,
        handler: _UdpHandler,
    ) -> None:
        self._transport: asyncio.DatagramTransport | None = None
        self._handler: _UdpHandler = handler

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        """
        Called by asyncio when a connection is made.
        """
        self._transport = cast(asyncio.DatagramTransport, transport)

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        """
        Called by asyncio when a datagram is received.
        """
        assert self._transport
        asyncio.create_task(self._handler(data, addr, self._transport))


class AsyncServer:
    """
    A generic asynchronous server which may handle UDP and/or TCP traffic.

    Once the server is executed as asyncio coroutine, it will keep running
    until a SIGINT/SIGTERM signal is received.
    """

    def __init__(
        self,
        udp_handler: _UdpHandler,
        tcp_handler: _TcpHandler,
        tls_port: int | None = None,
        tls_certfile: str | None = None,
        tls_keyfile: str | None = None,
        doh_port: int | None = None,
        doh_handler: _TcpHandler | None = None,
    ) -> None:
        logging.basicConfig(
            format="%(asctime)s %(levelname)8s  %(message)s",
            level=os.environ.get("ANS_LOG_LEVEL", "INFO").upper(),
        )
        try:
            port = int(sys.argv[1])
        except IndexError:
            port = int(os.environ.get("PORT", 5300))

        logging.info("Setting up IPv6 listener at [::1]:%d", port)

        self._ip_addresses: tuple[str, ...] = ("::1",)
        self._port: int = port
        self._udp_handler: _UdpHandler = udp_handler
        self._tcp_handler: _TcpHandler = tcp_handler
        self._tls_port: int | None = tls_port
        self._tls_certfile: str | None = tls_certfile
        self._tls_keyfile: str | None = tls_keyfile
        self._doh_port: int | None = doh_port
        self._doh_handler: _TcpHandler | None = doh_handler
        self._work_done: asyncio.Future | None = None

    def run(self) -> None:
        """
        Start the server in an asynchronous coroutine.
        """
        asyncio.run(self._run())

    async def _run(self) -> None:
        self._setup_exception_handler()
        self._setup_signals()
        assert self._work_done
        await self._listen_udp()
        await self._listen_tcp()
        await self._listen_tls()
        await self._listen_doh()
        await self._work_done

    def _setup_exception_handler(self) -> None:
        loop = asyncio.get_running_loop()
        self._work_done = loop.create_future()
        loop.set_exception_handler(self._handle_exception)

    def _handle_exception(
        self, _: asyncio.AbstractEventLoop, context: dict[str, Any]
    ) -> None:
        assert self._work_done
        exception = context.get("exception", RuntimeError(context["message"]))
        try:
            self._work_done.set_exception(exception)
        except asyncio.InvalidStateError:
            pass

    def _setup_signals(self) -> None:
        loop = asyncio.get_running_loop()
        loop.add_signal_handler(signal.SIGINT, self._signal_done)
        loop.add_signal_handler(signal.SIGTERM, self._signal_done)

    def _signal_done(self) -> None:
        assert self._work_done
        try:
            self._work_done.set_result(True)
        except asyncio.InvalidStateError:
            pass

    async def _listen_udp(self) -> None:
        loop = asyncio.get_running_loop()
        for ip_address in self._ip_addresses:
            await loop.create_datagram_endpoint(
                lambda: _AsyncUdpHandler(self._udp_handler),
                (ip_address, self._port),
            )

    async def _listen_tcp(self) -> None:
        for ip_address in self._ip_addresses:
            await asyncio.start_server(
                self._tcp_handler, host=ip_address, port=self._port, backlog=0
            )

    async def _listen_tls(self) -> None:
        if not self._tls_port:
            return
        assert self._tls_certfile and self._tls_keyfile
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(self._tls_certfile, self._tls_keyfile)
        for ip_address in self._ip_addresses:
            await asyncio.start_server(
                self._tcp_handler,
                host=ip_address,
                port=self._tls_port,
                ssl=ctx,
                backlog=0,
            )

    async def _listen_doh(self) -> None:
        if not self._doh_port:
            return
        assert self._doh_handler and self._tls_certfile and self._tls_keyfile
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(self._tls_certfile, self._tls_keyfile)
        # DoH clients check for a negotiated "h2" ALPN protocol and abort if
        # missing (dnssim's https2.c); DoT (_listen_tls above) needs no ALPN
        # at all, hence the separate context/listener.
        ctx.set_alpn_protocols(["h2"])
        for ip_address in self._ip_addresses:
            await asyncio.start_server(
                self._doh_handler,
                host=ip_address,
                port=self._doh_port,
                ssl=ctx,
                backlog=0,
            )


class DnsProtocol(enum.Enum):
    UDP = enum.auto()
    TCP = enum.auto()
    DOH = enum.auto()


@dataclass(frozen=True)
class Peer:
    """
    Pretty-printed connection endpoint.
    """

    host: str
    port: int

    def __str__(self) -> str:
        host = f"[{self.host}]" if ":" in self.host else self.host
        return f"{host}:{self.port}"


@dataclass
class QueryContext:
    """
    Context for the incoming query which may be used for preparing the response.
    """

    query: dns.message.Message
    response: dns.message.Message
    socket: Peer
    peer: Peer
    protocol: DnsProtocol
    _initialized_response: dns.message.Message | None = field(default=None, init=False)

    @property
    def qname(self) -> dns.name.Name:
        return self.query.question[0].name

    @property
    def qclass(self) -> dns.rdataclass.RdataClass:
        return self.query.question[0].rdclass

    @property
    def qtype(self) -> dns.rdatatype.RdataType:
        return self.query.question[0].rdtype

    def prepare_new_response(self) -> dns.message.Message:
        assert self._initialized_response
        self.response = copy.deepcopy(self._initialized_response)
        return self.response

    def save_initialized_response(self) -> None:
        self._initialized_response = copy.deepcopy(self.response)


@dataclass
class ResponseAction(abc.ABC):
    """
    Base class for actions that can be taken in response to a query.
    """

    @abc.abstractmethod
    async def perform(self) -> dns.message.Message | bytes | None:
        """
        This method is expected to carry out arbitrary actions (e.g. wait for a
        specific amount of time, modify the answer, etc.) and then return the
        DNS response to send (a dns.message.Message, a raw bytes object, or
        None, which prevents any response from being sent).
        """
        raise NotImplementedError


@dataclass
class DnsResponseSend(ResponseAction):
    """
    Action which yields a dns.message.Message response.

    The response may be sent with a delay if requested.
    """

    response: dns.message.Message
    delay: float = 0.0

    async def perform(self) -> dns.message.Message | bytes | None:
        """
        Yield a potentially delayed response that is a dns.message.Message.
        """
        assert isinstance(self.response, dns.message.Message)
        if not _is_asyncserver_response(self.response):
            error = "The response you are trying to send was not created using "
            error += "AsyncDnsServer's response preparation methods. "
            error += "If you need a fresh copy of a response, use "
            error += "`QueryContext.prepare_new_response` instead of "
            error += "`dns.message.make_response`."
            raise RuntimeError(error)

        if self.delay > 0:
            logging.info(
                "Delaying response (ID=%d) by %d ms",
                self.response.id,
                self.delay * 1000,
            )
            await asyncio.sleep(self.delay)
        return self.response


@dataclass
class BytesResponseSend(ResponseAction):
    """
    Action which yields a raw response that is a sequence of bytes.

    The response may be sent with a delay if requested.
    """

    response: bytes
    delay: float = 0.0

    async def perform(self) -> dns.message.Message | bytes | None:
        """
        Yield a potentially delayed response that is a sequence of bytes.
        """
        assert isinstance(self.response, bytes)
        if self.delay > 0:
            logging.info("Delaying raw response by %d ms", self.delay * 1000)
            await asyncio.sleep(self.delay)
        return self.response


@dataclass
class ResponseDrop(ResponseAction):
    """
    Action which does nothing - as if a packet was dropped.
    """

    async def perform(self) -> dns.message.Message | bytes | None:
        return None


class _ConnectionTeardownRequested(Exception):
    pass


@dataclass
class CloseConnection(ResponseAction):
    """
    Action which makes the server close the connection (TCP only).

    The connection may be closed with a delay if requested.
    """

    delay: float = 0.0

    async def perform(self) -> dns.message.Message | bytes | None:
        if self.delay > 0:
            logging.info("Waiting %.1fs before closing TCP connection", self.delay)
            await asyncio.sleep(self.delay)
        raise _ConnectionTeardownRequested


class ResponseHandler(abc.ABC):
    """
    Base class for generic response handlers.

    If a query passes the `match()` function logic, then it is handled by this
    response handler and response(s) may be generated by the `get_responses()`
    method.
    """

    # pylint: disable=unused-argument
    def match(self, qctx: QueryContext) -> bool:
        """
        Matching logic - the first handler whose `match()` method returns True
        is used for handling the query.

        The default for each handler is to handle all queries.
        """
        return True

    @abc.abstractmethod
    async def get_responses(
        self, qctx: QueryContext
    ) -> AsyncGenerator[ResponseAction, None]:
        """
        Custom handler which may produce response(s) to matching queries.
        """
        raise NotImplementedError
        yield  # pylint: disable=unreachable  # makes this an async generator

    def __str__(self) -> str:
        return self.__class__.__name__


class DomainHandler(ResponseHandler):
    """
    Base class used for deriving custom domain handlers.

    The derived class must specify a list of `domains` that it wants to handle.
    Queries for any of these domains (and their subdomains) will then be passed
    to the `get_response()` method in the derived class.

    The most specific matching domain is stored in the `matched_domain` attribute.
    """

    @property
    @abc.abstractmethod
    def domains(self) -> list[str]:
        """
        A list of domain names handled by this class.
        """
        raise NotImplementedError

    def __init__(self) -> None:
        self._domains: list[dns.name.Name] = sorted(
            [dns.name.from_text(d) for d in self.domains], reverse=True
        )
        self._matched_domain: dns.name.Name | None = None

    @property
    def matched_domain(self) -> dns.name.Name:
        assert self._matched_domain is not None
        return self._matched_domain

    def __str__(self) -> str:
        return f"{self.__class__.__name__}(domains: {', '.join(self.domains)})"

    def match(self, qctx: QueryContext) -> bool:
        """
        Handle queries whose QNAME matches any of the domains handled by this
        class.
        """
        self._matched_domain = None
        for domain in self._domains:
            if qctx.qname.is_subdomain(domain):
                self._matched_domain = domain
                return True
        return False


_ASYNCSERVER_RESPONSE_MARKER = "__is_asyncserver_response__"


def _make_asyncserver_response(query: dns.message.Message) -> dns.message.Message:
    response = dns.message.make_response(query)
    setattr(response, _ASYNCSERVER_RESPONSE_MARKER, True)
    return response


def _is_asyncserver_response(message: dns.message.Message) -> bool:
    return getattr(message, _ASYNCSERVER_RESPONSE_MARKER, False)


class AsyncDnsServer(AsyncServer):
    """
    DNS server which responds to queries using custom handlers.

    The server may use custom handlers which allow arbitrary query processing.
    These don't need to be standards-compliant and can be used for testing all
    sorts of scenarios, including delaying responses, synthesizing them based
    on query contents etc.

    Queries not matched by any installed handler are answered with the default
    RCODE (REFUSED).
    """

    _DEFAULT_RCODE = dns.rcode.REFUSED

    def __init__(
        self,
        tls_port: int | None = None,
        tls_certfile: str | None = None,
        tls_keyfile: str | None = None,
        doh_port: int | None = None,
    ) -> None:
        super().__init__(
            self._handle_udp,
            self._handle_tcp,
            tls_port=tls_port,
            tls_certfile=tls_certfile,
            tls_keyfile=tls_keyfile,
            doh_port=doh_port,
            doh_handler=self._handle_doh,
        )

        self._response_handlers: list[ResponseHandler] = []

    def install_response_handler(self, handler: ResponseHandler) -> None:
        """
        Add a response handler that will be used to handle matching queries.

        The provided handler is installed at the end of the response handler
        list.
        """
        logging.info("Installing response handler: %s", handler)
        self._response_handlers.append(handler)

    async def _handle_udp(
        self, wire: bytes, addr: tuple[str, int], transport: asyncio.DatagramTransport
    ) -> None:
        logging.debug("Received UDP message: %s", wire.hex())
        socket_info = transport.get_extra_info("sockname")
        socket = Peer(socket_info[0], socket_info[1])
        peer = Peer(addr[0], addr[1])
        responses = self._handle_query(wire, socket, peer, DnsProtocol.UDP)
        async for response in responses:
            logging.debug("Sending UDP message: %s", response.hex())
            transport.sendto(response, addr)

    async def _handle_tcp(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        peer_info = writer.get_extra_info("peername")
        peer = Peer(peer_info[0], peer_info[1])
        logging.debug("Accepted TCP connection from %s", peer)

        # Responses (including any artificial delay a handler adds) are
        # dispatched as background tasks rather than awaited inline, so one
        # slow response doesn't block reading/answering the next query on
        # this connection. Tasks are tracked here so they aren't garbage
        # collected while pending and so we can wait for in-flight
        # responses to finish before closing the connection below.
        pending_responses: set[asyncio.Task] = set()

        try:
            while True:
                wire = await self._read_tcp_query(reader, peer)
                if not wire:
                    break
                task = asyncio.create_task(
                    self._send_tcp_response(writer, peer, wire, pending_responses)
                )
                pending_responses.add(task)
                task.add_done_callback(pending_responses.discard)
        except _ConnectionTeardownRequested:
            pass
        except ConnectionResetError:
            logging.error("TCP connection from %s reset by peer", peer)
            return
        finally:
            # Wait for in-flight responses without letting one failure abort
            # the others, then re-raise anything unexpected so that handler
            # bugs still take the server down loudly, like they did when
            # responses were awaited inline.  Cancellations are expected
            # during teardown and connection errors are the peer's doing,
            # so neither is worth crashing over.
            for result in await asyncio.gather(
                *pending_responses, return_exceptions=True
            ):
                if not isinstance(result, BaseException):
                    continue
                if isinstance(result, (asyncio.CancelledError, ConnectionError)):
                    logging.debug(
                        "Response to %s ended with %s", peer, type(result).__name__
                    )
                    continue
                raise result

        logging.debug("Closing TCP connection from %s", peer)
        writer.close()
        try:
            await writer.wait_closed()
        except ConnectionError as exc:
            # A response dispatched before the client disconnected may have
            # been written into a socket the peer had already closed; the
            # transport then fails asynchronously and reports the error here.
            # That is the peer's doing, not a server bug.
            logging.debug("TCP connection from %s closed with %r", peer, exc)

    async def _read_tcp_query(
        self, reader: asyncio.StreamReader, peer: Peer
    ) -> bytes | None:
        wire_length = await self._read_tcp_query_wire_length(reader, peer)
        if not wire_length:
            return None

        return await self._read_tcp_query_wire(reader, peer, wire_length)

    async def _read_tcp_query_wire_length(
        self, reader: asyncio.StreamReader, peer: Peer
    ) -> int | None:
        logging.debug("Receiving TCP message length from %s...", peer)

        wire_length_bytes = await self._read_tcp_octets(reader, peer, 2)
        if not wire_length_bytes:
            return None

        return int.from_bytes(wire_length_bytes, byteorder="big")

    async def _read_tcp_query_wire(
        self, reader: asyncio.StreamReader, peer: Peer, wire_length: int
    ) -> bytes | None:
        logging.debug("Receiving TCP message (%d octets) from %s...", wire_length, peer)

        wire = await self._read_tcp_octets(reader, peer, wire_length)
        if not wire:
            return None

        logging.debug("Received complete TCP message from %s: %s", peer, wire.hex())

        return wire

    async def _read_tcp_octets(
        self, reader: asyncio.StreamReader, peer: Peer, expected: int
    ) -> bytes | None:
        buffer = b""

        while len(buffer) < expected:
            chunk = await reader.read(expected - len(buffer))
            if not chunk:
                if buffer:
                    logging.debug(
                        "Received short TCP message (%d octets) from %s: %s",
                        len(buffer),
                        peer,
                        buffer.hex(),
                    )
                else:
                    logging.debug("Received disconnect from %s", peer)
                return None

            logging.debug("Received %d TCP octets from %s", len(chunk), peer)
            buffer += chunk

        return buffer

    async def _send_tcp_response(
        self,
        writer: asyncio.StreamWriter,
        peer: Peer,
        wire: bytes,
        pending_responses: set[asyncio.Task],
    ) -> None:
        socket_info = writer.get_extra_info("sockname")
        socket = Peer(socket_info[0], socket_info[1])
        try:
            responses = self._handle_query(wire, socket, peer, DnsProtocol.TCP)
            async for response in responses:
                logging.debug("Sending TCP response: %s", response.hex())
                writer.write(response)
                await writer.drain()
        except _ConnectionTeardownRequested:
            # Closing the transport makes the read loop's next
            # _read_tcp_query() return None/EOF, so it exits on its own;
            # writer.close() is idempotent if called again once it does.
            # Cancel other in-flight responses on this connection too, since
            # the connection is being torn down regardless of their status.
            for task in list(pending_responses):
                if task is not asyncio.current_task():
                    task.cancel()
            writer.close()

    async def _handle_doh(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        peer_info = writer.get_extra_info("peername")
        peer = Peer(peer_info[0], peer_info[1])
        socket_info = writer.get_extra_info("sockname")
        socket = Peer(socket_info[0], socket_info[1])
        logging.debug("Accepted DoH connection from %s", peer)

        conn = h2.connection.H2Connection(config=h2.config.H2Configuration(client_side=False))
        conn.initiate_connection()
        # h2's default (100) is lower than a single dnsjit/dnssim pacing
        # batch (128 -- see BATCH in test_e2e_*.py), which would otherwise
        # refuse/stall queries pipelined past that limit on one connection.
        conn.update_settings({h2.settings.SettingCodes.MAX_CONCURRENT_STREAMS: 100_000})
        writer.write(conn.data_to_send())
        await writer.drain()

        request_headers: dict[int, dict[bytes, bytes]] = {}
        request_data: dict[int, bytearray] = {}
        pending_responses: set[asyncio.Task] = set()

        try:
            while True:
                data = await reader.read(65535)
                if not data:
                    break
                try:
                    events = conn.receive_data(data)
                except h2.exceptions.ProtocolError:
                    break

                for event in events:
                    if isinstance(event, h2.events.RequestReceived):
                        request_headers[event.stream_id] = dict(event.headers)
                        request_data[event.stream_id] = bytearray()
                    elif isinstance(event, h2.events.DataReceived):
                        request_data[event.stream_id] += event.data
                        conn.acknowledge_received_data(len(event.data), event.stream_id)
                    elif isinstance(event, h2.events.StreamEnded):
                        headers = request_headers.pop(event.stream_id, {})
                        body = bytes(request_data.pop(event.stream_id, b""))
                        wire = self._extract_doh_wire(headers, body)
                        if wire is None:
                            logging.error(
                                "Invalid DoH request from %s (%r, %s)",
                                peer,
                                headers,
                                body.hex(),
                            )
                            conn.reset_stream(event.stream_id)
                            continue
                        task = asyncio.create_task(
                            self._send_doh_response(
                                conn,
                                writer,
                                socket,
                                peer,
                                event.stream_id,
                                wire,
                                pending_responses,
                            )
                        )
                        pending_responses.add(task)
                        task.add_done_callback(pending_responses.discard)
                    elif isinstance(event, h2.events.ConnectionTerminated):
                        return

                outbound = conn.data_to_send()
                if outbound:
                    writer.write(outbound)
                    await writer.drain()
        except _ConnectionTeardownRequested:
            pass
        except ConnectionResetError:
            logging.error("DoH connection from %s reset by peer", peer)
            return
        finally:
            for result in await asyncio.gather(
                *pending_responses, return_exceptions=True
            ):
                if not isinstance(result, BaseException):
                    continue
                if isinstance(result, (asyncio.CancelledError, ConnectionError)):
                    logging.debug(
                        "Response to %s ended with %s", peer, type(result).__name__
                    )
                    continue
                raise result

        logging.debug("Closing DoH connection from %s", peer)
        writer.close()
        try:
            await writer.wait_closed()
        except ConnectionError as exc:
            logging.debug("DoH connection from %s closed with %r", peer, exc)

    def _extract_doh_wire(
        self, headers: dict[bytes, bytes], body: bytes
    ) -> bytes | None:
        """
        Extract the DNS wire message from a DoH request, per RFC 8484: POST's
        body is the message as-is; GET's is base64url(no padding)-encoded in
        the "dns" query parameter.
        """
        method = headers.get(b":method")
        if method == b"POST":
            return body
        if method == b"GET":
            path = headers.get(b":path")
            if not path:
                return None
            query = urllib.parse.urlsplit(path).query
            dns_param = urllib.parse.parse_qs(query).get(b"dns")
            if not dns_param:
                return None
            encoded = dns_param[0] + b"=" * (-len(dns_param[0]) % 4)
            try:
                return base64.urlsafe_b64decode(encoded)
            except binascii.Error:
                return None
        return None

    async def _send_doh_response(
        self,
        conn: h2.connection.H2Connection,
        writer: asyncio.StreamWriter,
        socket: Peer,
        peer: Peer,
        stream_id: int,
        wire: bytes,
        pending_responses: set[asyncio.Task],
    ) -> None:
        try:
            responses = self._handle_query(wire, socket, peer, DnsProtocol.DOH)
            async for response in responses:
                logging.debug("Sending DoH response: %s", response.hex())
                conn.send_headers(
                    stream_id,
                    [
                        (":status", "200"),
                        ("content-type", "application/dns-message"),
                        ("content-length", str(len(response))),
                    ],
                )
                conn.send_data(stream_id, response, end_stream=True)
                writer.write(conn.data_to_send())
                await writer.drain()
        except _ConnectionTeardownRequested:
            # Unlike CloseConnection on a plain TCP connection (one query,
            # one connection), HTTP/2 multiplexes many streams per
            # connection; CloseConnection tears down the whole thing, same
            # as it does for TCP, cancelling any other in-flight streams.
            for task in list(pending_responses):
                if task is not asyncio.current_task():
                    task.cancel()
            writer.close()

    def _log_query(self, qctx: QueryContext) -> None:
        logging.info(
            "Received %s/%s/%s (ID=%d) query from %s on %s (%s)",
            qctx.qname.to_text(omit_final_dot=True),
            dns.rdataclass.to_text(qctx.qclass),
            dns.rdatatype.to_text(qctx.qtype),
            qctx.query.id,
            qctx.peer,
            qctx.socket,
            qctx.protocol.name,
        )
        logging.debug(
            "\n".join([f"[IN] {l}" for l in [""] + str(qctx.query).splitlines()])
        )

    def _log_response(
        self, qctx: QueryContext, response: dns.message.Message | bytes | None
    ) -> None:
        if not response:
            logging.info(
                "Not sending a response to query (ID=%d) from %s on %s (%s)",
                qctx.query.id,
                qctx.peer,
                qctx.socket,
                qctx.protocol.name,
            )
            return

        if isinstance(response, dns.message.Message):
            try:
                qname = response.question[0].name.to_text(omit_final_dot=True)
                qclass = dns.rdataclass.to_text(response.question[0].rdclass)
                qtype = dns.rdatatype.to_text(response.question[0].rdtype)
            except IndexError:
                qname = "<empty>"
                qclass = "-"
                qtype = "-"

            logging.info(
                "Sending %s/%s/%s (ID=%d) response (%d/%d/%d/%d) to a query (ID=%d) from %s on %s (%s)",
                qname,
                qclass,
                qtype,
                response.id,
                len(response.question),
                len(response.answer),
                len(response.authority),
                len(response.additional),
                qctx.query.id,
                qctx.peer,
                qctx.socket,
                qctx.protocol.name,
            )
            try:
                response_text = str(response)
            except OverflowError:
                response_text = "<response not representable as text>"
            logging.debug(
                "\n".join([f"[OUT] {l}" for l in [""] + response_text.splitlines()])
            )
            return

        logging.info(
            "Sending response (%d bytes) to a query (ID=%d) from %s on %s (%s)",
            len(response),
            qctx.query.id,
            qctx.peer,
            qctx.socket,
            qctx.protocol.name,
        )
        logging.debug("[OUT] %s", response.hex())

    def _prepare_response_wire(
        self, qctx: QueryContext, response: dns.message.Message | bytes | None
    ) -> bytes | None:
        def add_framing(payload: bytes) -> bytes:
            # UDP and DoH delimit messages at the transport level already
            # (one datagram, one HTTP/2 DATA+END_STREAM); only TCP/DoT need
            # the 2-octet length prefix.
            if qctx.protocol in (DnsProtocol.UDP, DnsProtocol.DOH):
                return payload
            return len(payload).to_bytes(2, byteorder="big") + payload

        match response:
            case bytes() as payload:
                return add_framing(payload)
            case dns.message.Message():
                return add_framing(response.to_wire(max_size=65535))
            case _:
                return None

    async def _handle_query(
        self, wire: bytes, socket: Peer, peer: Peer, protocol: DnsProtocol
    ) -> AsyncGenerator[bytes, None]:
        """
        Yield wire data to send as a response over the established transport.
        """
        try:
            query = dns.message.from_wire(wire)
        except dns.exception.DNSException as exc:
            logging.error("Invalid query from %s (%s): %s", peer, wire.hex(), exc)
            return
        response_stub = _make_asyncserver_response(query)
        qctx = QueryContext(query, response_stub, socket, peer, protocol)
        self._log_query(qctx)
        responses = self._prepare_responses(qctx)
        async for response in responses:
            response_wire = self._prepare_response_wire(qctx, response)
            self._log_response(qctx, response)
            if response_wire is not None:
                yield response_wire

    async def _prepare_responses(
        self, qctx: QueryContext
    ) -> AsyncGenerator[dns.message.Message | bytes | None, None]:
        """
        Yield response(s) from the matching response handler, if any.
        """
        qctx.response.set_rcode(self._DEFAULT_RCODE)
        qctx.save_initialized_response()

        response_handled = False
        async for action in self._run_response_handlers(qctx):
            yield await action.perform()
            response_handled = True

        if not response_handled:
            logging.debug("No response handler matched, responding with default RCODE")
            yield qctx.response

    async def _run_response_handlers(
        self, qctx: QueryContext
    ) -> AsyncGenerator[ResponseAction, None]:
        """
        Yield response(s) to the query from a matching query handler.
        """
        for handler in self._response_handlers:
            if handler.match(qctx):
                logging.debug("Matched response handler: %s", handler)
                async for response in handler.get_responses(qctx):
                    yield response
                return
