# DNS Shotgun

Realistic DNS benchmarking tool which supports multiple transport protocols:

  - **DNS-over-QUIC (DoQ)**
  - **DNS-over-TLS (DoT)**
  - **DNS-over-HTTPS (DoH)**
  - UDP
  - TCP

*DNS Shotgun is capable of simulating hundreds of thousands of DoT/DoH clients.*

Every client establishes its own connection(s) when communicating over TCP-based
protocols. This makes the tool uniquely suited for realistic DoT/DoH benchmarks
since its traffic patterns are very similar to real clients.

Similarly, each client establishes its own connection(s) when communicating over
QUIC, utilizing its capability of sending/receiving queries over a single secure
connection, but with multiple mutually independent streams.

DNS Shotgun exports a number of statistics, such as query latencies, number of
handshakes and connections, response rate, response codes etc. in JSON format.
The toolchain also provides scripts that can plot these into readable charts.

## Features

- Supports DNS over UDP, TCP, TLS, HTTP/2, and QUIC
- Allows mixed-protocol simultaneous benchmark/testing
- Can bind to multiple source IP addresses
- Customizable client behaviour (idle time, TLS versions, HTTP method, ...)
- Replays captured queries over selected protocol(s) while keeping original timing
- Suitable for high-performance realistic benchmarks
- Tools to plot charts from output data to evaluate results

## Caveats

- Requires captured traffic from clients
- Setup for proper benchmarks can be quite complex
- Isn't suitable for testing with very low number of clients/queries
- Backward compatibility between versions isn't kept

## Code Repository

[https://gitlab.nic.cz/knot/shotgun](https://gitlab.nic.cz/knot/shotgun)
