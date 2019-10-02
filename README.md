# Shotgun

Realistic DNS traffic simulator with many independent clients

## Current status

- under development: active branches unstable, docker containers should work
- prototype for processing inut PCAPs is functional, but slow and requires
  python-dpkt from master
- prototype for sending traffic is able to simulate UDP clients
- dnsjit extensions are not merged upstream

## Overview

The idea is to simulate many simultaneous clients with real behaviour, e.g.
asking different queries with some delays in between. These clients can then be
replayed against a server using either UDP, TCP or TLS. This should allow
comparison of UDP vs TCP vs TLS performance from both client and server point
of view.

## Usage

### Dependencies

#### pellet.py

- python-dpkt (latest from git, commit 2c6aada35 or newer)

#### shotgun.lua

- dnsjit (with dnssim installed from https://github.com/tomaskrizek/dnsjit/tree/simulator )

### Input data

To have a realistic simulation of clients, no synthetic queries are created.
Instead, an input PCAP must be provided. There are the following assumptions:

- Each IP address represents a unique client.
- The packets are ordered by ascending time.
- Only UDP packets arriving to port 53 are used.

The PCAP is then sliced into the requested time periods, and DNS queries are
collected for each client. The output PCAP contains the exact same queries,
only the msgid is renumbered to be sequential (to avoid issues with multiple
in-flight TCP queries with potentially the same msgid).

The input data can be created with:

```
./pellet.py input.pcap -c CLIENTS -t TIME
```

where `CLIENTS` is the number of required clients and `TIME` is the selected
time period.

### Replaying the traffic

Simulating tens thousands of individual clients is challenging, especially with
TCP. Plans are to support UDP, TCP and TLS.

For ease of use, docker container with shotgun is available. Note that running
``--privileged`` can improve its performance by a few percent, if you don't mind
the security risk.

```
docker run registry.labs.nic.cz/knot/shotgun:20191001 --help
```

#### Shotgun

The machine that will act as the sender of the traffic should have enough IPs
and ports to avoid their exhaustion. This is especially important for TCP/TLS.

Only IPv6 is supported right now. You can use the fd00::/8 range to create
unique local addresses and assign multiple of them to a single interface.

It's also a good idea to extend the port range. In my testing with linux
kernel 5.3.1, it seemed once a half of this range is depleted, creating a new
socket starts to take a significantly longer time, slowing the tool down. I'd
recommend planing the expected port usage to utilize no more than half of the
port range per IP.

```
sysctl -w net.ipv4.ip_local_port_range="1025 60999"
```

#### UDP

- On the server, make sure the socket's receive buffer is sufficient.
  Otherwise, many packets can be lost, resulting in low response rate.

  ```
  net.core.rmem_default=8192000
  ```
