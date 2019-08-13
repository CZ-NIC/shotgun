# Shotgun

Realistic DNS traffic simulator with many independent clients

## Overview

The idea is to simulate many simultaneous clients with real behaviour, e.g.
asking different queries with some delays in between. These clients can then be
replayed against a server using either UDP, TCP or TLS. This should allow
comparison of UDP vs TCP vs TLS performance from both client and server point
of view.

## Usage

### Dependencies

- python-dpkt (latest from git, commit 2c6aada35 or newer)

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

TODO
