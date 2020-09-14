# DNS Shotgun

Realistic DNS benchmarking tool which supports:

  - UDP
  - TCP
  - DNS-over-TLS (DoT)
  - DNS-over-HTTPS (Doh)

DNS Shotgun is capable of emulating hundreds of thousands of clients.  This is
especially useful to simulate realistic traffic over stateful protocols, since
every client establishes its own connection.

## Current status (2020-09-14)

- under development: unstable UI, only IPv6 support
- prototype for processing input PCAPs is functional, but slow and requires
  python-dpkt from master
- dnsjit 1.0.0 supports UDP, TCP and DNS-over-TLS, development version
  is needed for DNS-over-HTTPS

## Overview

DNS Shotgun is capable of simulating real client behaviour by replaying
captured traffic over selected protocol(s). The timing of original queries as
well as their content is kept intact.

This tool requires large amount of source PCAPs. These are ideally captured
directly on your network to simulate the behaviour of your clients. The captured
PCAPs are then pre-processed into DNS Shotgun "pellets", which are input files
that contain the selected amount of simulated clients based on the original
traffic.

Realistic high-performance benchmarking requires complex setup, especially for
TCP-based protocols. However, the authors of this tool have successfully used it
to benchmark and test various DNS implementations with up to hundreds of
thousands of clients (meaning _connections_ for TCP-based transports) using
commodity hardware.

## Input data

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
./pellet.py input.pcap -c CLIENTS -t TIME -r RESOLVER_IP
```

where `CLIENTS` is the number of required clients and `TIME` is the selected
time period. `RESOLVER_IP` is necessary to extract only the traffic towards the
resolver and not other upstream servers.

## Replaying the traffic

### UDP

```
./shotgun.lua -P udp -p 53 -s "::1" pellets.pcap
```

### TCP

```
./shotgun.lua -P tcp -p 53 -s "::1" pellets.pcap
./shotgun.lua -P tcp -p 53 -s "::1" -e 0  pellets.pcap  # no idle timeout
```

### DNS-over-TLS (DoT)

```
./shotgun.lua -P dot -p 853 -s "::1" pellets.pcap
./shotgun.lua -P dot -p 853 -s "::1" --tls-priority "NORMAL:-VERS-ALL:+VERS-TLS1.3" pellets.pcap
./shotgun.lua -P dot -p 853 -s "::1" --tls-priority "NORMAL:%NO_TICKETS" pellets.pcap
```

### DNS-over-HTTPS (DoH)

```
./shotgun.lua -P doh -p 443 -s "::1" --tls-priority "NORMAL:-VERS-ALL:+VERS-TLS1.3" pellets.pcap
./shotgun.lua -P dot -p 443 -s "::1" --tls-priority "NORMAL:-VERS-ALL:+VERS-TLS1.3" -M POST pellets.pcap
```

### High-performance benchmarking

```
./shotgun.lua \
	-P dot \
	-p 853 \
	-s "fd00:dead:beef::cafe" \
	-T 15 \
	--bind-pattern "fd00:dead:beef::%x" \
	--bind-num 8 \
	pellets.pcap
```

To be able to scale-up to hundreds of thousands of TCP connections, multiple
source IP addresses are needed. It's possible to utilize [unique-local
addresses](https://en.wikipedia.org/wiki/Unique_local_address) in IPv6. Our rule
of thumb is to use one IP per every 30k clients (when the port range is extended
to allow 60k ephemeral ports).

Check out the kernel documentation for tuning the network stack for TCP. Other tips:
```
ulimit -n 1000000
sysctl -w net.ipv4.ip_local_port_range="1025 60999"
stsctl -w net.core.rmem_default="8192000"
```

## Docker container

For ease of use, docker container with shotgun is available. Note that running
``--privileged`` can improve its performance by a few percent, if you don't mind
the security risk.

```
docker run registry.labs.nic.cz/knot/shotgun:20200914 --help
```

The following example can be used to test the prototype to simulate UDP clients.

Process captured PCAP and extract clients 50k clients within 30 seconds of traffic:

```
docker run -v "$PWD:/data:rw" registry.nic.cz/knot/shotgun/pellet:20200914 /data/captured.pcap -o /data/pellets.pcap -c 50000 -t 30 -r $RESOLVER_IP
```

Replay the clients against IPv6 localhost server:

```
docker run --network host -v "$PWD:/data:rw" registry.nic.cz/knot/shotgun:20200914 -O /data /data/pellets.pcap -s "::1"
```

## Interpreting the results

DNS Shotgun's output is one JSON file per every thread. These can be merged
together and then various plots describing the latencies, connection statistics
etc. can be generated using our utility scripts in the `tools/` directory.

## Dependencies

When using the sources, the following dependencies are needed.

### pellet.py

- python-dpkt (latest from git, commit 2c6aada35 or newer)
- python-dnspython

### shotgun.lua

- dnsjit 1.0.0 for UDP, TCP and DoT
- development version of dnsjit for DoH
