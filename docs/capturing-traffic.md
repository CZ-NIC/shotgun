# Capturing Traffic

When replaying traffic using DNS Shotgun, you need to provide it with a PCAP
that contains extracted client data, or "*pellets*". You may not use an
arbitrary PCAP file. Instead, you must pre-process the raw PCAP capture into
pellets as described in the following sections.

!!! note
    DNS Shotgun's measurements are only as good as the data you feed it.
    Quality of input data that most accurately represents your clients is
    crucial for realistic benchmarking. Results can vary greatly for different
    client populations.

## Raw capture assumptions

To start, you need a traffic capture from your network to work with. It only
needs to contain UDP DNS queries from clients towards your resolver. Other
traffic may be present as well, but it will be filtered out.

### Packets must be sorted by increasing timestamp

Some network or hardware conditions may cause the packets to appear in
different order. To ensure correct order, use the `reodercap` command from
tshark/wireshark.

```
$ reordercap raw.pcap ordered.pcap
```

### Unique IP means unique client

Client needs to be somehow identified in the captured traffic. We decided to
use IP address to tell clients apart. This should be a reasonable assumption,
unless your clients are behind NAT.

!!! warning
    If your real clients are behind NAT, this has major consequences and should
    be acounted for, since multiple real clients will be bundled in a single
    simulated one.

### Only UDP packets are used

If large number of your clients already use DoT, DoH or TCP, you need to
somehow get their queries into plain UDP format. For example, Knot Resolver can
[mirror](https://knot-resolver.readthedocs.io/en/v5.2.1/modules-policy.html#policy.MIRROR)
incoming queries to UDP.

## Filtering DNS queries

In this step, UDP DNS queries from clients are extracted from the raw PCAP. If
the raw capture includes queries from resolver to upstream servers, it is
_crucial_ to provide the script with resolver IP address(es) to filter out
outgoing queries.

```
$ pcap/filter-dnsq.lua -r ordered.pcap -w filtered.pcap -a $RESOLVER_IP
```

!!! tip
    You may also use this script to work with traffic directly captured from
    interface chosen with `-i`. See `--help` for usage.
