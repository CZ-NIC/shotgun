# Key Concepts

DNS Shotgun is capable of simulating real client behaviour by replaying
captured traffic over selected protocol(s). The timing of original queries as
well as their content is kept intact.

Realistic high-performance benchmarking requires complex setup, especially for
TCP-based protocols. However, the authors of this tool have successfully used it
to benchmark and test various DNS implementations with up to hundreds of
thousands of clients (meaning _connections_ for TCP-based transports) using
commodity hardware. This requires [performance tuning](performance-tuning.md)
that is described in later section.

## Client

These docs often mention "*client*" and we often use it to describe DNS
infrastructure throughput in addition to queries per second (QPS). What is a
considered a client and why does it matter?

A client is the origin of one or more queries and it is supposed to represent a
single device, i.e. anything from a CPE such as home/office router to a mobile
device. Since traffic patterns of various devices can vary greatly, it is
crucial to use traffic that most accurately represents your real clients.

In plain DNS sent over UDP the concept of client doesn't matter, since UDP is a
stateless protocol and a packet is just a packet. Thus, QPS throughput may be
sufficient metric for UDP.

In stateful DNS protocols, such as DoT, DoH or TCP, much of the overhead and
performance cost is caused by establishing the connection over which queries
are subsequently sent. Therefore, the concept of client becomes crucial for
benchmarking stateful protocols.

!!! note
    As an extreme example, consider 10k QPS sent over a single DoH connection
    versus establishing a 10k DoH connections, each with 1 QPS. While both
    scenarios have the same overall QPS, the second one will consume vastly more
    resources, especially when establishing the connections.

### Client replay guarantees

DNS Shotgun aims to provide the most realistic client behaviour when replaying
the traffic. When you run DNS Shotgun, there are the following guarantees when
using a stateful protocol.

- **Multiple clients never share a single connection.**
- **Each client attempts to establish at least one connection.**
- **A client may have zero, one or more (rarely) active established connections
  at any time**, depending on its traffic and behavior.

## Real traffic

A key focus of this toolchain is to make the benchmarks as realistic as
possible. Therefore, no synthetic queries or clients are generated. To
effectively use this tool, you need to have large amount of source PCAPs.
Ideally, these contain the traffic from your own network.

!!! note
    In case you'd prefer to use synthetic client/queries anyway, you can just
    generate the traffic and capture it in PCAP for further processing. Doing that
    is outside of the scope of this documentation.

### Traffic replay guarantees

- **Content of DNS messages is left intact.** Messages without proper DNS header
  or question section will be discarded.
- **Timing of the DNS messages is kept as close to the original traffic as
  possible.** If the tool detects time skew larger than one second, it aborts the
  test. However, real time difference may be slightly longer due to various
  buffers.
