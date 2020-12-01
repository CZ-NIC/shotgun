# Replaying Traffic

Once you've prepared the input pellets file with clients and either have you
own configuration file or know which present you want to use, you can the the
following scripts to run DNS Shotgun.

```
$ replay.py -r pellets.pcap -c udp -s ::1
```

!!! tip
    Use the `--help` option to explore other options.

During the replay, there is quite a bit of logging information that look like
this.

```
UDP-01 notice: total processed:       267; answers:         0; discarded:         2; ongoing:       172
```

The important thing to look out for is the number of `discarded` packets. In
case nearly all the packets are discarded or a large portion of them, it almost
certainly indicates some improper setup or input data. The test should be
aborted and the reason should be investigated. Increasing the `-v/--verbosity`
level might help.

## Binding to multiple source addresses

When sending traffic against a single IP/port combination of the target server,
the source IP address has a limited number of ports it can utilize.  A single
IP address is insufficient to achieve hundreds of thousands of clients.


DNS Shotgun can bind to multiple sources addresses with the `-b/--bind-net`
option. Multiple IP addresses can be specified. A network range using the CIDR
notation can be used as well.

```
$ replay.py -r pellets.pcap -c tcp -s fd00:dead:beef::cafe -b fd00:dead:beef::/124
```

!!! tip
    Our rule of thumb is to use at least one source IP address per every 30k
    clients.  However, using more addresses is certainly better and can help to
    avoid weird behaviour, slow performance and other issues that require
    in-depth troubleshooting.

!!! note
    If you're limited by the number of source addresses you can use, utilizing
    either IPv6 unique-local addresses (fd00::/8) or private IPv4 ranges could
    be helpful.

## Emulating link latency

!!! warning
    This is an advanced topic and emulating latency isn't necessary for many
    scenarios.

Overall latency will affect the user's experience with DNS resolution. It also
becomes much more relevant when using TCP and TLS, since the handshakes
introduce additional round trips. When benchmarks are done in the data center
with two servers that are directly connected to each other with practically no
latency, it can provide a skewed view of the expected end user latency.

Luckily, the `netem` Network Emulator makes it very simple to emulate various
network conditions. For example, emulating latency on the sender side can be
done quite easily. The following command adds 10 ms latency to outgoing
packets, effectively simulating RTT of 10 ms.

```
$ tc qdisc add dev $INTERFACE root netem limit 10000000 delay 10ms
```

!!! tip
    For more possibilities, refer to `man netem.8`. Using a sufficiently large
    buffer (limit) is essential for proper operation.

However, beware that the settings affect the entire interface. If you're going
to emulate latency, it's best if the resolver-client traffic is on a separate
interface, so the resolver-upstream traffic isn't negatively impacted.
