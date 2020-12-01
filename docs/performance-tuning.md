# Performance Tuning

Any high-performance benchmark setup requires separate server for generating
traffic which then sends the traffic to the target server under test.  In order
to scale-up DNS Shotgun to be able to perform well under heavy load, some
performance tuning and network adjustments are needed.

!!! tip
    An example of performance tuning we use in our benchmarks can be found in
    our [ansible
    role](https://gitlab.nic.cz/knot/resolver-benchmarking/-/tree/master/roles/tuning).

## Number of file descriptors

Make sure the number of available file descriptors is sufficient. It's
typically necessary when running DNS Shotgun from terminal. When using docker,
the defaults are usually sufficient.

```
$ ulimit -n 1000000
```

## Ephemeral port range

Extending the ephemeral port range gives the tool more outgoing ports to work with.

```
$ sysctl -w net.ipv4.ip_local_port_range="1025 60999"
```

## NIC queues

High-end network cards typically has multiple queues. Ideally, you want to set
their number to be the same as number of available CPUs.

```
$ ethtool -L $INTERFACE combined $NCPU
```

!!! note
    It's important that the NIC interrupts from different queues are handled
    by different CPUs. If there are throughput issues, you may want to verify
    this is the case.

## UDP

DNS Shotgun can generate quite bursty traffic. Increasing the receiving
server's socket memory can help to prevent that. If this buffer isn't
sufficient, it can cause packet loss.

```
$ sysctl -w net.core.rmem_default="8192000"
```

## TCP, DoT, DoH

Tuning the network stack for TCP isn't as straightforward and it's network-card
specific. It's best to refer to [kernel
documentation](https://www.kernel.org/doc/html/latest/networking/device_drivers/ethernet/intel/ixgb.html#improving-performance)
for your specific network card.

## conntrack

For our benchmarks, we don't use iptables or any firewall. Especially the
`conntrack` module probably won't be able to handle serious load. Make sure the
conntrack module isn't loaded by kernel if you're not using it.
