# Configuration Presets

You can either use a configuration preset or create your own configuration. It
is possible to replay the original traffic over various different protocols
with different client behaviours simultaneously. For example, you can split
your traffic into 60 % UDP, 20 % DoT and 20 % DoH.

There are the following predefined use-cases for simplicity of use without the
need to create a configuration file. You can pass these values instead of
filepath to `-c/--config` option of `replay.py` utility.

- `udp`
    - 100 % DNS-over-UDP clients
- `tcp`
    - 100 % well-behaved DNS-over-TCP clients
- `dot`
    - 100 % well-behaved DNS-over-TLS clients using TLS Session Resumption
- `doh`
    - 50 % well-behaved DNS-over-HTTPS GET clients using TLS Session Resumption
    - 50 % well-behaved DNS-over-HTTPS POST clients using TLS Session Resumption
- `doq`
    - 100 % well-behaved DNS-over-QUIC clients
- `mixed`
    - 60 % DNS-over-UDP clients
    - 5 % well-behaved DNS-over-TCP clients
    - 5 % aggressive DNS-over-TCP clients
    - 10 % well-behaved DNS-over-TLS clients using TLS Session Resumption
    - 5 % well-behaved DNS-over-TLS clients without TLS Session Resumption
    - 10 % well-behaved DNS-over-HTTPS GET clients using TLS Session Resumption
    - 5 % well-behaved DNS-over-HTTPS POST clients using TLS Session Resumption

!!! note
    You can find configuration files for presets in
    [`config/`](https://gitlab.nic.cz/knot/shotgun/-/tree/master/config).  They
    are an excellent starting point to create your own configurations.
