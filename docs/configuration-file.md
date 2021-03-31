# Configuration File

!!! tip
    You can find configuration files for presets in
    [`config/`](https://gitlab.nic.cz/knot/shotgun/-/tree/master/config).  They
    are an excellent starting point to create your own configurations.

Configuration is written in [TOML](https://toml.io/en/). There are multiple sections that may have additional subsections.

- `[traffic]` contains one or more subsections that each define client behaviour, including protocol
- `[charts]` is an optional section which can contain subsections that define charts that should be automatically plotted
- `[defaults.traffic]` is an optional section that makes it possible specify defaults shared by all traffic senders
- `[input]` is an optional section that specifies how to read input data

## [traffic] section

You can define one or more traffic senders with specific client behaviour. Every traffic sender has a name and may have multiple parameters. At the very least, each traffic sender must define `protocol`.

This is an example of minimal configuration file sending all traffic as DNS-over-TLS using defaults for everything. The name of the traffic sender here is "DoT".

```
[traffic]
[traffic.DoT]
protocol = "dot"
```

The following configuration parameters for traffic senders are supported.

### protocol

- `udp`: DNS over UDP
- `tcp`: DNS over TCP
- `dot`: DNS over TLS over TCP
- `doh`: DNS over HTTP/2 over TLS over TCP

### weight

When multiple traffic senders are defined, weight affects the client
distribution between them.  Weight is relative to the sum of all weights.

Integer or float. Defaults to 1.


### idle_time_s

Determines whether clients keep the connection in idle state, i.e. leaving it
established after they have received all answers and currently have no more
queries to send.  Idle time of 0 means the client will close the connection as
soon as possible.

Integer. Defaults to 10 seconds.

### gnutls_priority

[GnuTLS priority string](https://gnutls.org/manual/html_node/Priority-Strings.html)
which can be used to select TLS protocol version and features, for example:

```
gnutls_priority = "NORMAL:%NO_TICKETS"  # don't use TLS Session Resumption
gnutls_priority = "NORMAL:-VERS-ALL:+VERS-TLS1.3"  # only use TLS 1.3
```

String. Defaults to `NORMAL` which is determined by the system's GnuTLS library.

### http_method

- `GET`
- `POST`

### timeout_s

Individual query timeout in seconds.

Integer. Defaults to 2 seconds.

!!! warning
    Increasing the query timeout can negatively impact DNS Shotgun's
    performance and is not recommended.

### handshake_timeout_s

Timeout for establishing a connection in seconds.

Integer. Defaults to 5 seconds.

### Advanced settings

You shouldn't use these unless you need to.

- `cpu_factor`: override the default CPU thread distribution (UDP: 1, TCP:2, DoT/DoH: 3)
- `max_clients`: number of clients each dnssim instance can hold (per-thread settings)
- `channel_size`: number of queries that can be buffered before thread starts to block
- `batch_size`: number of queries processed in each loop

### CLI overrides

The following options can be used to override the CLI options for `replay.py`.
Values in configuration file always take precedence before CLI options.

- `server`: target server's IPv4/IPv6 address
- `dns_port`: target server's port for plain DNS (UDP and TCP)
- `dot_port`: target server's port for DNS-over-TLS
- `doh_port`: target server's port for DNS-over-HTTPS

## [charts] section

This section is optional and is only provided as a convenience to automate
plotting charts after the test. Anything defined in this section can be
achieved by using the plotting scripts directly.

Similarly to the `[traffic]` section, it also contains named subsections. Every
such subsection must contain `type` which determines the charts that should be
plotted. For example:

```
[charts]
[charts.response-rate]
type = "response-rate"
```

### type

Type determines which chart will be plotted. The following charts are supported:

- `response-rate`: [Response Rate Chart](response-rate-chart.md)
- `latency`: [Latency Histogram](latency-histogram.md)
- `connections`: [Connection Chart](connection-chart.md)

### title

Title of the chart.

### output

Output filename for the chart. Various file extensions can be used. Defaults to using svg.

### Other parameters

These depend on the specific chart type. Generally, any option that can be
passed directly to the plotting scripts can also be specified in the config.
Refer to the tools `--help` for possible options.

## [defaults] section

### [defaults.traffic] section

This section can provide defaults for all traffic senders. If a specific
traffic sender re-defines the same parameter, the traffic sender-specific value
takes precedence before the default value.

Any parameter that can be specified for traffic senders in `[traffic]` section
can also be specified in this section. For example, to override the default
behavior to not use TLS Session Resumption, you can use:

```
[defaults]
[defaults.traffic]
gnutls_priority = "NORMAL:%NO_TICKETS"
```

## [input] section

Optionally specifies how to read input data.

```
[input]
pcap = /path/to/input.pcap
stop_after_s = 600
```

### pcap

Path to PCAP file, overrides value specified by `--read` command line option.
Intended as shortcut when re-running test with the same dataset again and again.

### stop_after_s

Time limit for test, in seconds (integer).
Reading queries from PCAP will stop at first packet with timestamp >= `stop_after_s`.

Defaults to no limit, i.e. read all packets from PCAP.

!!! warning
    Using the `stop_after_s` option negatively impacts DNS Shotgun's read
    performance and slows down PCAP processing by 50 %. If this performance
    penalty is unacceptable, cut the PCAP using external tools and avoid using
    this option.
