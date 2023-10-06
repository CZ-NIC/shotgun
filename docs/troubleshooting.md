# Troubleshooting

## failed to send udp packet: too many open files

Increase the number of file descriptors. (See
[`man limits.conf`](https://www.man7.org/linux/man-pages/man5/limits.conf.5.html)
and/or `ulimit --help`)

## fatal: aborting, real time drifted ahead of simulated time

This happens when DNS Shotgun can't keep up with the traffic it's supposed to
send/receive. The tool attempts to keep realistic timing from the original data
and it just aborts it if fails to keep that promise. This can have multiple
causes.

- You're pushing the tool beyond the limits of what it can do, e.g.:
    - Not enough computing power (are all CPUs utilized?)
    - Insufficient network throughput (is network tuned properly? are there enough source IPs?)
    - Unresponsive resolver and/or too high `timeout_s`
- NIC interrupts aren't properly distributed among CPUs
- A single thread is assigned too much traffic
    - This typically shouldn't be the case, but if specific traffic sender is
      *always* causing this failure, tweaking `cpu_factor` and/or number of
      threads might help

## critical: buffer capacity exceeded, threads are blocked

This is an indication that a specific thread filled up its buffer and is now
causing the entire tool to slow down which will eventually cause the crash
described above if it goes on for too long. If it only happens for a specific
traffic sender, tweaking `cpu_factor` to change thread distribution could help.

## various warnings

Especially under heavy load, there can occasionally be some warnings.
Sometimes it's a GnuTLS connection error, a mismatched response etc. The general
rule is a few different warnings during heavy load probably isn't something to
be too concerned about. Typically, it's when the output is spammed by the same
warning over and over that you have a problem.
