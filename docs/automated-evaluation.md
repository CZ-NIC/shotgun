# Automated Evaluation

In some cases, like automated testing in CI or performance monitoring, it is
useful to get a yes or no answer to the question of "Did the DNS Shotgun results
(aka resolver performance) change compared to some other version / conditions /
configuration etc.?"

When doing this sort of comparative testing, it is essential to change just a
single condition in your test environment, while keeping everything else the
same. E.g. test a different version of the software, but with the same
configuration, hardware and network environment, traffic load, used protocols
etc.

The [BIND 9](https://gitlab.isc.org/isc-projects/bind9) project uses DNS Shotgun
extensively to check resolver performance during development and it's integrated
into their CI. The code is available from the
[bind9-shotgun-ci](https://gitlab.isc.org/isc-projects/bind9-shotgun-ci)
repository.

The most useful script is the `evaluate-results.py`, which is used to
automatically evaluate whether a DNS Shotgun performance test with a new code
change yields different results from a baseline DNS Shotgun performance test of
a known working version. You might need to tweak the script for your needs,
since it also compares data from a related
[resource-monitor](https://gitlab.isc.org/isc-projects/resource-monitor)
project, which is used to capture CPU usage, memory consumption and other
metrics during the DNS Shotgun performance test.
