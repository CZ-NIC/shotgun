# Raw Output

In the output directory of DNS Shotgun's `replay.py` tool, the following
structure is created. Let's assume we ran a configuration that configure two
traffic senders - `DoT` and `DoH`.

```
$OUTDIR
├── .config               # ignore this directory
│   └── luaconfig.lua     # for debugging purposes only
├── data                  # directory with raw JSON output
│   ├── DoH               # "DoH" traffic sender data
│   │   ├── DoH-01.json   # raw data from first thread of DoH traffic sender
│   │   ├── DoH-02.json   # raw data from second thread of DoH traffic sender
│   │   └── ...           # raw data from other threads of DoH traffic sender
│   ├── DoH.json          # merged raw data from all DoH sender threads
│   ├── DoT               # "DoT" traffic sender data
│   │   ├── DoT-01.json   # raw data from first thread of DoT traffic sender
│   │   ├── DoT-02.json   # raw data from second thread of DoT traffic sender
│   │   └── ...           # raw data from other threads of DoT traffic sender
│   └── DoT.json          # merged raw data from all DoT sender threads
└── charts                # directory with automatically plotted charts (if configured)
    ├── latency.svg       # chart comparing latency of DoT and DoH clients
    └── response-rate.svg # chart comparing the response rate of DoT and DoH clients
```

## data directory

This directory contains the raw JSON data. Since DNS Shotgun typically operates
with multiple threads, the results for each traffic sender are also provided
per each thread. However, since you typically don't care about the clients were
emulated, but only about their aggregate behaviour, a data file that contains
the combined results of all threads belonging to the configured traffic sender
is also provided.

Every configured traffic sender will have its own output directory of the same
name. Inside, per-thread raw data are available. The aggregate file is directly
in the `data/` directory as JSON file with the name of the configured traffic
sender. The aggregate file is the one you typically want to use.

!!! note
    The raw JSON file is versioned and is not intended to be forward or
    backward compatible with various DNS Shotgun versions. You should use the
    same version of the toolchain for both replay and interpreting the data.

!!! tip
    If you wish to explore, format or interpret the raw JSON data,
    [jq](https://stedolan.github.io/jq/) utility can be useful for some
    rudimentary processing.

## charts directory

This directory may not be present if you didn't configure any charts to be
automatically plotted in the configuration file. If it is available, it
contains the plotted charts that are described in the following sections.

When charts are plotted automatically, they always display data for all the
configure traffic senders with their predefined names. If you wish to customize
it, omit certain senders etc., you can use the plotting scripts
directly from CLI. These can be found in the `tools/` directory and you can
refer to their `--help` for usage.
