# Extracting Clients

Once you have the `filtered.pcap` with DNS queries from clients, you can
process them into *pellets* - the pre-processed input files for DNS Shotgun.
All the content of these files will be used during the replay stage - all
clients for the entire duration of the file.

The following example takes the entire `filtered.pcap` and transforms it into
pellets. The pellets file will contain all the clients and it will have the
same duration as the original file.

```
$ pcap/extract-clients.lua -r filtered.pcap -O $OUTPUT_DIR
```

The produced pellets file is ready to be used as the input for DNS Shotgun
replay.

## Splitting original capture into multiple pellets files

It can be useful to have a long original capture file, which contains more
clients and queries. However, since the pellets file will be replayed in its
entirety, you may want to split the original file into multiple pellets files
with shorter duration.

For example, if your initial capture file is 30 minutes long and you could
split it into fifteen two minute pellets files with the `-d/--duration` option.

```
$ pcap/extract-clients.lua -r filtered.pcap -O $OUTPUT_DIR -d 120
```

!!! tip
    Is it useful to keep a collection of these original pellets files of same
    duration. They can be later combined to create different test cases.

## Scaling-up the traffic

If you want to stress-test your infrastructure, you can combine these pellets
files together to effectively scale-up the traffic. The pellets files are
created in a way that you can simply use `mergecap` utility to combine them.

```
$ mergecap -w scaled.pcap $OUTPUT_DIR/*
```

!!! warning
    You can only merge chunks that were created with the same duration when
    calling `extract-clients.lua`. Modifying the chunks in other ways, such as
    attempting to shift or extend the traffic, will produce unexpected results.
    For more information, see [this
    discussion](https://gitlab.nic.cz/knot/shotgun/-/merge_requests/32#note_196879).

## Limiting the traffic

It is also possible to take a pellets file and scale-down its traffic. This is
done on a per-client basis. Either client's entire query stream will be
present, or the client won't be present at all.

To limit the overall traffic, you can select the portion of the clients that
should be included. This can range from 0 to 1. For example, let's suppose we
want to scale-down the number of clients in the pellets file to 30 %.

```
$ pcap/limit-clients.lua -r pellets.pcap -w limited.pcap -l 0.3
```
