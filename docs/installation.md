# Installation

TODO re-write based on dnsjit release

Currently, there are two options for using DNS Shotgun: docker image, or
directly using the source files and compiling the needed dependencies.

## Docker Image

Pre-built image can be obtained from [CZ.NIC DNS Shotgun
Registry](https://gitlab.nic.cz/knot/shotgun/container_registry/65).

```
docker pull registry.nic.cz/knot/shotgun:vTODO
```

Alternately, you can build the image yourself from Dockerfile in the repository.

### Docker Usage

- Make sure to run with `--network host`.
- Mount input/output directories and files with `-v/--volume`.
- Using `--privileged` might slightly improve performance if you don't mind the security risk.

```
docker run \
  --network host \
  -v "$PWD:/mnt" \
  registry.nic.cz/knot/shotgun:vTODO \
  $COMMAND
```

## Sources

You can also use the toolchain scripts directly from the git repository. You
need to ensure you have the required dependencies installed.

```
git clone https://gitlab.nic.cz/knot/shotgun.git
```

### Dependencies

When using the scripts directly, the following dependencies are needed. If you
only wish to process shotgun JSON output (e.g. plot charts), then dnsjit isn't
required.

- [dnsjit](https://github.com/DNS-OARC/dnsjit): Version **newer than 1.0.0** is
  required for proper operation. Currently, no such packages are available and
  it needs to be compiled from sources, refer to dnsjit README for
  instructions.
- Python 3.6 or later
- Python dependencies from [requirements.txt](https://gitlab.nic.cz/knot/shotgun/-/blob/master/requirements.txt)
- (optional) tshark/wireshark for some PCAP pre-processing
