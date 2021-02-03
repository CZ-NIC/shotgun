# Installation

There are two options for using DNS Shotgun. You can either install the
dependencies and use the scripts from the repository directly, or use a
pre-built docker image.

## Using script directly

You can use the toolchain scripts directly from the git repository. You need to
ensure you have the required dependencies installed. Also make sure to check
out some tagged version, as the development happens in master branch.

```
$ git clone https://gitlab.nic.cz/knot/shotgun.git
$ git checkout v20210203
```

### Dependencies

When using the scripts directly, the following dependencies are needed. If you
only wish to process shotgun JSON output (e.g. plot charts), then dnsjit isn't
required.

- [dnsjit](https://github.com/DNS-OARC/dnsjit): Can be installed from [DNS-OARC
  repositories](https://dev.dns-oarc.net/packages/).
- Python 3.6 or later
- Python dependencies from [requirements.txt](https://gitlab.nic.cz/knot/shotgun/-/blob/master/requirements.txt)
- (optional) tshark/wireshark for some PCAP pre-processing

## Docker Image

Pre-built image can be obtained from [CZ.NIC DNS Shotgun
Registry](https://gitlab.nic.cz/knot/shotgun/container_registry/65).

```
$ docker pull registry.nic.cz/knot/shotgun:v20210203
```

Alternately, you can build the image yourself from Dockerfile in the repository.

### Docker Usage

- Make sure to run with `--network host`.
- Mount input/output directories and files with `-v/--volume`.
- Using `--privileged` might slightly improve performance if you don't mind the security risk.

```
$ docker run \
    --network host \
    -v "$PWD:/mnt" \
    registry.nic.cz/knot/shotgun:v20210203 \
    $COMMAND
```
