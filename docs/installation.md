# Installation

There are two options for using DNS Shotgun. You can either use a pre-built
docker image, or install the dependencies, compile the dnssim module and use
the scripts from the repository directly.

## Docker Image

Pre-built image can be obtained from [CZ.NIC DNS Shotgun
Registry](https://gitlab.nic.cz/knot/shotgun/container_registry/65).

```
$ docker pull registry.nic.cz/knot/shotgun:v20210714
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
    registry.nic.cz/knot/shotgun:v20210714 \
    $COMMAND
```

## Using scripts from sources

You can use the toolchain scripts directly from the git repository. You need to
ensure you have the required dependencies installed and the compile and install
the dnssim module. Also make sure to check out some tagged version, as the
development happens in master branch.

```
$ git clone https://gitlab.nic.cz/knot/shotgun.git
$ git checkout v20210714
$ git submodule update --init --recursive
$ cd shotgun/replay/dnssim
$ mkdir build && cd build
$ cmake ..
$ cmake --build .
$ sudo cmake --install .
```

### Dependencies

When using the scripts directly, the following dependencies are needed.

If you only wish to process shotgun JSON output (e.g. plot charts), then dnsjit
and compiling the dnssim module isn't required.

- [dnsjit 1.2+](https://github.com/DNS-OARC/dnsjit): Can be installed from [DNS-OARC
  repositories](https://dev.dns-oarc.net/packages/).
- libuv
- libnghttp2

- Python 3.6 or later
- Python dependencies from [requirements.txt](https://gitlab.nic.cz/knot/shotgun/-/blob/master/requirements.txt)
- (optional) tshark/wireshark for some PCAP pre-processing
