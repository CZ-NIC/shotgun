ARG BASE_IMAGE=ubuntu:22.04
FROM $BASE_IMAGE AS runtime_base
MAINTAINER Petr Spacek <pspacek@isc.org>
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update -q
RUN apt-get upgrade -y -q
# required for PPA repo usage
RUN apt-get install -y -q -o APT::Install-Suggests=0 -o APT::Install-Recommends=0 \
	ca-certificates \
	lsb-release

# avoid PGP; keyring download here would have dependency on TLS anyway
# and I don't want to hardcode PGP key ID here
RUN echo "deb [trusted=yes] https://ppa.launchpadcontent.net/dns-oarc/dnsjit/ubuntu `lsb_release -c -s` main" > /etc/apt/sources.list.d/dns-oarc.list
RUN apt-get update -q

# shotgun's runtime depedencies
RUN apt-get install -y -q -o APT::Install-Suggests=0 -o APT::Install-Recommends=0 \
	dnsjit \
	libnghttp2-14 \
	libuv1 \
	python3 \
	python3-pip

COPY requirements.txt /tmp/requirements.txt
RUN pip3 install -r /tmp/requirements.txt

# separate image for build, will not be tagged at the end
FROM runtime_base AS build_stage
RUN apt-get install -y -q -o APT::Install-Suggests=0 -o APT::Install-Recommends=0 \
	cmake \
	dnsjit-dev \
	g++ \
	gcc \
	git \
	jq \
	libnghttp2-dev \
	libuv1-dev \
	ninja-build \
	pkg-config \
	tshark

COPY . /shotgun
RUN mkdir /shotgun/replay/dnssim/build
WORKDIR /shotgun/replay/dnssim/build
RUN cmake .. -DCMAKE_BUILD_TYPE=Release -G Ninja
RUN cmake --build .
RUN cmake --install .

# copy only installed artifacts, Shotgun repo and throw away everything else
FROM runtime_base AS installed
COPY --from=build_stage /usr/local /usr/local
COPY . /shotgun
WORKDIR /shotgun
ENV PATH="${PATH}:/shotgun"

# cleanup intended for docker build --squash
RUN rm -rf /shotgun/.git
