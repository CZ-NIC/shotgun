FROM ubuntu:focal
ARG SHOTGUN_VERSION=v20200914

ENV DEBIAN_FRONTEND=noninteractive

RUN \
	apt-get update -qq && \
	apt-get install -y -qqq \
		libck-dev \
		libluajit-5.1-dev \
		libpcap-dev \
		liblmdb-dev \
		libgnutls28-dev \
		libnghttp2-dev \
		luajit \
		libuv1-dev \
		libgoogle-perftools-dev \
		make \
		automake \
		libtool \
		pkg-config \
		git && \
	rm -rf /var/lib/apt/lists/*

RUN \
	git clone https://github.com/DNS-OARC/dnsjit.git && \
	cd dnsjit && \
	./autogen.sh && \
	./configure --disable-dependency-tracking && \
	make && \
	cd ..

RUN \
	git clone -b $SHOTGUN_VERSION --depth=1 \
	https://gitlab.labs.nic.cz/knot/shotgun.git

ENTRYPOINT ["dnsjit/src/dnsjit", "shotgun/shotgun.lua"]
