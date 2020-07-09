FROM ubuntu:focal

ENV DEBIAN_FRONTEND=noninteractive

RUN \
	apt-get update -qq && \
	apt-get install -y -qqq \
		libck-dev \
		libluajit-5.1-dev \
		libpcap-dev \
		liblmdb-dev \
		libgnutls28-dev \
		luajit \
		libuv1-dev \
		libnghttp2-dev \
		libgoogle-perftools-dev \
		make \
		automake \
		libtool \
		pkg-config \
		git && \
	rm -rf /var/lib/apt/lists/*

RUN \
	git clone https://github.com/tomaskrizek/dnsjit.git && \
	cd dnsjit && \
	git checkout https2-dnssim && \
	./autogen.sh && \
	./configure --disable-dependency-tracking && \
	make && \
	cd ..

RUN \
	git clone https://gitlab.labs.nic.cz/knot/shotgun.git && \
	cd shotgun && \
	git checkout tmp-udp-shotgun && \
	cd ..

ENTRYPOINT ["dnsjit/src/dnsjit", "shotgun/shotgun.lua"]
