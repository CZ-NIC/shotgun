FROM ubuntu:focal
ENV DEBIAN_FRONTEND=noninteractive
RUN \
	apt-get update -qq && \
	apt-get install -y -qqq \
		python3 \
		python3-pip \
		tshark \
		jq \
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
	make install && \
	cd ..

COPY . /shotgun
WORKDIR /shotgun
ENV PATH="${PATH}:/shotgun"
RUN pip3 install -r requirements.txt
