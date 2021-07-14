FROM ubuntu:focal
ENV DEBIAN_FRONTEND=noninteractive
RUN \
	apt-get update -qq && \
	apt-get install -y -qqq software-properties-common && \
	add-apt-repository -y ppa:dns-oarc/dnsjit && \
	apt-get update -qq && \
	apt-get install -y -qqq \
		dnsjit-dev \
		python3 \
		python3-pip \
		tshark \
		jq \
		libnghttp2-dev \
		luajit \
		libuv1-dev \
		make \
		automake \
		libtool \
		pkg-config \
		git && \
	rm -rf /var/lib/apt/lists/*

COPY . /shotgun
WORKDIR /shotgun
ENV PATH="${PATH}:/shotgun"
RUN cd replay/dnssim && \
  ./autogen.sh && \
  ./configure && \
  make && \
  make install && \
  cd ../..
RUN pip3 install -r requirements.txt
