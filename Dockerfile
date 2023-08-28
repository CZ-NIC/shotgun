FROM ubuntu:focal
ENV DEBIAN_FRONTEND=noninteractive
RUN \
	apt-get update -qq && \
	apt-get install -y -qqq software-properties-common && \
	add-apt-repository -y ppa:dns-oarc/dnsjit && \
	apt-get update -qq && \
	apt-get install -y -qqq \
		dnsjit \
		dnsjit-dev \
		python3 \
		python3-pip \
		tshark \
		jq \
		libnghttp2-dev \
		luajit \
		libuv1-dev \
		make \
		cmake \
		ninja-build \
		pkg-config \
		git && \
	rm -rf /var/lib/apt/lists/*

COPY . /shotgun
WORKDIR /shotgun
ENV PATH="${PATH}:/shotgun"
RUN cd replay/dnssim && \
  mkdir build && \
  cd build && \
  cmake .. -DCMAKE_BUILD_TYPE=Release -G Ninja && \
  cmake --build . && \
  cmake --install . && \
  cd /shotgun
RUN pip3 install -r requirements.txt
