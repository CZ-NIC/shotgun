FROM ubuntu:focal
ARG SHOTGUN_VERSION=v20200914

ENV DEBIAN_FRONTEND=noninteractive

RUN \
	apt-get update -qq && \
	apt-get install -y -qqq \
		python3-pip \
		git && \
	rm -rf /var/lib/apt/lists/*

RUN pip3 install dnspython
RUN pip3 install git+git://github.com/kbandla/dpkt.git@2c6aada35c38c93061ac6d4c47862174ffcc4799

RUN git clone -b $SHOTGUN_VERSION --depth=1 https://gitlab.labs.nic.cz/knot/shotgun.git

ENTRYPOINT ["shotgun/pellet.py"]
