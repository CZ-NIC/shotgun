ARG DNSJIT_VERSION
ARG CI_REGISTRY=registry.nic.cz
FROM $CI_REGISTRY/knot/knot-resolver/ci/debian-11:knot-3.0

ENV DNSJIT_VERSION=${DNSJIT_VERSION:-1.2.3}

RUN apt-get update && \
    apt-get install -y libpcap-dev libck-dev

RUN wget "https://github.com/DNS-OARC/dnsjit/archive/refs/tags/v${DNSJIT_VERSION}.tar.gz" \
    --output-document 'dnsjit.tar.gz' && \
    tar -xzf dnsjit.tar.gz
WORKDIR dnsjit-${DNSJIT_VERSION}
RUN sh autogen.sh && \
    ./configure --prefix=/usr && \
    make && \
    make install