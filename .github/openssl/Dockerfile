# syntax=docker/dockerfile:1
FROM debian:trixie@sha256:9cc080028c43b27d2074d63a5f9caf7166d731494965616c1a6d2827a004585c AS build
ARG BUILDKIT_SBOM_SCAN_STAGE=true
ARG VERSION
ARG SHA256
SHELL ["/bin/bash", "-o", "pipefail", "-c"]
RUN sed -i -E -e '/^# http:\/\/snapshot\.debian\.org\//{s/^# //;h;d}' -e '/^URIs: /{g;s/^/URIs: /}' /etc/apt/sources.list.d/debian.sources \
 && ! grep -E '^URIs: ' /etc/apt/sources.list.d/debian.sources | grep -v -E '^URIs: http://snapshot\.debian\.org/archive/' \
 && apt-get -o Acquire::Check-Valid-Until=false update \
 && apt-get install -y --no-install-recommends build-essential=12.12 perl=5.40.1-6+deb13u1 \
 && rm -rf /var/lib/apt/lists/*
ADD --checksum=sha256:${SHA256} https://github.com/openssl/openssl/releases/download/openssl-${VERSION}/openssl-${VERSION}.tar.gz /src/
WORKDIR /src
RUN tar -xzf "openssl-${VERSION}.tar.gz"
WORKDIR /src/openssl-${VERSION}
RUN ./Configure -static --prefix=/usr/local --openssldir=/usr/local/ssl --libdir=lib no-shared no-module no-tests \
 && make -j"$(nproc)" build_sw \
 && make DESTDIR=/out install_sw install_ssldirs

FROM scratch
COPY --from=build /out/usr/local /usr/local
ENV PATH=/usr/local/bin
USER 65534:65534
ENTRYPOINT ["/usr/local/bin/openssl"]
CMD ["version", "-a"]
