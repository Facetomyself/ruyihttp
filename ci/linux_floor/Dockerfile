# Build only CPython; both stages use the same digest-pinned Bullseye userland.
ARG BASE_IMAGE
FROM ${BASE_IMAGE} AS cpython
# CPython xz SHA-256 independently checked against docker-library/python
# 3a144d79062aa1f59d2e4e99fc96aec3b5871e72 (versions.json).
ARG CPYTHON_VERSION=3.14.10
ARG CPYTHON_SHA256=de414a57119abef52784d8993e341d53aed635fc2b05c2607d9f98a2c5b72032
RUN set -eux; \
    test "$(getconf GNU_LIBC_VERSION)" = 'glibc 2.31'; \
    curl --fail --silent --show-error --location --retry 3 --proto '=https' \
        "https://www.python.org/ftp/python/${CPYTHON_VERSION}/Python-${CPYTHON_VERSION}.tar.xz" \
        --output /tmp/python.tar.xz; \
    echo "${CPYTHON_SHA256}  /tmp/python.tar.xz" | sha256sum --check --strict; \
    mkdir /tmp/cpython; \
    tar -xJf /tmp/python.tar.xz --strip-components=1 -C /tmp/cpython; \
    cd /tmp/cpython; \
    ./configure --prefix=/opt/cpython --with-ensurepip=install; \
    make -j "$(nproc)"; \
    make install; \
    /opt/cpython/bin/python3.14 -I -c 'import bz2, ctypes, lzma, sqlite3, ssl, zlib; from compression import zstd; assert zstd.decompress(zstd.compress(b"floor")) == b"floor"; print(ssl.OPENSSL_VERSION)'; \
    printf '%s  %s\n' "$CPYTHON_SHA256" "Python-$CPYTHON_VERSION.tar.xz" > /opt/cpython/qualification-source.txt

FROM ${BASE_IMAGE}
COPY --from=cpython /opt/cpython /opt/cpython
