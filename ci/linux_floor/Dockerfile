# Build only CPython; both stages use the same digest-pinned Bullseye userland.
ARG BASE_IMAGE
FROM ${BASE_IMAGE} AS cpython
# CPython xz SHA-256 independently checked against docker-library/python
# 3a144d79062aa1f59d2e4e99fc96aec3b5871e72 (versions.json).
ARG CPYTHON_VERSION=3.14.10
ARG CPYTHON_SHA256=de414a57119abef52784d8993e341d53aed635fc2b05c2607d9f98a2c5b72032
ARG TARGETARCH
# Python 3.14's compression.zstd needs development headers. Use only the
# headers from the matching Bullseye package; link to the original system .so.1.
RUN set -eux; \
    test "$(getconf GNU_LIBC_VERSION)" = 'glibc 2.31'; \
    zstd_version='1.4.8+dfsg-2.1'; \
    case "$TARGETARCH" in \
      amd64) zstd_sha=d95e92c8b24e36e5f230a645e447dd6b951e4eea9226c8f2a1d7cf8adbb7c4e1 ;; \
      arm64) zstd_sha=518ac362ce66e842281e0bf2565715cedff1d1047a0970dae6f09bfde51594a7 ;; \
      *) exit 2 ;; \
    esac; \
    test "$(dpkg-query -W -f='${Version}' libzstd1)" = "$zstd_version"; \
    curl --fail --silent --show-error --location --retry 3 --proto '=https' \
        "https://deb.debian.org/debian/pool/main/libz/libzstd/libzstd-dev_${zstd_version}_${TARGETARCH}.deb" \
        --output /tmp/zstd-dev.deb; \
    echo "${zstd_sha}  /tmp/zstd-dev.deb" | sha256sum --check --strict; \
    dpkg-deb --extract /tmp/zstd-dev.deb /tmp/zstd-dev; \
    curl --fail --silent --show-error --location --retry 3 --proto '=https' \
        "https://www.python.org/ftp/python/${CPYTHON_VERSION}/Python-${CPYTHON_VERSION}.tar.xz" \
        --output /tmp/python.tar.xz; \
    echo "${CPYTHON_SHA256}  /tmp/python.tar.xz" | sha256sum --check --strict; \
    mkdir /tmp/cpython; \
    tar -xJf /tmp/python.tar.xz --strip-components=1 -C /tmp/cpython; \
    cd /tmp/cpython; \
    LIBZSTD_CFLAGS=-I/tmp/zstd-dev/usr/include LIBZSTD_LIBS=-l:libzstd.so.1 \
        ./configure --prefix=/opt/cpython --with-ensurepip=install; \
    make -j "$(nproc)"; \
    make install; \
    /opt/cpython/bin/python3.14 -I -c 'import bz2, ctypes, lzma, sqlite3, ssl, zlib; from compression import zstd; assert zstd.decompress(zstd.compress(b"floor")) == b"floor"; print(ssl.OPENSSL_VERSION)'; \
    printf '%s  %s\n%s  %s\n' "$CPYTHON_SHA256" "Python-$CPYTHON_VERSION.tar.xz" \
        "$zstd_sha" "libzstd-dev_${zstd_version}_${TARGETARCH}.deb (headers only)" > /opt/cpython/qualification-source.txt

FROM ${BASE_IMAGE}
COPY --from=cpython /opt/cpython /opt/cpython
