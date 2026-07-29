# The Linux x86_64 reproduction image (scripts/linux-repro.sh, `make test-linux`).
#
# WHY THIS EXISTS: the development box is macOS/arm64 and CI is Linux x86_64, and a whole class of
# defects in this stack is invisible on macOS — uninitialized memory that only shows on the wire, a
# teardown that only deadlocks under Linux thread scheduling, a discovery window that is wide enough
# there and not here. Every one of those was found by Linux and none by macOS. This image makes the
# CI platform reachable in ~90 seconds from the dev box instead of one push per experiment.
#
# It deliberately matches what CI runs (Ubuntu + the distro SBCL + Quicklisp), NOT the newest
# available SBCL: the point is to reproduce the platform under test, not a better one.
#
# The traps this file and its launcher exist to encode are documented in scripts/linux-repro.sh.
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

# libsqlite3-dev + libffi-dev: the durability SQLite store and CFFI. build-essential + perl: CFFI
# groveling, and the OpenSSL build below.
RUN apt-get update && apt-get install -y --no-install-recommends \
      sbcl curl ca-certificates libsqlite3-dev libffi-dev build-essential perl \
 && rm -rf /var/lib/apt/lists/*

# OPENSSL >= 3.5, BUILT FROM SOURCE, BECAUSE THE DISTRO'S IS TOO OLD AND THAT SILENTLY HALVED THE SUITE.
# DDS.DARE (CNSA-2.0 Data-At-Rest Encryption) and everything above it — the DDS-Security AccessControl,
# authentication and key-exchange tests — require OpenSSL >= 3.5. Ubuntu 24.04 ships 3.0.x, so
# dds.dare:dare-available-p returned NIL and every one of those tests SKIPPED here while passing on the
# macOS dev box. A Linux run reporting "N passed, 0 FAILED" was not covering the security suite at all,
# which is precisely the shape of blind spot this harness exists to remove.
#
# Installed to its own prefix so the distro libssl the rest of the image links against is untouched;
# DDS_DARE_LIBCRYPTO is the override dds-dare/openssl-ffi.lisp already consults first.
ARG OPENSSL_VERSION=3.5.0
RUN curl -sSLo /tmp/openssl.tar.gz \
      "https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VERSION}/openssl-${OPENSSL_VERSION}.tar.gz" \
 && tar -xzf /tmp/openssl.tar.gz -C /tmp \
 && cd "/tmp/openssl-${OPENSSL_VERSION}" \
 && ./Configure linux-x86_64 shared --prefix=/opt/openssl-3.5 --openssldir=/opt/openssl-3.5/ssl \
 && make -j"$(nproc)" build_sw \
 && make install_sw \
 && cd / && rm -rf /tmp/openssl.tar.gz "/tmp/openssl-${OPENSSL_VERSION}"

ENV DDS_DARE_LIBCRYPTO=/opt/openssl-3.5/lib64/libcrypto.so.3
ENV LD_LIBRARY_PATH=/opt/openssl-3.5/lib64

# Quicklisp into the image, so a container start needs no network.
RUN curl -sSLo /tmp/ql.lisp https://beta.quicklisp.org/quicklisp.lisp \
 && sbcl --non-interactive --load /tmp/ql.lisp \
      --eval '(quicklisp-quickstart:install)' \
      --eval '(ql-util:without-prompting (ql:add-to-init-file))' \
 && rm -f /tmp/ql.lisp

WORKDIR /src
