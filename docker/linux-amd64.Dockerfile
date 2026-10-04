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
# Installed to its own prefix so the distro libssl the rest of the image links against is untouched.
# Pinned to the same release and SHA-256 as scripts/build-openssl.sh (WP-0.8; keep the two in step): the
# build stops on a checksum mismatch. The OpenPGP check lives in that script, not here.
#
# DDS_DARE_LIBCRYPTO is the ONLY variable set: the fail-closed loader (ADR 0123) dlopens that absolute path
# and refuses to run if a second libcrypto is mapped. LD_LIBRARY_PATH is deliberately NOT set, so every other
# program in the image keeps the distro library and nothing pulls the /opt copy in by search path.
ARG OPENSSL_VERSION=3.5.9
ARG OPENSSL_SHA256=603f5602e2eef00d77fbd429d34dcd5822bb301757a1bc9cdb24c670f1eb859a
RUN curl -sSfLo /tmp/openssl.tar.gz \
      "https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VERSION}/openssl-${OPENSSL_VERSION}.tar.gz" \
 && echo "${OPENSSL_SHA256}  /tmp/openssl.tar.gz" | sha256sum -c - \
 && tar -xzf /tmp/openssl.tar.gz -C /tmp \
 && cd "/tmp/openssl-${OPENSSL_VERSION}" \
 && ./Configure linux-x86_64 shared no-docs no-tests --prefix=/opt/openssl-3.5 --openssldir=/opt/openssl-3.5/ssl \
      '-Wl,-rpath,$(LIBRPATH)' \
 && make -j"$(nproc)" build_sw \
 && make install_sw \
 && cd / && rm -rf /tmp/openssl.tar.gz "/tmp/openssl-${OPENSSL_VERSION}"

ENV DDS_DARE_LIBCRYPTO=/opt/openssl-3.5/lib64/libcrypto.so.3

# Quicklisp into the image, so a container start needs no network.
RUN curl -sSLo /tmp/ql.lisp https://beta.quicklisp.org/quicklisp.lisp \
 && sbcl --non-interactive --load /tmp/ql.lisp \
      --eval '(quicklisp-quickstart:install)' \
      --eval '(ql-util:without-prompting (ql:add-to-init-file))' \
 && rm -f /tmp/ql.lisp

WORKDIR /src
