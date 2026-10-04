# shellcheck shell=bash
# Source me:  . scripts/openssl-env.sh
#
# Points DDS.DARE / DDS-Security at the pinned OpenSSL 3.5 build from scripts/build-openssl.sh
# (WP-0.8, ADR 0123). It exports EXACTLY ONE variable, DDS_DARE_LIBCRYPTO, holding the absolute path of that
# build's libcrypto.so.3. It deliberately does NOT touch LD_LIBRARY_PATH (or LD_PRELOAD): the library is
# dlopen()ed by absolute path, so every other process started from this shell (interop peers, tshark,
# AllegroCL's own aclssl modules) keeps the system libcrypto, and a second libcrypto is never pulled into a
# NeoDDS process by the search path. The loader is fail-closed (ADR 0123): once this variable is set, a
# missing or wrong library is a hard load error, never a fallback to the system copy.
#
# The prefix is read from DDS_OPENSSL_PREFIX (default $HOME/.local/opt/openssl-3.5) but not exported.
# Sourcing fails (return 1) with a message when the build is absent, so `. scripts/openssl-env.sh && make test`
# never silently runs against the system library.

__dds_ossl_prefix="${DDS_OPENSSL_PREFIX:-$HOME/.local/opt/openssl-3.5}"
__dds_ossl_lib=""
for __dds_ossl_d in lib64 lib; do
  if [ -f "${__dds_ossl_prefix}/${__dds_ossl_d}/libcrypto.so.3" ]; then
    __dds_ossl_lib="${__dds_ossl_prefix}/${__dds_ossl_d}/libcrypto.so.3"
    break
  fi
done

if [ -z "$__dds_ossl_lib" ]; then
  echo "openssl-env: no libcrypto.so.3 under ${__dds_ossl_prefix}/{lib64,lib}; run scripts/build-openssl.sh first" >&2
  unset __dds_ossl_prefix __dds_ossl_lib __dds_ossl_d
  return 1 2>/dev/null || exit 1
fi

DDS_DARE_LIBCRYPTO="$(readlink -f "$__dds_ossl_lib")"
export DDS_DARE_LIBCRYPTO
unset __dds_ossl_prefix __dds_ossl_lib __dds_ossl_d
