#!/usr/bin/env bash
# Build the pinned OpenSSL 3.5 LTS release that DDS.DARE and DDS-Security load (WP-0.8, ADR 0123).
#
# Why a private build: DARE needs OpenSSL >= 3.5.0 for ML-KEM-1024 (FIPS 203, CNSA 2.0), and the Linux
# reference host ships 3.0.13. The build goes into a user prefix and is loaded by ABSOLUTE PATH through
# DDS_DARE_LIBCRYPTO (scripts/openssl-env.sh). Nothing here touches LD_LIBRARY_PATH or the system library,
# so interop peers, tshark and AllegroCL's own aclssl modules keep the system libcrypto.
#
# Usage:   scripts/build-openssl.sh            # build + install (idempotent: a matching stamp is a no-op)
#          scripts/build-openssl.sh --print-prefix
# Env:     DDS_OPENSSL_PREFIX     install prefix   (default $HOME/.local/opt/openssl-3.5)
#          DDS_OPENSSL_CACHE      tarball cache    (default ${XDG_CACHE_HOME:-$HOME/.cache}/neodds/openssl)
#          DDS_OPENSSL_REQUIRE_PGP=1   fail when the OpenPGP signature cannot be checked (gpg absent or the
#                                      release keys unobtainable). Default: SHA-256 is mandatory, OpenPGP is
#                                      checked whenever gpg is present, and a check that RUNS and fails is
#                                      always fatal.
#          DDS_OPENSSL_JOBS       parallel make jobs (default: nproc)
#
# Integrity pins (recorded 2026-10-04, docs/provenance.md):
#   * SHA-256 below is the value published both at
#     https://github.com/openssl/openssl/releases/download/openssl-3.5.9/openssl-3.5.9.tar.gz.sha256 and at
#     https://www.openssl.org/source/openssl-3.5.9.tar.gz.sha256 (identical), and was recomputed locally.
#   * The detached signature openssl-3.5.9.tar.gz.asc is made by signing subkey
#     C46E D3F2 CBEF DA1F DAAD A442 64ED 7B1D CCE7 1CB2 of the OpenSSL release certificate
#     B146 647E 45A7 B339 47AB 226B 2A2C 87D1 6169 2D40. That primary fingerprint is the trust anchor named
#     at https://openssl-library.org/source/, is served by keys.openpgp.org, and is cross-certified by the
#     previous release key BA54 73A2 B058 7B07 FB27 CF2D 2160 94DF D0CB 81EF. The script imports the
#     published key bundle into a throw-away GNUPGHOME and accepts the signature ONLY if gpg reports a good
#     signature whose primary-key fingerprint equals the pin.
set -euo pipefail

OPENSSL_VERSION="3.5.9"
OPENSSL_SHA256="603f5602e2eef00d77fbd429d34dcd5822bb301757a1bc9cdb24c670f1eb859a"
OPENSSL_PGP_PRIMARY_FPR="B146647E45A7B33947AB226B2A2C87D161692D40"
OPENSSL_TARBALL="openssl-${OPENSSL_VERSION}.tar.gz"
OPENSSL_URL="https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VERSION}/${OPENSSL_TARBALL}"
OPENSSL_KEYS_URL="https://openssl-library.org/source/pubkeys.asc"

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PREFIX="${DDS_OPENSSL_PREFIX:-$HOME/.local/opt/openssl-3.5}"
CACHE="${DDS_OPENSSL_CACHE:-${XDG_CACHE_HOME:-$HOME/.cache}/neodds/openssl}"
JOBS="${DDS_OPENSSL_JOBS:-$(nproc 2>/dev/null || echo 4)}"
STAMP="${PREFIX}/.neodds-openssl-stamp"
STAMP_TEXT="version=${OPENSSL_VERSION} sha256=${OPENSSL_SHA256}"

if [[ "${1:-}" == "--print-prefix" ]]; then echo "$PREFIX"; exit 0; fi

log() { echo "build-openssl: $*" >&2; }
die() { echo "build-openssl: ERROR: $*" >&2; exit 1; }

if [[ -f "$STAMP" ]] && [[ "$(cat "$STAMP")" == "$STAMP_TEXT" ]]; then
  log "OpenSSL ${OPENSSL_VERSION} already installed at ${PREFIX} (stamp matches); nothing to do"
  exit 0
fi

# Ownership guard, checked before any download or build (the install section below explains it).
owned_prefix() { [[ -f "${PREFIX}/.neodds-openssl-stamp" || -f "${PREFIX}/.neodds-openssl-provenance" ]]; }
if [[ -e "$PREFIX" ]]; then
  [[ -d "$PREFIX" ]] || die "${PREFIX} exists and is not a directory; refusing to replace it"
  if [[ -n "$(ls -A "$PREFIX")" ]] && ! owned_prefix; then
    die "${PREFIX} is not empty and was not installed by this script (no .neodds-openssl-stamp or .neodds-openssl-provenance); refusing to delete it. Choose another DDS_OPENSSL_PREFIX or empty that directory yourself."
  fi
fi

mkdir -p "$CACHE"
TARBALL="${CACHE}/${OPENSSL_TARBALL}"

# --- fetch (cached) --------------------------------------------------------------------------------------
if [[ ! -f "$TARBALL" ]]; then
  log "fetching ${OPENSSL_URL}"
  curl -sSfL --retry 3 -o "${TARBALL}.part" "$OPENSSL_URL"
  mv "${TARBALL}.part" "$TARBALL"
fi

# --- SHA-256: mandatory -----------------------------------------------------------------------------------
actual="$(sha256sum "$TARBALL" | cut -d' ' -f1)"
if [[ "$actual" != "$OPENSSL_SHA256" ]]; then
  rm -f "$TARBALL"
  die "SHA-256 mismatch for ${OPENSSL_TARBALL}: expected ${OPENSSL_SHA256}, got ${actual} (tarball removed)"
fi
log "SHA-256 verified: ${actual}"

# --- OpenPGP: checked whenever possible, fatal when it runs and fails --------------------------------------
pgp_status="NOT VERIFIED"
if command -v gpg >/dev/null 2>&1; then
  gnupg="$(mktemp -d)"
  trap 'rm -rf "$gnupg" "${BUILD_DIR:-}"' EXIT
  chmod 700 "$gnupg"
  if curl -sSfL --retry 3 -o "${gnupg}/pubkeys.asc" "$OPENSSL_KEYS_URL" \
     && curl -sSfL --retry 3 -o "${gnupg}/sig.asc" "${OPENSSL_URL}.asc"; then
    GNUPGHOME="$gnupg" gpg --batch --quiet --import "${gnupg}/pubkeys.asc" 2>/dev/null || true
    # --status-fd gives machine-readable lines: VALIDSIG <subkey-fpr> ... <primary-fpr> is the last field.
    if status="$(GNUPGHOME="$gnupg" gpg --batch --status-fd 1 --verify "${gnupg}/sig.asc" "$TARBALL" 2>/dev/null)"; then
      primary="$(awk '$2=="VALIDSIG"{print $NF}' <<<"$status")"
      if [[ "$primary" == "$OPENSSL_PGP_PRIMARY_FPR" ]]; then
        pgp_status="VERIFIED (primary ${primary})"
      else
        die "OpenPGP signature is valid but made by primary key '${primary}', not the pinned ${OPENSSL_PGP_PRIMARY_FPR}"
      fi
    else
      die "OpenPGP signature verification FAILED for ${OPENSSL_TARBALL}"
    fi
  else
    log "could not fetch the release keys or the signature; OpenPGP not checked"
  fi
else
  log "gpg not found; OpenPGP not checked"
fi
if [[ "$pgp_status" == "NOT VERIFIED" && "${DDS_OPENSSL_REQUIRE_PGP:-0}" == "1" ]]; then
  die "DDS_OPENSSL_REQUIRE_PGP=1 but the OpenPGP signature could not be checked"
fi
log "OpenPGP: ${pgp_status}"

# --- build -------------------------------------------------------------------------------------------------
BUILD_DIR="$(mktemp -d)"
trap 'rm -rf "${gnupg:-}" "$BUILD_DIR"' EXIT
tar -xzf "$TARBALL" -C "$BUILD_DIR"
cd "${BUILD_DIR}/openssl-${OPENSSL_VERSION}"

# Reproducibility: pin the embedded build date to the release signature's creation time (1790690724 =
# 2026-09-29T14:05:24Z, read from the .asc signature packet) so a rebuild of the same pin embeds the same date.
export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-1790690724}"

# shared:  libcrypto.so.3 is what DDS.DARE dlopens. no-docs/no-tests: install the libraries only (INSTALL.md
# "no-docs", "no-tests"). The rpath idiom is NOTES-UNIX.md "Shared libraries and installation in
# non-default locations": it lets $PREFIX/bin/openssl find ITS libcrypto without LD_LIBRARY_PATH.
log "configuring for ${PREFIX}"
./Configure --prefix="$PREFIX" --openssldir="${PREFIX}/ssl" \
  shared no-docs no-tests \
  '-Wl,-rpath,$(LIBRPATH)' >"${BUILD_DIR}/configure.log" 2>&1 \
  || { tail -40 "${BUILD_DIR}/configure.log" >&2; die "Configure failed"; }

log "building with ${JOBS} jobs"
make -j"$JOBS" >"${BUILD_DIR}/build.log" 2>&1 || { tail -60 "${BUILD_DIR}/build.log" >&2; die "make failed"; }

# --- install: stage beside PREFIX, verify, then swap into place ------------------------------------------
# PREFIX comes from the environment, so it is never deleted unless this script owns it: an existing non-empty
# PREFIX must carry this script's stamp or provenance file, otherwise the run stops before touching anything
# (a mistyped DDS_OPENSSL_PREFIX=$HOME/.local must not wipe a tree). The install goes into a staging directory
# next to PREFIX (same filesystem, so the swap is a rename); the self-checks run on the swapped-in tree, and
# if one fails the previous install is put back, so a failed upgrade never leaves a half-installed PREFIX.
PARENT="$(dirname "$PREFIX")"
mkdir -p "$PARENT"
STAGE="$(mktemp -d "${PARENT}/.neodds-openssl-stage.XXXXXX")"
OLD=""
cleanup() {
  rm -rf "${gnupg:-}" "$BUILD_DIR" "$STAGE"
  [[ -n "$OLD" && -d "$OLD" ]] && rm -rf "$OLD"
  return 0
}
trap cleanup EXIT
make DESTDIR="$STAGE" install_sw install_ssldirs >"${BUILD_DIR}/install.log" 2>&1 \
  || { tail -40 "${BUILD_DIR}/install.log" >&2; die "make install failed"; }
[[ -d "${STAGE}${PREFIX}" ]] || die "staged install missing ${STAGE}${PREFIX}"
# Mark the tree as ours BEFORE it lands at PREFIX, so an interrupted run leaves a PREFIX a rerun may replace.
echo "status=installing version=${OPENSSL_VERSION}" >"${STAGE}${PREFIX}/.neodds-openssl-provenance"

if [[ -e "$PREFIX" ]]; then
  OLD="${PARENT}/.neodds-openssl-old.$$"
  mv "$PREFIX" "$OLD"
fi
mv "${STAGE}${PREFIX}" "$PREFIX"
rollback() {
  rm -rf "$PREFIX"
  if [[ -n "$OLD" && -d "$OLD" ]]; then mv "$OLD" "$PREFIX"; OLD=""; log "previous install restored at ${PREFIX}"; fi
  die "$*"
}

# --- post-install self-check (on the swapped-in tree, so bin/openssl uses its real rpath) -----------------
lib=""
for d in lib64 lib; do
  [[ -f "${PREFIX}/${d}/libcrypto.so.3" ]] && { lib="${PREFIX}/${d}/libcrypto.so.3"; break; }
done
[[ -n "$lib" ]] || rollback "install finished but no libcrypto.so.3 under ${PREFIX}/{lib64,lib}"
ver="$("${PREFIX}/bin/openssl" version)" || rollback "installed openssl does not run"
[[ "$ver" == "OpenSSL ${OPENSSL_VERSION} "* ]] || rollback "installed openssl reports '${ver}', expected ${OPENSSL_VERSION}"
"${PREFIX}/bin/openssl" list -kem-algorithms 2>/dev/null | grep -q "ML-KEM-1024" \
  || rollback "installed OpenSSL does not list ML-KEM-1024"

# OSSL_PARAM layout: src/dds-dare/openssl-ffi.lisp writes OSSL_PARAM slots by hand (+OSSL-PARAM-SIZE+ and the
# offsets in %SET-OSSL-PARAM-SLOT, the +OSSL-PARAM-DATA-TYPE-*+ selectors). Probe them from THIS install's
# <openssl/core.h> and refuse an install whose layout differs from what the Lisp code assumes.
EXPECTED_LAYOUT="sizeof=40 key=0 data_type=8 data=16 data_size=24 return_size=32 INTEGER=1 UNSIGNED_INTEGER=2 UTF8_STRING=4 OCTET_STRING=5"
cc -I"${PREFIX}/include" -o "${BUILD_DIR}/ossl-param-layout" "${REPO}/scripts/probes/ossl-param-layout.c" \
  || rollback "could not compile the OSSL_PARAM layout probe"
layout="$("${BUILD_DIR}/ossl-param-layout")" || rollback "the OSSL_PARAM layout probe failed to run"
[[ "${layout#* }" == "$EXPECTED_LAYOUT" ]] \
  || rollback "OSSL_PARAM layout '${layout}' differs from the layout openssl-ffi.lisp assumes: '${EXPECTED_LAYOUT}'"
log "OSSL_PARAM layout probe: ${layout}"

echo "$STAMP_TEXT" >"$STAMP"
{
  echo "version=${OPENSSL_VERSION}"
  echo "sha256=${OPENSSL_SHA256}"
  echo "pgp=${pgp_status}"
  echo "libcrypto=${lib}"
  echo "ossl_param_layout=${layout}"
  echo "built=$(date -u +%Y-%m-%dT%H:%M:%SZ) host=$(uname -m) cc=$(cc --version | head -1)"
} >"${PREFIX}/.neodds-openssl-provenance"
log "installed ${ver} at ${PREFIX}; libcrypto=${lib}"
log "now: source scripts/openssl-env.sh"
