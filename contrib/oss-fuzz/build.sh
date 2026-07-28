#!/bin/bash -eu
#
# OSS-Fuzz build script for GNU libmicrohttpd.
#
# This file is in the public domain.
#
# It is executed inside the OSS-Fuzz base-builder image, which exports:
#
#   $SRC                 parent directory of the checked-out sources
#                        ($SRC/libmicrohttpd, see Dockerfile)
#   $WORK                scratch directory for build artifacts
#   $OUT                 where the finished fuzz targets must be installed
#   $CC $CXX             the instrumented compilers
#   $CFLAGS $CXXFLAGS    sanitizer + coverage flags; MUST be honoured and
#                        MUST NOT be replaced
#   $LIB_FUZZING_ENGINE  the fuzzing engine to link against ("-fsanitize=fuzzer",
#                        a path to libFuzzingEngine.a, the AFL driver, ...)
#   $SANITIZER           address | undefined | memory | coverage
#   $FUZZING_ENGINE      libfuzzer | afl | honggfuzz | centipede | none
#
# The same script can be run outside OSS-Fuzz for a local smoke test; every
# variable above has a defensive default below.
#
# See contrib/oss-fuzz/README for the full story and for the local
# infra/helper.py recipe.

# ---------------------------------------------------------------------------
# Defaults, so that the script is also runnable by hand
# ---------------------------------------------------------------------------
SRC="${SRC:-$(cd "$(dirname "$0")/../../.." && pwd)}"
WORK="${WORK:-${SRC}/work}"
OUT="${OUT:-${SRC}/out}"
CC="${CC:-clang}"
CXX="${CXX:-clang++}"
CFLAGS="${CFLAGS:--O1 -fno-omit-frame-pointer -gline-tables-only}"
CXXFLAGS="${CXXFLAGS:-${CFLAGS}}"
LIB_FUZZING_ENGINE="${LIB_FUZZING_ENGINE:--fsanitize=fuzzer}"
SANITIZER="${SANITIZER:-address}"

# Directory holding the libmicrohttpd sources.  OSS-Fuzz clones them to
# $SRC/libmicrohttpd (see Dockerfile); allow an override for local runs.
MHD_SRC="${MHD_SRC:-${SRC}/libmicrohttpd}"

# Out-of-tree build directory.  Keeping the build out of the source tree
# means build.sh never modifies the checkout, which matters for the
# "run build.sh twice" and "reproduce against a pristine tree" cases.
BUILD="${WORK}/mhd-build"

FUZZERS="fuzz_request fuzz_str fuzz_auth_header fuzz_postprocessor"

mkdir -p "${WORK}" "${OUT}" "${BUILD}"

echo "=== libmicrohttpd OSS-Fuzz build ==="
echo "    MHD_SRC            = ${MHD_SRC}"
echo "    BUILD              = ${BUILD}"
echo "    OUT                = ${OUT}"
echo "    SANITIZER          = ${SANITIZER}"
echo "    LIB_FUZZING_ENGINE = ${LIB_FUZZING_ENGINE}"

# ---------------------------------------------------------------------------
# 1. Bootstrap (the git checkout ships no 'configure')
# ---------------------------------------------------------------------------
cd "${MHD_SRC}"
if [ ! -x ./configure ]; then
  echo "--- bootstrapping ---"
  # ./bootstrap swallows its own failures (it ends in an '|| echo ...'
  # chain), so its exit status cannot be trusted; check for the product
  # and fall back to autoreconf.
  ./bootstrap || true
  if [ ! -x ./configure ]; then
    autoreconf -fi
  fi
fi

# ---------------------------------------------------------------------------
# 2. Configure
# ---------------------------------------------------------------------------
# Rationale for each flag:
#
#  --enable-static --disable-shared
#        fuzz_str and fuzz_auth_header call MHD-internal symbols
#        (MHD_hex_to_bin(), MHD_get_rq_dauth_params_(), MHD_pool_create(),
#        ...) that are compiled with hidden visibility and are therefore
#        NOT exported from libmicrohttpd.so.  Only the static archive can
#        be linked.  Static linking is also what OSS-Fuzz wants: the
#        target binaries in $OUT must not depend on anything outside $OUT.
#  --with-pic
#        keep the static objects position independent so they can be
#        linked into the (PIE) fuzz targets regardless of compiler default.
#  --enable-fuzzing
#        configures src/fuzz/Makefile.  Not strictly needed here (the
#        harnesses are compiled by hand below) but it keeps this build
#        equivalent to the documented developer build, and it makes
#        configure fail loudly if src/fuzz/ ever stops being wired up.
#  --enable-asserts
#        keeps mhd_assert() alive.  Assertions on attacker-reachable paths
#        are exactly what this campaign is meant to find; without them
#        findings K1-K6 (src/fuzz/README section 6) are invisible.
#  --disable-https
#        deliberate.  The harnesses never speak TLS: they hand MHD an
#        already-connected AF_UNIX socketpair via MHD_add_connection() and
#        never set MHD_USE_TLS.  Enabling HTTPS would (a) add nothing to
#        coverage, (b) drag GnuTLS - which OSS-Fuzz fuzzes separately -
#        into the link, and (c) make the MemorySanitizer build impossible
#        without an MSan-instrumented GnuTLS.  With HTTPS off the only
#        external dependencies are libc and libpthread, so all three
#        sanitizers are usable.
#  --disable-curl
#        the curl-based test suite is not built here and pulling libcurl in
#        would create the same uninstrumented-dependency problem.
#  --disable-doc --disable-examples --disable-tools
#        nothing of that is needed and it only costs build time (and
#        texinfo/pandoc dependencies).
#  --disable-dependency-tracking
#        one-shot build, no need for .deps.
#  --enable-build-type=neutral
#        the default, stated explicitly: "neutral" is the one build type
#        that does NOT inject its own optimisation/debug flags, so the
#        $CFLAGS handed to us by OSS-Fuzz survive unmodified.
#
# NOTE: no --enable-sanitizers and no --enable-coverage.  OSS-Fuzz supplies
# the sanitizer and coverage instrumentation through $CFLAGS; letting
# configure add a second, possibly conflicting -fsanitize= set is a classic
# way to break an OSS-Fuzz build.
cd "${BUILD}"
"${MHD_SRC}/configure" \
  --enable-static \
  --disable-shared \
  --with-pic \
  --enable-fuzzing \
  --enable-asserts \
  --disable-https \
  --disable-curl \
  --disable-doc \
  --disable-examples \
  --disable-tools \
  --disable-dependency-tracking \
  --enable-build-type=neutral \
  CC="${CC}" \
  CFLAGS="${CFLAGS}" \
  LDFLAGS="${LDFLAGS:-}"

# ---------------------------------------------------------------------------
# 3. Build the library only
# ---------------------------------------------------------------------------
# Building just src/microhttpd avoids compiling the (large) test suite and
# the src/fuzz check_PROGRAMS, which would be built with the standalone
# driver's main() and are useless here.
make -j"$(nproc)" -C src/microhttpd libmicrohttpd.la

MHD_LIB="${BUILD}/src/microhttpd/.libs/libmicrohttpd.a"
test -f "${MHD_LIB}" || {
  echo "ERROR: ${MHD_LIB} was not produced" >&2
  exit 1
}

# ---------------------------------------------------------------------------
# 4. Compile the harnesses as libFuzzer translation units
# ---------------------------------------------------------------------------
# -DFUZZ_NO_MAIN drops the standalone driver's main() from fuzz_common.h;
# LLVMFuzzerTestOneInput() itself is unconditional in every harness.
#
# Include path:
#   -I${BUILD}                for the generated MHD_config.h
#   -I${MHD_SRC}              for the in-tree headers next to configure.ac
#   -I${MHD_SRC}/src/include  for microhttpd.h
#   -I${MHD_SRC}/src/microhttpd for internal.h, mhd_str.h, gen_auth.h, ...
#   -I${MHD_SRC}/src/fuzz     for fuzz_common.h
MHD_INCLUDES=(
  -I"${BUILD}"
  -I"${MHD_SRC}"
  -I"${MHD_SRC}/src/include"
  -I"${MHD_SRC}/src/microhttpd"
  -I"${MHD_SRC}/src/fuzz"
)

for fuzzer in ${FUZZERS}; do
  echo "--- building ${fuzzer} ---"
  # shellcheck disable=SC2086
  $CC $CFLAGS \
      -DFUZZ_NO_MAIN \
      "${MHD_INCLUDES[@]}" \
      -c "${MHD_SRC}/src/fuzz/${fuzzer}.c" \
      -o "${WORK}/${fuzzer}.o"
  # Link with $CXX: $LIB_FUZZING_ENGINE is a C++ archive for most engines.
  # shellcheck disable=SC2086
  $CXX $CXXFLAGS \
      "${WORK}/${fuzzer}.o" \
      -o "${OUT}/${fuzzer}" \
      $LIB_FUZZING_ENGINE \
      "${MHD_LIB}" \
      -lpthread
done

# ---------------------------------------------------------------------------
# 5. Seed corpora, dictionaries and .options files
# ---------------------------------------------------------------------------
"${MHD_SRC}/contrib/oss-fuzz/make_seed_corpus.sh" "${MHD_SRC}" "${OUT}"

for fuzzer in ${FUZZERS}; do
  cp "${MHD_SRC}/contrib/oss-fuzz/dicts/${fuzzer}.dict" "${OUT}/${fuzzer}.dict"
  cp "${MHD_SRC}/contrib/oss-fuzz/${fuzzer}.options" "${OUT}/${fuzzer}.options"
done

echo "=== done; contents of \$OUT ==="
ls -la "${OUT}"
