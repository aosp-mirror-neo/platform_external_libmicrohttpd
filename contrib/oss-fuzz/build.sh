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
# The shebang already carries -eu, but only when the script is executed
# directly; "bash build.sh" silently drops it, and a harness that fails to
# link then leaves $OUT without that target and the script still exits 0.
set -eu

SRC="${SRC:-$(cd "$(dirname "$0")/../../.." && pwd)}"
WORK="${WORK:-${SRC}/work}"
OUT="${OUT:-${SRC}/out}"
SANITIZER="${SANITIZER:-address}"
FUZZING_ENGINE="${FUZZING_ENGINE:-libfuzzer}"
ARCHITECTURE="${ARCHITECTURE:-x86_64}"

# --- engine ------------------------------------------------------------------
#
# Under OSS-Fuzz $CC, $CXX and $LIB_FUZZING_ENGINE are exported by the
# base-builder image for the engine being built and MUST be used as given,
# so everything here is dead code there.  It fires only on a local run,
# and its job is to make "FUZZING_ENGINE=afl ./build.sh" produce a real
# AFL++ target rather than a libFuzzer one that happens to link.
#
# _mhd_cov_cflags is the coverage instrumentation the engine needs at
# compile time.  Getting it wrong is the failure mode that matters: the
# build succeeds, the target runs, and it finds nothing, because the
# engine has no feedback signal.
case "${FUZZING_ENGINE}" in
  libfuzzer)
    CC="${CC:-clang}"
    CXX="${CXX:-clang++}"
    LIB_FUZZING_ENGINE="${LIB_FUZZING_ENGINE:--fsanitize=fuzzer}"
    _mhd_cov_cflags="-fsanitize=fuzzer-no-link"
    _mhd_main="engine"
    ;;
  afl)
    # afl-clang-fast inserts AFL++'s own instrumentation, so libFuzzer's
    # must not be added on top; libAFLDriver.a supplies a main() that
    # feeds AFL++ input to LLVMFuzzerTestOneInput().
    CC="${CC:-afl-clang-fast}"
    CXX="${CXX:-afl-clang-fast++}"
    LIB_FUZZING_ENGINE="${LIB_FUZZING_ENGINE:-/usr/lib/afl/libAFLDriver.a}"
    _mhd_cov_cflags=""
    _mhd_main="engine"
    ;;
  honggfuzz)
    # hfuzz-clang does the same job for honggfuzz.  It is not packaged by
    # Debian; build it from https://github.com/google/honggfuzz and put
    # its directory on $PATH (see contrib/oss-fuzz/README).
    CC="${CC:-hfuzz-clang}"
    CXX="${CXX:-hfuzz-clang++}"
    # hfuzz-clang links libhfuzz/libhfcommon and supplies main() itself,
    # so $LIB_FUZZING_ENGINE stays empty.
    LIB_FUZZING_ENGINE="${LIB_FUZZING_ENGINE:-}"
    _mhd_cov_cflags=""
    _mhd_main="engine"
    ;;
  none)
    # No engine: link the harnesses' own deterministic driver instead.
    # This is what makes a sanitizer-only smoke test possible without any
    # fuzzing engine installed at all.
    CC="${CC:-clang}"
    CXX="${CXX:-clang++}"
    LIB_FUZZING_ENGINE="${LIB_FUZZING_ENGINE:-}"
    _mhd_cov_cflags=""
    _mhd_main="builtin"
    ;;
  *)
    echo "ERROR: unknown FUZZING_ENGINE='${FUZZING_ENGINE}'" >&2
    echo "       expected: libfuzzer | afl | honggfuzz | none" >&2
    exit 1
    ;;
esac

# --- architecture ------------------------------------------------------------
#
# OSS-Fuzz exports $ARCHITECTURE and already has -m32 in $CFLAGS for i386,
# so this too only fires locally.
#
# -no-pie is needed on i386 and only there: a position independent
# executable built with -m32 and any sanitizer dies with SEGV at address
# 0 before main() on current Linux/clang.  It is harmless on x86_64 and
# is therefore not applied there, to keep that build byte-comparable with
# what OSS-Fuzz produces.
case "${ARCHITECTURE}" in
  x86_64)
    _mhd_arch_cflags=""
    ;;
  i386)
    _mhd_arch_cflags="-m32 -no-pie"
    ;;
  *)
    echo "ERROR: unknown ARCHITECTURE='${ARCHITECTURE}'" >&2
    echo "       expected: x86_64 | i386" >&2
    exit 1
    ;;
esac

# --- $CFLAGS / $CXXFLAGS -----------------------------------------------------
#
# Under OSS-Fuzz $CFLAGS and $CXXFLAGS are always exported by the
# base-builder image and MUST be used verbatim, so everything below is
# dead code there: it fires only when the variable is unset, i.e. only on
# a local run.
#
# The point of the defaults is that a local run must be a *real* fuzzing
# run.  Two flags are what make it one, and leaving either out produces a
# build that looks fine and finds nothing:
#
#   -fsanitize=fuzzer-no-link
#         installs libFuzzer's coverage instrumentation (SanitizerCoverage
#         trace-pc-guard + the comparison hooks) in every translation unit
#         of the library.  Without it libFuzzer gets no feedback signal at
#         all and degenerates into blind random input generation --
#         `cov:` stays flat and the corpus never grows.  "-no-link" is the
#         compile-time half; $LIB_FUZZING_ENGINE supplies the driver at
#         link time.
#   a sanitizer
#         libFuzzer by itself only notices a crash the kernel delivers.
#         ASan/UBSan are what turn a silently-tolerated overflow into a
#         report.  Note that MHD's own oracles -- the
#         MHD_set_panic_func() tripwire and mhd_assert(), enabled by the
#         --enable-asserts below -- work without any sanitizer, which is
#         why SANITIZER=none is still worth something.
#
# The mapping below mirrors what OSS-Fuzz's own helper passes for each
# $SANITIZER value, with one deliberate difference in the "address" case,
# noted there.
if [ -z "${CFLAGS:-}" ]; then
  # -O1                     OSS-Fuzz's optimisation level for fuzz builds:
  #                         fast enough to get exec/s, low enough that
  #                         inlining does not destroy the stack traces.
  # -fno-omit-frame-pointer needed for usable ASan/libFuzzer backtraces.
  # -gline-tables-only      just enough debug info to symbolize; a full -g
  #                         would multiply build time and object size.
  _mhd_base_cflags="-O1 -fno-omit-frame-pointer -gline-tables-only"

  case "${SANITIZER}" in
    address)
      # OSS-Fuzz builds "address" and "undefined" as two separate
      # campaigns, because it has unlimited machine time and wants each
      # report attributed to one sanitizer.  A local run has an afternoon
      # at most, so the default folds UBSan into the ASan build: two
      # oracles per CPU-hour instead of one, at a few percent of speed.
      # Set SANITIZER=undefined explicitly for the split OSS-Fuzz shape.
      #
      # -fno-sanitize-recover=undefined is essential: by default UBSan
      # *prints* and continues, and libFuzzer only records a finding for a
      # process that dies.  Without it UB scrolls past and the run is
      # reported clean.
      _mhd_san_cflags="-fsanitize=address,undefined"
      _mhd_san_cflags="${_mhd_san_cflags} -fsanitize-address-use-after-scope"
      _mhd_san_cflags="${_mhd_san_cflags} -fno-sanitize-recover=undefined"
      ;;
    undefined)
      _mhd_san_cflags="-fsanitize=undefined -fno-sanitize-recover=undefined"
      ;;
    memory)
      # MSan reports uninitialised reads from *any* uninstrumented code it
      # links against, so this is only usable when the C library is
      # instrumented too -- true inside the OSS-Fuzz image, essentially
      # never true on a distro toolchain.  Expect false positives in libc
      # frames locally; use the OSS-Fuzz container for a real MSan run.
      #
      # This is also why build.sh configures --disable-https and
      # --disable-curl: an uninstrumented GnuTLS would poison every run.
      # Any harness that needs TLS is skipped in this configuration; see
      # the $FUZZERS selection below.
      _mhd_san_cflags="-fsanitize=memory -fsanitize-memory-track-origins"
      ;;
    coverage)
      # A coverage build is not a fuzzing build: it replays an existing
      # corpus to produce a report, so no sanitizer and no libFuzzer
      # coverage instrumentation.
      _mhd_san_cflags="-fprofile-instr-generate -fcoverage-mapping"
      ;;
    none | "")
      _mhd_san_cflags=""
      ;;
    *)
      echo "ERROR: unknown SANITIZER='${SANITIZER}'" >&2
      echo "       expected: address | undefined | memory | coverage | none" >&2
      exit 1
      ;;
  esac

  if [ "${SANITIZER}" = "coverage" ]; then
    CFLAGS="${_mhd_arch_cflags} ${_mhd_base_cflags} ${_mhd_san_cflags}"
  else
    CFLAGS="${_mhd_arch_cflags} ${_mhd_base_cflags} ${_mhd_san_cflags}"
    CFLAGS="${CFLAGS} ${_mhd_cov_cflags}"
  fi
  unset _mhd_base_cflags _mhd_san_cflags
fi
CXXFLAGS="${CXXFLAGS:-${CFLAGS}}"
if [ "${_mhd_main}" = "builtin" ]; then
  _mhd_no_main=""
else
  _mhd_no_main="-DFUZZ_NO_MAIN"
fi
unset _mhd_arch_cflags _mhd_cov_cflags _mhd_main

# Directory holding the libmicrohttpd sources.  OSS-Fuzz clones them to
# $SRC/libmicrohttpd (see Dockerfile); allow an override for local runs.
MHD_SRC="${MHD_SRC:-${SRC}/libmicrohttpd}"

# Out-of-tree build directory.  Keeping the build out of the source tree
# means build.sh never modifies the checkout, which matters for the
# "run build.sh twice" and "reproduce against a pristine tree" cases.
BUILD="${WORK}/mhd-build"

FUZZERS="fuzz_request fuzz_options fuzz_eventloop fuzz_str fuzz_memorypool fuzz_auth_header fuzz_postprocessor"

# fuzz_tls is deliberately absent: it needs a TLS backend, and this build
# configures --disable-https on purpose (see the rationale below), so the
# target would be an empty shell on all three sanitizers.  Shipping it
# would need a second, HTTPS-enabled build variant, which also gives up
# the MemorySanitizer configuration -- an uninstrumented GnuTLS poisons
# every MSan run.  It is built and tested in tree by "make -C src/fuzz
# check" instead.

mkdir -p "${WORK}" "${OUT}" "${BUILD}"

echo "=== libmicrohttpd OSS-Fuzz build ==="
echo "    MHD_SRC            = ${MHD_SRC}"
echo "    BUILD              = ${BUILD}"
echo "    OUT                = ${OUT}"
echo "    SANITIZER          = ${SANITIZER}"
echo "    FUZZING_ENGINE     = ${FUZZING_ENGINE}"
echo "    ARCHITECTURE       = ${ARCHITECTURE}"
echo "    LIB_FUZZING_ENGINE = ${LIB_FUZZING_ENGINE}"
echo "    CC / CXX           = ${CC} / ${CXX}"
echo "    CFLAGS             = ${CFLAGS}"
echo "    CXXFLAGS           = ${CXXFLAGS}"
echo "    FUZZERS            = ${FUZZERS}"

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
#        findings K1-K7 (src/fuzz/README section 6) are invisible.
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
# -DFUZZ_NO_MAIN drops the standalone driver's main() from fuzz_common.h,
# because the engine supplies its own.  With FUZZING_ENGINE=none there is
# no engine, so the harnesses' built-in driver is kept instead and the
# result is a self-contained, deterministic, seeded fuzzer that needs no
# engine at all.  LLVMFuzzerTestOneInput() itself is unconditional in
# every harness either way.
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
      ${_mhd_no_main} \
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

# ---------------------------------------------------------------------------
# 6. Verify: every requested target must actually be in $OUT
# ---------------------------------------------------------------------------
# Belt and braces for the failure that matters most -- a build that
# reports success but ships nothing, which on OSS-Fuzz shows up only as a
# target that never runs.
_mhd_missing=""
for fuzzer in ${FUZZERS}; do
  [ -x "${OUT}/${fuzzer}" ] || _mhd_missing="${_mhd_missing} ${fuzzer}"
  [ -f "${OUT}/${fuzzer}_seed_corpus.zip" ] ||
    _mhd_missing="${_mhd_missing} ${fuzzer}_seed_corpus.zip"
done
if [ -n "${_mhd_missing}" ]; then
  echo "ERROR: build did not produce:${_mhd_missing}" >&2
  exit 1
fi
unset _mhd_missing

echo "=== done; contents of \$OUT ==="
ls -la "${OUT}"
