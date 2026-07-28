# This Makefile.am is in the public domain

# In-process fuzzing harnesses.  See README in this directory.
#
# The harnesses are built only with --enable-fuzzing (see
# BUILD-INTEGRATION.md).  They are ordinary check_PROGRAMS with a
# built-in deterministic driver, so they need neither clang nor
# libFuzzer nor AFL++; with those available the very same sources can be
# compiled into libFuzzer/AFL++ targets (again, see the README).

SUBDIRS = .

# Number of generate/mutate iterations per harness during "make check".
# Raise for a real fuzzing session, e.g.
#   make MHD_FUZZ_ITERATIONS=1000000 MHD_FUZZ_SEED=42 check
# The whole suite takes about three seconds under ASAN+UBSAN at this value.
MHD_FUZZ_ITERATIONS = 50000

# PRNG seed; every run is exactly reproducible from (harness, seed).
MHD_FUZZ_SEED = 1

# Lower bound for MHD_OPTION_CLIENT_DISCIPLINE_LVL in fuzz_request.
# -3 is the full range: it includes the deliberately non-conformant
# parsing modes, which is where the most interesting inputs live.
MHD_FUZZ_MIN_DISCIPLINE = -3

# Lower bound for MHD_OPTION_CONNECTION_MEMORY_LIMIT in fuzz_request.
# 0 is the full range, including the tiny pools needed to reach the
# read-buffer "shift back" code path.
MHD_FUZZ_MIN_MEM_LIMIT = 0

# Where reproducers for failing inputs are written.
MHD_FUZZ_CRASH_DIR = crashes

AM_CPPFLAGS = \
  -I$(top_srcdir)/src/include \
  -I$(top_srcdir)/src/microhttpd \
  $(CPPFLAGS_ac)

AM_CFLAGS = $(CFLAGS_ac)

AM_LDFLAGS = $(LDFLAGS_ac)

AM_TESTS_ENVIRONMENT = $(TESTS_ENVIRONMENT_ac) \
  MHD_FUZZ_ITERATIONS="$(MHD_FUZZ_ITERATIONS)" ; \
  export MHD_FUZZ_ITERATIONS ; \
  MHD_FUZZ_SEED="$(MHD_FUZZ_SEED)" ; export MHD_FUZZ_SEED ; \
  MHD_FUZZ_MIN_DISCIPLINE="$(MHD_FUZZ_MIN_DISCIPLINE)" ; \
  export MHD_FUZZ_MIN_DISCIPLINE ; \
  MHD_FUZZ_MIN_MEM_LIMIT="$(MHD_FUZZ_MIN_MEM_LIMIT)" ; \
  export MHD_FUZZ_MIN_MEM_LIMIT ; \
  MHD_FUZZ_CRASH_DIR="$(MHD_FUZZ_CRASH_DIR)" ; \
  export MHD_FUZZ_CRASH_DIR ;

if USE_COVERAGE
  AM_CFLAGS += -fprofile-arcs -ftest-coverage
endif

# fuzz_str and fuzz_auth_header call functions that are internal to the
# library (mhd_str.c, gen_auth.c, memorypool.c) and therefore hidden in
# the shared object; link them against the static archive.  This
# requires a build with --enable-static (the default).
LDADD = \
  $(top_builddir)/src/microhttpd/libmicrohttpd.la

$(top_builddir)/src/microhttpd/libmicrohttpd.la: $(top_builddir)/src/microhttpd/Makefile
	@echo ' cd $(top_builddir)/src/microhttpd && $(MAKE) $(AM_MAKEFLAGS) libmicrohttpd.la'; \
	$(am__cd) $(top_builddir)/src/microhttpd && $(MAKE) $(AM_MAKEFLAGS) libmicrohttpd.la

check_PROGRAMS = \
  fuzz_request \
  fuzz_str \
  fuzz_postprocessor

if HAVE_ANYAUTH
check_PROGRAMS += \
  fuzz_auth_header
endif

.NOTPARALLEL:

TESTS = $(check_PROGRAMS)

fuzz_request_SOURCES = \
  fuzz_request.c fuzz_common.h
fuzz_request_LDFLAGS = $(AM_LDFLAGS) -static

fuzz_str_SOURCES = \
  fuzz_str.c fuzz_common.h
fuzz_str_LDFLAGS = $(AM_LDFLAGS) -static

fuzz_auth_header_SOURCES = \
  fuzz_auth_header.c fuzz_common.h
fuzz_auth_header_LDFLAGS = $(AM_LDFLAGS) -static

fuzz_postprocessor_SOURCES = \
  fuzz_postprocessor.c fuzz_common.h
fuzz_postprocessor_LDFLAGS = $(AM_LDFLAGS) -static

# The whole corpus directory is distributed as-is.
EXTRA_DIST = \
  README \
  BUILD-INTEGRATION.md \
  corpus

CLEANFILES = \
  $(MHD_FUZZ_CRASH_DIR)/*.bin

# Regenerate the on-disk seed corpus from the built-in one.
.PHONY: refresh-corpus
refresh-corpus: $(check_PROGRAMS)
	for p in $(check_PROGRAMS) ; do \
	  ./$$p --write-corpus=$(srcdir)/corpus || exit 1 ; \
	done

# Replay the whole on-disk corpus through every harness; this is what a
# CI regression run should do after a crash has been fixed.
.PHONY: check-corpus
check-corpus: $(check_PROGRAMS)
	for p in $(check_PROGRAMS) ; do \
	  MHD_FUZZ_MIN_DISCIPLINE="$(MHD_FUZZ_MIN_DISCIPLINE)" \
	  MHD_FUZZ_MIN_MEM_LIMIT="$(MHD_FUZZ_MIN_MEM_LIMIT)" \
	    ./$$p --corpus-dir=$(srcdir)/corpus || exit 1 ; \
	done
