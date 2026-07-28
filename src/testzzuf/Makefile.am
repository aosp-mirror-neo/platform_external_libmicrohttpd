# This Makefile.am is in the public domain

SUBDIRS  = .

# ZZUF_SEED can be redefined to use other initial seeds
# for extended testing. E.g.,
#  make ZZUF_SEED=1234 check
# When a test fails, the runner scripts print the seed(s) that produced
# the failure so that the failure can be replayed with this variable.
ZZUF_SEED = 0

# ZZUF_SEED_START / ZZUF_SEED_STOP sweep a whole range of seeds instead of
# using a single one; they are mapped onto zzuf's "--seed=start:stop".
# Every seed in the range starts one new child, so a large range takes a
# correspondingly long time. E.g.,
#  make ZZUF_SEED_START=0 ZZUF_SEED_STOP=500 check
# ZZUF_SEED_START takes precedence over ZZUF_SEED.
ZZUF_SEED_START =
ZZUF_SEED_STOP =


# Additional flags for zzuf
ZZUF_FLAGS =

# Additional flags for socat (if socat is used)
SOCAT_FLAGS =

# Sanitizer options that are appended to the options set by configure.
# The fuzzing tests must abort at the very first error, otherwise the
# input that produced the error is lost.
# Leak detection is off: under fuzzing MHD legitimately abandons
# half-processed requests, and the test itself is killed by zzuf.
# To run the fuzzing tests under the sanitizers, configure MHD with
#  ./configure --enable-sanitizers=address,undefined
# (this automatically makes the socat mode mandatory, as zzuf and the
# sanitizers cannot both intercept the standard library calls).
ZZUF_ASAN_OPTIONS = abort_on_error=1:detect_leaks=0
ZZUF_UBSAN_OPTIONS = print_stacktrace=1:halt_on_error=1

if FORCE_USE_ZZUF_SOCAT
TEST_RUNNER_SCRIPT = zzuf_socat_test_runner.sh
else
TEST_RUNNER_SCRIPT = zzuf_test_runner.sh
endif

AM_CPPFLAGS = \
  -I$(top_srcdir)/src/include \
  -I$(top_srcdir)/src/microhttpd \
  -DMHD_CPU_COUNT=$(CPU_COUNT) \
  $(CPPFLAGS_ac) $(LIBCURL_CPPFLAGS)

AM_CFLAGS = $(CFLAGS_ac)

AM_LDFLAGS = $(LDFLAGS_ac)

AM_TESTS_ENVIRONMENT = $(TESTS_ENVIRONMENT_ac) \
  ZZUF="$(ZZUF)" ; export ZZUF ; \
  ZZUF_SEED="$(ZZUF_SEED)" ; export ZZUF_SEED ; \
  ZZUF_SEED_START="$(ZZUF_SEED_START)" ; export ZZUF_SEED_START ; \
  ZZUF_SEED_STOP="$(ZZUF_SEED_STOP)" ; export ZZUF_SEED_STOP ; \
  ZZUF_FLAGS="$(ZZUF_FLAGS)" ; export ZZUF_FLAGS ; \
  SOCAT="$(SOCAT)" ; export SOCAT ; \
  SOCAT_FLAGS="$(SOCAT_FLAGS)" ; export SOCAT_FLAGS ; \
  ASAN_OPTIONS="$${ASAN_OPTIONS:+$${ASAN_OPTIONS}:}$(ZZUF_ASAN_OPTIONS)" ; \
  export ASAN_OPTIONS ; \
  UBSAN_OPTIONS="$${UBSAN_OPTIONS:+$${UBSAN_OPTIONS}:}$(ZZUF_UBSAN_OPTIONS)" ; \
  export UBSAN_OPTIONS ;

if USE_COVERAGE
  AM_CFLAGS += -fprofile-arcs -ftest-coverage
endif

LDADD = \
  $(top_builddir)/src/microhttpd/libmicrohttpd.la \
  @LIBCURL@

$(top_builddir)/src/microhttpd/libmicrohttpd.la: $(top_builddir)/src/microhttpd/Makefile
	@echo ' cd $(top_builddir)/src/microhttpd && $(MAKE) $(AM_MAKEFLAGS) libmicrohttpd.la'; \
	$(am__cd) $(top_builddir)/src/microhttpd && $(MAKE) $(AM_MAKEFLAGS) libmicrohttpd.la

check_PROGRAMS = \
  test_get \
  test_get_chunked \
  test_post \
  test_post_form \
  test_put \
  test_put_chunked \
  test_put_large \
  test_get_long_uri \
  test_get_long_header \
  test_get_close \
  test_get_chunked_close \
  test_post_close \
  test_post_form_close \
  test_put_close \
  test_put_chunked_close \
  test_put_large_close \
  test_get_long_uri_close \
  test_get_long_header_close \
  test_get10 \
  test_get_chunked10 \
  test_post10 \
  test_post_form10 \
  test_put10 \
  test_put_large10 \
  test_get_long_uri10 \
  test_get_long_header10 \
  test_get_hostile \
  test_get_chunked_hostile \
  test_post_hostile \
  test_put_chunked_hostile \
  test_put_large_hostile \
  test_get_args \
  test_get_args_close \
  test_get_args10 \
  test_get_chunked_ext \
  test_get_chunked_ext_close \
  test_put_chunked_ext \
  test_put_chunked_ext_close \
  test_pipelined \
  test_pipelined_close

if ENABLE_DAUTH
check_PROGRAMS += \
  test_digest_auth \
  test_digest_auth_close
endif

if ENABLE_BAUTH
check_PROGRAMS += \
  test_basic_auth \
  test_basic_auth_close
endif

.NOTPARALLEL:


TESTS = $(check_PROGRAMS)

dist_check_SCRIPTS = zzuf_test_runner.sh zzuf_socat_test_runner.sh

LOG_COMPILER = @SHELL@ "$(srcdir)/$(TEST_RUNNER_SCRIPT)"

if VHEAVY_TESTS
check_SCRIPTS = warn_vheavy_use

.PHONY: warn_vheavy_use
endif

warn_vheavy_use:
	@echo "NOTICE" ; \
	echo "NOTICE: Full heavy tests are enabled. Each test may take up to several minutes to complete." ; \
	echo "NOTICE"


tests_common_sources = \
  mhd_debug_funcs.h mhd_debug_funcs.c \
  mhd_zzuf_common.h mhd_zzuf_common.c

test_get_SOURCES = \
  test_get.c $(tests_common_sources)

test_get_chunked_SOURCES = $(test_get_SOURCES)

test_post_SOURCES = $(test_get_SOURCES)

test_post_form_SOURCES = $(test_get_SOURCES)

test_put_SOURCES = $(test_get_SOURCES)

test_put_chunked_SOURCES = $(test_get_SOURCES)

test_put_large_SOURCES = $(test_get_SOURCES)

test_get_long_uri_SOURCES = $(test_get_SOURCES)

test_get_long_header_SOURCES = $(test_get_SOURCES)

test_get_close_SOURCES = $(test_get_SOURCES)

test_get_chunked_close_SOURCES = $(test_get_chunked_SOURCES)

test_post_close_SOURCES = $(test_post_SOURCES)

test_post_form_close_SOURCES = $(test_post_form_SOURCES)

test_put_close_SOURCES = $(test_put_SOURCES)

test_put_chunked_close_SOURCES = $(test_put_chunked_SOURCES)

test_put_large_close_SOURCES = $(test_put_large_SOURCES)

test_get_long_uri_close_SOURCES = $(test_get_long_uri_SOURCES)

test_get_long_header_close_SOURCES = $(test_get_long_header_SOURCES)

test_get10_SOURCES = $(test_get_SOURCES)

test_get_chunked10_SOURCES = $(test_get_chunked_SOURCES)

test_post10_SOURCES = $(test_post_SOURCES)

test_post_form10_SOURCES = $(test_post_form_SOURCES)

test_put10_SOURCES = $(test_put_SOURCES)

test_put_large10_SOURCES = $(test_put_large_SOURCES)

test_get_long_uri10_SOURCES = $(test_get_long_uri_SOURCES)

test_get_long_header10_SOURCES = $(test_get_long_header_SOURCES)

# The "_hostile" variants run exactly the same client/server exchange as
# the programs above, but every started daemon uses another entry of the
# "hostile" daemon option matrix (see mhd_zzuf_common.c): tiny connection
# memory pools, small connection limits, short timeouts and the whole
# range of MHD_OPTION_CLIENT_DISCIPLINE_LVL /
# MHD_OPTION_STRICT_FOR_CLIENT values.

test_get_hostile_SOURCES = $(test_get_SOURCES)

test_get_chunked_hostile_SOURCES = $(test_get_chunked_SOURCES)

test_post_hostile_SOURCES = $(test_post_SOURCES)

test_put_chunked_hostile_SOURCES = $(test_put_chunked_SOURCES)

test_put_large_hostile_SOURCES = $(test_put_large_SOURCES)

# GET requests with hostile query strings (arguments without '=', empty
# names and values, trailing '&', percent-encoded names, a very long tail
# argument), combined with connection memory pools below MHD_BUF_INC_SIZE.

test_get_args_SOURCES = \
  test_get_args.c $(tests_common_sources)

test_get_args_close_SOURCES = $(test_get_args_SOURCES)

test_get_args10_SOURCES = $(test_get_args_SOURCES)

# Chunked transfers whose chunk-size lines carry chunk extensions, plus
# trailers/footers. libcurl cannot produce chunk extensions, so these
# tests use the raw socket client of mhd_zzuf_common.c.

test_get_chunked_ext_SOURCES = \
  test_get_chunked_ext.c $(tests_common_sources)

test_get_chunked_ext_close_SOURCES = $(test_get_chunked_ext_SOURCES)

test_put_chunked_ext_SOURCES = $(test_get_chunked_ext_SOURCES)

test_put_chunked_ext_close_SOURCES = $(test_get_chunked_ext_SOURCES)

# Several complete requests written with a single send() call.

test_pipelined_SOURCES = \
  test_pipelined.c $(tests_common_sources)

test_pipelined_close_SOURCES = $(test_pipelined_SOURCES)

# Authentication. Both are built only if the respective support has not
# been disabled at configure time (--disable-dauth / --disable-bauth).

test_digest_auth_SOURCES = \
  test_digest_auth.c $(tests_common_sources)

test_digest_auth_close_SOURCES = $(test_digest_auth_SOURCES)

test_basic_auth_SOURCES = \
  test_basic_auth.c $(tests_common_sources)

test_basic_auth_close_SOURCES = $(test_basic_auth_SOURCES)
