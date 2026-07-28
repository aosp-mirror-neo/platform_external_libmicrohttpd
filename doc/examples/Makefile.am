# This Makefile.am is in the public domain
SUBDIRS  = .

AM_CPPFLAGS = \
  -I$(top_srcdir)/src/include \
  $(CPPFLAGS_ac) $(LIBCURL_CPPFLAGS)

AM_CFLAGS = $(CFLAGS_ac) @LIBGCRYPT_CFLAGS@

AM_LDFLAGS = $(LDFLAGS_ac)

AM_TESTS_ENVIRONMENT = $(TESTS_ENVIRONMENT_ac)

if USE_COVERAGE
  AM_CFLAGS += --coverage
endif

$(top_builddir)/src/microhttpd/libmicrohttpd.la: $(top_builddir)/src/microhttpd/Makefile
	@echo ' cd $(top_builddir)/src/microhttpd && $(MAKE) $(AM_MAKEFLAGS) libmicrohttpd.la'; \
	$(am__cd) $(top_builddir)/src/microhttpd && $(MAKE) $(AM_MAKEFLAGS) libmicrohttpd.la

# example programs
noinst_PROGRAMS = \
  callbackresponse \
  hellobrowser \
  logging \
  responseheaders

if ENABLE_UPGRADE
noinst_PROGRAMS += \
  upgrade
endif

if ENABLE_BAUTH
noinst_PROGRAMS += \
  basicauthentication
if ENABLE_HTTPS
noinst_PROGRAMS += \
  tlsauthentication
endif
endif

if HAVE_POSTPROCESSOR
noinst_PROGRAMS += simplepost largepost sessions
endif

if HAVE_POSIX_THREADS
noinst_PROGRAMS += asyncresponse
if HAVE_FORK_WAITPID
if RUN_LIBCURL_TESTS
check_PROGRAMS = test_asyncresponse
TESTS = $(check_PROGRAMS)
endif
endif
endif

if HAVE_W32
AM_CPPFLAGS += -DWINDOWS
endif

asyncresponse_SOURCES = \
 asyncresponse.c
asyncresponse_CFLAGS = \
 $(AM_CFLAGS) $(PTHREAD_CFLAGS)
asyncresponse_LDADD = \
 $(PTHREAD_LIBS) \
 $(top_builddir)/src/microhttpd/libmicrohttpd.la

test_asyncresponse_SOURCES = \
 test_asyncresponse.c
test_asyncresponse_CFLAGS = \
 $(AM_CFLAGS) $(PTHREAD_CFLAGS)
test_asyncresponse_LDADD = \
 $(PTHREAD_LIBS) \
 $(top_builddir)/src/microhttpd/libmicrohttpd.la \
 @LIBCURL@

basicauthentication_SOURCES = \
 basicauthentication.c
basicauthentication_LDADD = \
 $(top_builddir)/src/microhttpd/libmicrohttpd.la

callbackresponse_SOURCES = \
 callbackresponse.c
callbackresponse_LDADD = \
 $(top_builddir)/src/microhttpd/libmicrohttpd.la

hellobrowser_SOURCES = \
 hellobrowser.c
hellobrowser_LDADD = \
 $(top_builddir)/src/microhttpd/libmicrohttpd.la

logging_SOURCES = \
 logging.c 
logging_LDADD = \
 $(top_builddir)/src/microhttpd/libmicrohttpd.la

responseheaders_SOURCES = \
 responseheaders.c 
responseheaders_LDADD = \
 $(top_builddir)/src/microhttpd/libmicrohttpd.la 

sessions_SOURCES = \
 sessions.c 
sessions_LDADD = \
 $(top_builddir)/src/microhttpd/libmicrohttpd.la 

tlsauthentication_SOURCES = \
 tlsauthentication.c 
tlsauthentication_LDADD = \
 $(top_builddir)/src/microhttpd/libmicrohttpd.la 

simplepost_SOURCES = \
 simplepost.c 
simplepost_LDADD = \
 $(top_builddir)/src/microhttpd/libmicrohttpd.la 

largepost_SOURCES = \
 largepost.c 
largepost_LDADD = \
 $(top_builddir)/src/microhttpd/libmicrohttpd.la 

upgrade_SOURCES = \
 upgrade.c
upgrade_LDADD = \
 $(top_builddir)/src/microhttpd/libmicrohttpd.la
