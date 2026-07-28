/*
  This file is part of libmicrohttpd
  Copyright (C) 2026 Christian Grothoff

  This library is free software; you can redistribute it and/or
  modify it under the terms of the GNU Lesser General Public
  License as published by the Free Software Foundation; either
  version 2.1 of the License, or (at your option) any later version.

  This library is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public
  License along with this library.
  If not, see <http://www.gnu.org/licenses/>.
*/

/**
 * @file fuzz/fuzz_auth_header.c
 * @brief Direct fuzzer for the "Authorization:" header parsers.
 * @author Christian Grothoff
 *
 * MHD_get_rq_dauth_params_() and MHD_get_rq_bauth_params_() are internal
 * (they live in gen_auth.c and are not exported), and both need a
 * `struct MHD_Connection`.  Rather than pushing bytes through a socket,
 * this harness assembles the *minimal* connection object those two
 * functions actually touch -- a daemon pointer, a memory pool, a state
 * and a single "Authorization" header -- and then varies only the header
 * value.  That makes this the fastest way to explore the parameter
 * parser (roughly two orders of magnitude more executions per second
 * than fuzz_request).
 *
 * Besides memory-safety (ASAN), the harness checks the parser output for
 * internal consistency: every returned parameter must be a sub-range of
 * the header value that was fed in.  A parameter pointing outside of it
 * would be a parser bug that ASAN alone might not catch.
 *
 * Input format:
 *   byte 0    scheme selector / pool size selector
 *   byte 1..  the raw "Authorization" header value
 */

#define FUZZ_HARNESS_NAME "fuzz_auth_header"
#include "fuzz_common.h"

/* internal.h pulls in MHD_config.h and <microhttpd.h> in the right
   order; including <microhttpd.h> first would redefine _MHD_EXTERN. */
#include "internal.h"
#include "memorypool.h"
#include "gen_auth.h"
#include "mhd_str.h"

#ifdef DAUTH_SUPPORT
#include "digestauth.h"
#endif
#ifdef BAUTH_SUPPORT
#include "basicauth.h"
#endif

static const size_t pool_sizes[] = { 256, 512, 1024, 4096, 32768 };

/**
 * gen_auth.c logs through MHD_DLOG(), which dereferences the daemon of
 * the connection, so a real (but idle) daemon is required.  It is
 * created once and reused for the whole run.
 */
static struct MHD_Daemon *shared_daemon;

/** Statistics, printed at exit with --verbose. */
static unsigned long stat_dauth_parsed;
static unsigned long stat_dauth_failed;
static unsigned long stat_bauth_parsed;
static unsigned long stat_bauth_failed;


static void
print_stats (void)
{
  if (! fuzz_verbose)
    return;
  fprintf (stderr,
           "%s: digest headers parsed=%lu rejected=%lu; "
           "basic headers parsed=%lu rejected=%lu\n",
           FUZZ_HARNESS_NAME,
           stat_dauth_parsed, stat_dauth_failed,
           stat_bauth_parsed, stat_bauth_failed);
}


static enum MHD_Result
dummy_ahc (void *cls,
           struct MHD_Connection *connection,
           const char *url,
           const char *method,
           const char *version,
           const char *upload_data,
           size_t *upload_data_size,
           void **req_cls)
{
  (void) cls; (void) connection; (void) url; (void) method; (void) version;
  (void) upload_data; (void) upload_data_size; (void) req_cls;
  return MHD_NO;
}


static void
stop_shared_daemon (void)
{
  if (NULL != shared_daemon)
  {
    MHD_stop_daemon (shared_daemon);
    shared_daemon = NULL;
  }
}


static struct MHD_Daemon *
get_shared_daemon (void)
{
  if (NULL == shared_daemon)
  {
    shared_daemon =
      MHD_start_daemon (MHD_USE_NO_LISTEN_SOCKET
                        | (fuzz_verbose ? MHD_USE_ERROR_LOG : 0u),
                        0, NULL, NULL, &dummy_ahc, NULL,
                        MHD_OPTION_END);
    if (NULL != shared_daemon)
    {
      (void) atexit (&stop_shared_daemon);
      (void) atexit (&print_stats);
    }
  }
  return shared_daemon;
}


#ifdef DAUTH_SUPPORT
/**
 * Every parsed parameter must be a sub-range of the header value.
 */
static void
check_param (const struct MHD_RqDAuthParam *pm,
             const char *base,
             size_t base_len,
             const char *what)
{
  char msg[256];

  if (NULL == pm->value.str)
  {
    if (0 != pm->value.len)
    {
      (void) snprintf (msg, sizeof (msg),
                       "digest parameter '%s' has NULL string but "
                       "non-zero length", what);
      fuzz_report_finding (msg);
    }
    return;
  }
  if ( (pm->value.str < base) ||
       (pm->value.str > base + base_len) ||
       (pm->value.len > base_len) ||
       (pm->value.str + pm->value.len > base + base_len) )
  {
    (void) snprintf (msg, sizeof (msg),
                     "digest parameter '%s' points outside of the "
                     "Authorization header value", what);
    fuzz_report_finding (msg);
  }
}


#endif /* DAUTH_SUPPORT */


int
LLVMFuzzerTestOneInput (const uint8_t *data,
                        size_t size)
{
  static const char hdr_name[] = MHD_HTTP_HEADER_AUTHORIZATION;
  struct MHD_Connection c;
  struct MHD_HTTP_Req_Header h;
  struct MemoryPool *pool;
  char *value;
  size_t vlen;
  unsigned int sel;
  size_t pool_size;

  if (size < 2)
    return 0;
  if (NULL == get_shared_daemon ())
    return 0;
  sel = data[0];
  vlen = size - 1;
  if (vlen > 4096)
    vlen = 4096;
  pool_size = pool_sizes[(sel >> 3) % (sizeof (pool_sizes)
                                       / sizeof (pool_sizes[0]))];

  /* Exactly sized, zero-terminated copy of the header value, so that
     ASAN catches any read past its end. */
  value = (char *) malloc (vlen + 1);
  if (NULL == value)
    return 0;
  memcpy (value, data + 1, vlen);
  value[vlen] = '\0';

  pool = MHD_pool_create (pool_size);
  if (NULL == pool)
  {
    free (value);
    return 0;
  }

  memset (&c, 0, sizeof (c));
  memset (&h, 0, sizeof (h));
  h.header = hdr_name;
  h.header_size = MHD_STATICSTR_LEN_ (MHD_HTTP_HEADER_AUTHORIZATION);
  h.value = value;
  h.value_size = vlen;
  h.kind = MHD_HEADER_KIND;
  c.daemon = shared_daemon;
  c.pool = pool;
  c.rq.headers_received = &h;
  c.rq.headers_received_tail = &h;
  c.state = MHD_CONNECTION_HEADERS_PROCESSED;

#ifdef DAUTH_SUPPORT
  if (0 == (sel & 0x01))
  {
    const struct MHD_RqDAuth *da;

    da = MHD_get_rq_dauth_params_ (&c);
    if (NULL == da)
      stat_dauth_failed++;
    else
    {
      stat_dauth_parsed++;
      check_param (&da->nonce, value, vlen, "nonce");
      check_param (&da->opaque, value, vlen, "opaque");
      check_param (&da->response, value, vlen, "response");
      check_param (&da->username, value, vlen, "username");
      check_param (&da->username_ext, value, vlen, "username*");
      check_param (&da->realm, value, vlen, "realm");
      check_param (&da->uri, value, vlen, "uri");
      check_param (&da->qop_raw, value, vlen, "qop");
      check_param (&da->cnonce, value, vlen, "cnonce");
      check_param (&da->nc, value, vlen, "nc");
      /* The result must be stable: a second call returns the cache. */
      if (da != MHD_get_rq_dauth_params_ (&c))
        fuzz_report_finding ("MHD_get_rq_dauth_params_() is not idempotent");
    }
  }
#endif /* DAUTH_SUPPORT */
#ifdef BAUTH_SUPPORT
  if (0 != (sel & 0x01))
  {
    const struct MHD_RqBAuth *ba;

    ba = MHD_get_rq_bauth_params_ (&c);
    if (NULL == ba)
      stat_bauth_failed++;
    else
    {
      stat_bauth_parsed++;
      if (NULL != ba->token68.str)
      {
        if ( (ba->token68.str < value) ||
             (ba->token68.str + ba->token68.len > value + vlen) )
          fuzz_report_finding ("basic auth token68 points outside of the "
                               "Authorization header value");
        /* Decoding must fit into the documented maximum size. */
        if (0 != ba->token68.len)
        {
          size_t need = MHD_base64_max_dec_size_ (ba->token68.len);
          uint8_t *bin = (uint8_t *) malloc ((0 == need) ? 1 : need);

          if (NULL != bin)
          {
            size_t r = MHD_base64_to_bin_n (ba->token68.str,
                                            ba->token68.len,
                                            bin,
                                            need);
            if (r > need)
              fuzz_report_finding ("MHD_base64_to_bin_n() exceeded "
                                   "MHD_base64_max_dec_size_()");
            free (bin);
          }
        }
      }
      if (ba != MHD_get_rq_bauth_params_ (&c))
        fuzz_report_finding ("MHD_get_rq_bauth_params_() is not idempotent");
    }
  }
#endif /* BAUTH_SUPPORT */

  MHD_pool_destroy (pool);
  free (value);
  return 0;
}


/* ------------------------------------------------------------------ */
/* Generator                                                           */
/* ------------------------------------------------------------------ */

static const char *const gen_param_names[] = {
  "username", "username*", "realm", "nonce", "uri", "response", "algorithm",
  "qop", "nc", "cnonce", "opaque", "userhash", "charset", "domain",
  "unknown", "", "USERNAME", "user name"
};

static const char *const gen_param_values[] = {
  "\"user\"", "user", "\"\"", "\"a\\\"b\"", "\"a\\\\\"", "\"\\\"",
  "UTF-8''a%20b", "utf-8''%41", "''", "'", "true", "false", "TRUE",
  "auth", "auth-int", "auth,auth-int", "\"auth\"", "MD5", "SHA-256",
  "SHA-512-256", "BOGUS", "\"SHA-256\"", "00000001", "ffffffff",
  "0123456789abcdef0123456789abcdef",
  "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
  "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
  "\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
  "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\""
};


static size_t
fuzz_generate (struct fuzz_rng *rng,
               uint8_t *buf,
               size_t cap)
{
  size_t len = 0;
  unsigned int nparams;
  unsigned int i;
  int basic;

  if (cap < 32)
    return 0;
  basic = fuzz_chance (rng, 4);
  buf[len++] = (uint8_t) ((fuzz_byte (rng) & 0xFE) | (basic ? 1u : 0u));

/* NB: evaluate the argument exactly once -- it usually contains a
   call into the PRNG. */
#define ADD(s) \
  do { \
    const char *s_ = (s); \
    size_t l_ = strlen (s_); \
    if (len + l_ >= cap) \
    return len; \
    memcpy (buf + len, s_, l_); \
    len += l_; \
  } while (0)

  if (basic)
  {
    unsigned int n;

    ADD ("Basic ");
    n = fuzz_below (rng, 48);
    for (i = 0; (i < n) && (len < cap); i++)
      buf[len++] =
        (uint8_t) "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
        "0123456789+/= "[fuzz_below (rng, 66)];
    return len;
  }

  ADD ("Digest ");
  nparams = 1 + fuzz_below (rng, 12);
  for (i = 0; i < nparams; i++)
  {
    if (0 != i)
      ADD (fuzz_chance (rng, 8) ? "," : ", ");
    ADD (gen_param_names[fuzz_below (rng,
                                     (uint32_t) (sizeof (gen_param_names)
                                                 / sizeof (char *)))]);
    if (! fuzz_chance (rng, 10))
      ADD (fuzz_chance (rng, 10) ? " = " : "=");
    ADD (gen_param_values[fuzz_below (rng,
                                      (uint32_t) (sizeof (gen_param_values)
                                                  / sizeof (char *)))]);
  }
#undef ADD
  return len;
}


/* ------------------------------------------------------------------ */
/* Seed corpus                                                         */
/* ------------------------------------------------------------------ */

struct ah_seed
{
  const char *txt;
  size_t len;
};

#define ASEED(t) { t, sizeof (t) - 1 }

static const struct ah_seed ah_seeds[] = {
  ASEED ("\x00" "Digest username=\"user\", realm=\"TestRealm\", "
         "nonce=\"0123456789abcdef\", uri=\"/a\", qop=auth, nc=00000001, "
         "cnonce=\"x\", algorithm=MD5, response=\"0123456789abcdef\""),
  ASEED ("\x00" "Digest algorithm=BOGUS"),
  ASEED ("\x00" "Digest algorithm="),
  ASEED ("\x00" "Digest username*=UTF-8''a%20b"),
  ASEED ("\x00" "Digest username*=''"),
  ASEED ("\x00" "Digest username=\"\\\""),
  ASEED ("\x00" "Digest userhash=true, username=\"aaaa\""),
  ASEED ("\x00" "Digest response=\""
         "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
         "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\""),
  ASEED ("\x00" "Digest"),
  ASEED ("\x00" "Digest "),
  ASEED ("\x00" "Digest ,,,,,"),
  ASEED ("\x00" "Digest nc=\"ffffffffffffffffffffffff\""),
  ASEED ("\x01" "Basic dXNlcjpwYXNz"),
  ASEED ("\x01" "Basic "),
  ASEED ("\x01" "Basic ===="),
  ASEED ("\x01" "Basic QQ==QQ==")
};


static size_t
fuzz_seed_count (void)
{
  return sizeof (ah_seeds) / sizeof (ah_seeds[0]);
}


static const uint8_t *
fuzz_seed_get (size_t idx,
               size_t *len)
{
  *len = ah_seeds[idx].len;
  return (const uint8_t *) ah_seeds[idx].txt;
}
