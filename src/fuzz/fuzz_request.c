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
 * @file fuzz/fuzz_request.c
 * @brief End-to-end in-process fuzzer for the MHD request parser.
 * @author Christian Grothoff
 *
 * A real `struct MHD_Daemon` is created with #MHD_USE_NO_LISTEN_SOCKET
 * and driven through a `socketpair()` that is handed to MHD with
 * #MHD_add_connection().  The daemon runs in external-polling mode, so
 * everything happens in the fuzzer's thread: fully deterministic, no
 * TCP stack, no ports, no races.
 *
 * Input format (see README):
 *
 *   byte 0   configuration: connection memory limit
 *   byte 1   configuration: handler behaviour bitmask
 *   byte 2   configuration: client discipline / insanity level
 *   byte 3   configuration: digest-auth parameters
 *   byte 4.. a sequence of send-segments, each introduced by a
 *            little-endian 16 bit header  (op << 14) | length
 *              op 0  send the payload
 *              op 1  the payload is the *expected* decoded request body
 *                    (ground truth for the body oracle); nothing is sent
 *              op 2  send the payload and pump the daemon extra rounds
 *              op 3  close the connection, open a fresh one, send
 *
 * Splitting the byte stream into explicit segments matters: MHD's
 * parser is incremental and several past bugs only showed up for
 * particular split points.
 *
 * The literal ASCII token "%%NONCE%%" inside a segment is replaced,
 * at send time, by the most recent `nonce="..."` value seen in a
 * response from the daemon.  This is what allows the fuzzer to walk
 * through the Digest-Auth challenge/response handshake and reach the
 * code that is only executed for a *valid* nonce.
 */

#define FUZZ_HARNESS_NAME "fuzz_request"
#include "fuzz_common.h"

#include <microhttpd.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define MAX_SEGMENTS 96
#define MAX_CONNECTIONS 8
#define RESP_BUF_SIZE 16384
#define GEN_BUF_SIZE 8192
#define MAX_EXPECT_BODY 4096

#define DIGEST_REALM "TestRealm"
#define DIGEST_USER "user"
#define DIGEST_PASS "pass"

/* ------------------------------------------------------------------ */
/* Per-iteration state                                                 */
/* ------------------------------------------------------------------ */

struct fuzz_cfg
{
  size_t mem_limit;
  int discipline;
  unsigned int insanity;
  unsigned int nonce_nc_size;
  enum MHD_DigestAuthMultiAlgo3 algo;
  enum MHD_DigestAuthMultiQOP qop;
  int do_digest;
  int do_basic;
  int do_postproc;
  int do_iterate;
  int chunked_reply;
  int error_reply;
};

static struct fuzz_cfg cfg;

/** Most recent nonce harvested from a 401 response. */
static char nonce_val[192];
static size_t nonce_len;

/** Ground-truth body of a generated (pristine) request, see README. */
static uint8_t expect_body[MAX_EXPECT_BODY];
static size_t expect_body_len;
static int oracle_on;

/** Statistics, printed at exit with --verbose. */
static unsigned long stat_daemons;
static unsigned long stat_handler_calls;
static unsigned long stat_final_calls;
static unsigned long stat_body_bytes;
static unsigned long stat_challenges;
static unsigned long stat_auth_ok;
static int stats_registered;


static void
print_stats (void)
{
  if (! fuzz_verbose)
    return;
  fprintf (stderr,
           "%s: daemons=%lu handler calls=%lu (final=%lu) body bytes=%lu "
           "401 challenges=%lu authenticated=%lu\n",
           FUZZ_HARNESS_NAME,
           stat_daemons, stat_handler_calls, stat_final_calls,
           stat_body_bytes, stat_challenges, stat_auth_ok);
}


/** Bytes received from the daemon during the current iteration. */
static char resp_buf[RESP_BUF_SIZE];
static size_t resp_len;

static const size_t mem_limit_tbl[] = {
  0 /* MHD default */, 128, 192, 256, 320, 384, 512, 768, 1024, 1400, 1500,
  2048, 4096, 32768
};

static const int discipline_tbl[] = { -3, -2, -1, 0, 1, 2 };

/**
 * Lower bound for MHD_OPTION_CLIENT_DISCIPLINE_LVL, -3 is the full
 * range.  On a tree without the patches listed in README section 6,
 * levels below 0 reach two stale mhd_assert()s in get_req_header();
 * set MHD_FUZZ_MIN_DISCIPLINE=0 there so that the rest of the state
 * space keeps being explored.
 */
static int min_discipline = -3;
static int min_discipline_read;

/**
 * Restrict the generator to a single grammar shape (see enum gen_shape).
 * -1 (the default) means "pick a random shape every time".  Set with
 * MHD_FUZZ_SHAPE=<n>; handy for triage and for regression testing a
 * specific past bug.
 */
static int forced_shape = -1;
static int forced_shape_read;

/**
 * Lower bound for MHD_OPTION_CONNECTION_MEMORY_LIMIT.  0 (the default)
 * fuzzes the full range, including the 128 byte pools that are needed
 * to reach the read-buffer "shift back" code.  On a tree without the
 * patches listed in README section 6, pools below ~500 bytes combined
 * with a chunked request body reach two mhd_assert()s in connection.c;
 * set MHD_FUZZ_MIN_MEM_LIMIT=512 there.
 */
static size_t min_mem_limit;
static int min_mem_limit_read;

static const enum MHD_DigestAuthMultiAlgo3 algo_tbl[] = {
  MHD_DIGEST_AUTH_MULT_ALGO3_SHA256,
  MHD_DIGEST_AUTH_MULT_ALGO3_MD5,
  MHD_DIGEST_AUTH_MULT_ALGO3_SHA512_256,
  MHD_DIGEST_AUTH_MULT_ALGO3_SHA256
};

static const unsigned int nnc_tbl[] = { 4, 1, 8, 64 };

/** Fixed entropy so that nonces are reproducible across runs. */
static const char digest_rnd[32] =
  "\x01\x23\x45\x67\x89\xab\xcd\xef\x01\x23\x45\x67\x89\xab\xcd\xef"
  "\xfe\xdc\xba\x98\x76\x54\x32\x10\xfe\xdc\xba\x98\x76\x54\x32\x10";


/* ------------------------------------------------------------------ */
/* Access handler                                                      */
/* ------------------------------------------------------------------ */

struct hstate
{
  size_t body_off;
  struct MHD_PostProcessor *pp;
  int pp_tried;
};


static enum MHD_Result
kv_iter (void *cls,
         enum MHD_ValueKind kind,
         const char *key,
         const char *value)
{
  volatile size_t sink = 0;

  (void) cls;
  (void) kind;
  if (NULL != key)
    sink += strlen (key);
  if (NULL != value)
    sink += strlen (value);
  (void) sink;
  return MHD_YES;
}


static enum MHD_Result
post_iter (void *cls,
           enum MHD_ValueKind kind,
           const char *key,
           const char *filename,
           const char *content_type,
           const char *transfer_encoding,
           const char *data,
           uint64_t off,
           size_t size)
{
  volatile size_t sink = 0;

  (void) cls;
  (void) kind;
  (void) off;
  if (NULL != key)
    sink += strlen (key);
  if (NULL != filename)
    sink += strlen (filename);
  if (NULL != content_type)
    sink += strlen (content_type);
  if (NULL != transfer_encoding)
    sink += strlen (transfer_encoding);
  if ( (NULL != data) && (0 != size) )
    sink += (size_t) (unsigned char) data[size - 1];
  (void) sink;
  return MHD_YES;
}


/**
 * Check the body MHD hands to the application against the body that
 * the generator encoded into the request.  MHD is allowed to reject
 * the request at any point, but every byte that it *does* deliver must
 * be the next expected byte.  A mismatch means the framing layer
 * (Content-Length or chunked transfer coding) got out of sync, which
 * is exactly the class of bug that enables request smuggling.
 */
static void
oracle_check_body (struct hstate *hs,
                   const char *data,
                   size_t size)
{
  if ( (! oracle_on) ||
       (0 == size) )
    return;
  if ( (hs->body_off + size > expect_body_len) ||
       (0 != memcmp (expect_body + hs->body_off, data, size)) )
    fuzz_report_finding (
      "request body desync: the bytes MHD delivered to the application "
      "differ from the body encoded in the generated request "
      "(chunked/Content-Length framing bug, cf. HTTP request smuggling)");
  hs->body_off += size;
}


static enum MHD_Result
ahc (void *cls,
     struct MHD_Connection *connection,
     const char *url,
     const char *method,
     const char *version,
     const char *upload_data,
     size_t *upload_data_size,
     void **req_cls)
{
  struct hstate *hs = (struct hstate *) *req_cls;
  struct MHD_Response *resp;
  enum MHD_Result ret;
  volatile size_t sink = 0;

  (void) cls;
  if (NULL == hs)
  {
    hs = (struct hstate *) calloc (1, sizeof (struct hstate));
    if (NULL == hs)
      return MHD_NO;
    *req_cls = hs;
    return MHD_YES;
  }

  stat_handler_calls++;
  /* Touch the parsed request line the way a real application would. */
  if (NULL != url)
    sink += strlen (url);
  if (NULL != method)
    sink += strlen (method);
  if (NULL != version)
    sink += strlen (version);
  (void) sink;

  if (0 != *upload_data_size)
  {
    stat_body_bytes += (unsigned long) *upload_data_size;
    oracle_check_body (hs, upload_data, *upload_data_size);
    if (cfg.do_postproc)
    {
      if ( (NULL == hs->pp) &&
           (! hs->pp_tried) )
      {
        hs->pp_tried = 1;
        hs->pp = MHD_create_post_processor (connection,
                                            1024,
                                            &post_iter,
                                            NULL);
      }
      if (NULL != hs->pp)
        (void) MHD_post_process (hs->pp, upload_data, *upload_data_size);
    }
    *upload_data_size = 0;
    return MHD_YES;
  }

  stat_final_calls++;
  if (cfg.do_iterate)
  {
    (void) MHD_get_connection_values (connection,
                                      MHD_HEADER_KIND
                                      | MHD_GET_ARGUMENT_KIND
                                      | MHD_COOKIE_KIND
                                      | MHD_FOOTER_KIND,
                                      &kv_iter,
                                      NULL);
  }

  if (oracle_on &&
      (hs->body_off != expect_body_len) )
    fuzz_report_finding (
      "request body truncated: MHD completed the request but delivered "
      "fewer body bytes than the generated request contained");

  if (cfg.do_basic)
  {
    struct MHD_BasicAuthInfo *bai;

    bai = MHD_basic_auth_get_username_password3 (connection);
    if (NULL != bai)
    {
      if (NULL != bai->username)
        sink += bai->username_len;
      if (NULL != bai->password)
        sink += bai->password_len;
      MHD_free (bai);
    }
  }

  if (cfg.do_digest)
  {
    enum MHD_DigestAuthResult dres;

    dres = MHD_digest_auth_check3 (connection,
                                   DIGEST_REALM,
                                   DIGEST_USER,
                                   DIGEST_PASS,
                                   0 /* daemon default nonce timeout */,
                                   0 /* daemon default max_nc */,
                                   cfg.qop,
                                   MHD_DIGEST_AUTH_MULT_ALGO3_ANY_NON_SESSION);
    if (MHD_DAUTH_OK == dres)
      stat_auth_ok++;
    else
    {
      stat_challenges++;
      resp = MHD_create_response_from_buffer_static (0, "");
      if (NULL == resp)
        return MHD_NO;
      ret = MHD_queue_auth_required_response3 (connection,
                                               DIGEST_REALM,
                                               "0123456789abcdef" /* opaque */,
                                               "/",
                                               resp,
                                               (MHD_DAUTH_NONCE_STALE == dres)
                                               ? MHD_YES : MHD_NO,
                                               cfg.qop,
                                               cfg.algo,
                                               MHD_YES /* userhash */,
                                               MHD_NO);
      MHD_destroy_response (resp);
      return ret;
    }
  }

  if (cfg.chunked_reply)
    resp = MHD_create_response_from_buffer_copy (11, "hello world");
  else
    resp = MHD_create_response_from_buffer_static (2, "ok");
  if (NULL == resp)
    return MHD_NO;
  ret = MHD_queue_response (connection,
                            cfg.error_reply
                            ? MHD_HTTP_FORBIDDEN : MHD_HTTP_OK,
                            resp);
  MHD_destroy_response (resp);
  return ret;
}


static void
completed_cb (void *cls,
              struct MHD_Connection *connection,
              void **req_cls,
              enum MHD_RequestTerminationCode toe)
{
  struct hstate *hs = (struct hstate *) *req_cls;

  (void) cls;
  (void) connection;
  (void) toe;
  if (NULL == hs)
    return;
  if (NULL != hs->pp)
    (void) MHD_destroy_post_processor (hs->pp);
  free (hs);
  *req_cls = NULL;
}


static void
panic_cb (void *cls,
          const char *file,
          unsigned int line,
          const char *reason)
{
  char msg[512];

  (void) cls;
  (void) snprintf (msg, sizeof (msg),
                   "MHD_PANIC() reached from network input at %s:%u: %s",
                   (NULL != file) ? file : "?",
                   line,
                   (NULL != reason) ? reason : "?");
  fuzz_report_finding (msg);
}


/* ------------------------------------------------------------------ */
/* Driving the daemon                                                  */
/* ------------------------------------------------------------------ */

/**
 * Read whatever the daemon has produced so far and look for a fresh
 * Digest-Auth nonce in it.
 */
static void
drain_and_harvest (int sock)
{
  for (;;)
  {
    ssize_t n;
    char tmp[4096];

    n = recv (sock, tmp, sizeof (tmp), MSG_DONTWAIT);
    if (0 >= n)
      break;
    if (resp_len + (size_t) n < RESP_BUF_SIZE)
    {
      memcpy (resp_buf + resp_len, tmp, (size_t) n);
      resp_len += (size_t) n;
      resp_buf[resp_len] = '\0';
    }
  }
  if (0 != resp_len)
  {
    const char *p = resp_buf;

    while (NULL != (p = strstr (p, "nonce=\"")))
    {
      const char *s = p + 7;
      const char *e = strchr (s, '"');

      p = s;
      if (NULL == e)
        break;
      if ((size_t) (e - s) < sizeof (nonce_val))
      {
        memcpy (nonce_val, s, (size_t) (e - s));
        nonce_len = (size_t) (e - s);
        nonce_val[nonce_len] = '\0';
      }
    }
  }
}


static void
pump (struct MHD_Daemon *d,
      int sock,
      unsigned int rounds)
{
  unsigned int i;

  for (i = 0; i < rounds; i++)
  {
    (void) MHD_run (d);
    drain_and_harvest (sock);
  }
}


/**
 * Copy @a in to @a out, expanding every occurrence of the ASCII token
 * "%%NONCE%%" to the harvested nonce.
 *
 * @return number of bytes written to @a out
 */
static size_t
expand_nonce (const uint8_t *in,
              size_t in_len,
              uint8_t *out,
              size_t out_cap)
{
  static const char tok[] = "%%NONCE%%";
  const size_t tok_len = sizeof (tok) - 1;
  size_t i = 0;
  size_t o = 0;

  while (i < in_len)
  {
    if ( (i + tok_len <= in_len) &&
         (0 == memcmp (in + i, tok, tok_len)) )
    {
      if (o + nonce_len > out_cap)
        break;
      memcpy (out + o, nonce_val, nonce_len);
      o += nonce_len;
      i += tok_len;
      continue;
    }
    if (o >= out_cap)
      break;
    out[o++] = in[i++];
  }
  return o;
}


static void
send_all (struct MHD_Daemon *d,
          int sock,
          const uint8_t *data,
          size_t len)
{
  size_t off = 0;
  unsigned int stall = 0;

  while ( (off < len) &&
          (stall < 64) )
  {
    ssize_t s = send (sock, data + off, len - off, MSG_DONTWAIT);

    if (0 < s)
    {
      off += (size_t) s;
      stall = 0;
      continue;
    }
    stall++;
    pump (d, sock, 2);
    if ( (0 > s) &&
         (EAGAIN != errno) &&
         (EWOULDBLOCK != errno) &&
         (EINTR != errno) )
      break;
  }
}


static int
new_connection (struct MHD_Daemon *d,
                int *sock)
{
  int sv[2];
  struct sockaddr_in sa;

  if (0 != socketpair (AF_UNIX, SOCK_STREAM, 0, sv))
    return -1;
  memset (&sa, 0, sizeof (sa));
  sa.sin_family = AF_INET;
  sa.sin_port = htons (44444);
  sa.sin_addr.s_addr = htonl (INADDR_LOOPBACK);
  if (MHD_YES != MHD_add_connection (d,
                                     (MHD_socket) sv[1],
                                     (const struct sockaddr *) &sa,
                                     (socklen_t) sizeof (sa)))
  {
    /* MHD has already closed sv[1] in that case */
    (void) close (sv[0]);
    return -1;
  }
  *sock = sv[0];
  return 0;
}


static void
close_connection (struct MHD_Daemon *d,
                  int *sock)
{
  if (0 > *sock)
    return;
  (void) shutdown (*sock, SHUT_WR);
  pump (d, *sock, 4);
  (void) close (*sock);
  *sock = -1;
}


/* ------------------------------------------------------------------ */
/* The fuzz target                                                     */
/* ------------------------------------------------------------------ */

int
LLVMFuzzerTestOneInput (const uint8_t *data,
                        size_t size)
{
  struct MHD_Daemon *d;
  struct MHD_OptionItem opts[8];
  unsigned int nopt = 0;
  unsigned int flags;
  int sock = -1;
  size_t pos;
  unsigned int nseg = 0;
  unsigned int nconn = 1;
  static uint8_t xbuf[FUZZ_MAX_INPUT + 4096];

  if (size < 6)
    return 0;

  nonce_len = 0;
  nonce_val[0] = '\0';
  resp_len = 0;
  resp_buf[0] = '\0';

  memset (&cfg, 0, sizeof (cfg));
  cfg.mem_limit =
    mem_limit_tbl[data[0] % (sizeof (mem_limit_tbl)
                             / sizeof (mem_limit_tbl[0]))];
  cfg.do_digest = (0 != (data[1] & 0x01));
  cfg.do_basic = (0 != (data[1] & 0x02));
  cfg.do_postproc = (0 != (data[1] & 0x04));
  cfg.do_iterate = (0 != (data[1] & 0x08));
  cfg.chunked_reply = (0 != (data[1] & 0x20));
  cfg.error_reply = (0 != (data[1] & 0x40));
  if (! min_mem_limit_read)
  {
    const char *e = getenv ("MHD_FUZZ_MIN_MEM_LIMIT");

    min_mem_limit_read = 1;
    if (NULL != e)
      min_mem_limit = (size_t) strtoul (e, NULL, 10);
  }
  if ( (0 != cfg.mem_limit) &&
       (cfg.mem_limit < min_mem_limit) )
    cfg.mem_limit = min_mem_limit;
  if (! min_discipline_read)
  {
    const char *e = getenv ("MHD_FUZZ_MIN_DISCIPLINE");

    min_discipline_read = 1;
    if (NULL != e)
      min_discipline = atoi (e);
  }
  cfg.discipline =
    discipline_tbl[(data[2] & 0x0F) % (sizeof (discipline_tbl)
                                       / sizeof (discipline_tbl[0]))];
  if (cfg.discipline < min_discipline)
    cfg.discipline = min_discipline;
  cfg.insanity = (unsigned int) MHD_DSC_SANE;
  cfg.algo = algo_tbl[data[3] & 0x03];
  cfg.qop = (0 != (data[3] & 0x04))
            ? MHD_DIGEST_AUTH_MULT_QOP_AUTH
            : MHD_DIGEST_AUTH_MULT_QOP_ANY_NON_INT;
  cfg.nonce_nc_size = nnc_tbl[(data[3] >> 4) & 0x03];

  oracle_on = 0;
  expect_body_len = 0;

  if (0 != cfg.mem_limit)
  {
    opts[nopt].option = MHD_OPTION_CONNECTION_MEMORY_LIMIT;
    opts[nopt].value = (intptr_t) cfg.mem_limit;
    opts[nopt].ptr_value = NULL;
    nopt++;
  }
  opts[nopt].option = MHD_OPTION_CLIENT_DISCIPLINE_LVL;
  opts[nopt].value = (intptr_t) cfg.discipline;
  opts[nopt].ptr_value = NULL;
  nopt++;
  opts[nopt].option = MHD_OPTION_SERVER_INSANITY;
  opts[nopt].value = (intptr_t) cfg.insanity;
  opts[nopt].ptr_value = NULL;
  nopt++;
  opts[nopt].option = MHD_OPTION_NONCE_NC_SIZE;
  opts[nopt].value = (intptr_t) cfg.nonce_nc_size;
  opts[nopt].ptr_value = NULL;
  nopt++;
  opts[nopt].option = MHD_OPTION_DIGEST_AUTH_RANDOM;
  opts[nopt].value = (intptr_t) sizeof (digest_rnd);
  opts[nopt].ptr_value = (void *) (intptr_t) digest_rnd;
  nopt++;
  opts[nopt].option = MHD_OPTION_END;
  opts[nopt].value = 0;
  opts[nopt].ptr_value = NULL;

  flags = MHD_USE_NO_LISTEN_SOCKET;
  if (fuzz_verbose)
    flags |= MHD_USE_ERROR_LOG;

  MHD_set_panic_func (&panic_cb, NULL);
  d = MHD_start_daemon (flags,
                        0,
                        NULL, NULL,
                        &ahc, NULL,
                        MHD_OPTION_ARRAY, opts,
                        /* passed through the varargs rather than through
                           the option array: storing a function pointer in
                           the array's intptr_t member is not strictly
                           conforming C */
                        MHD_OPTION_NOTIFY_COMPLETED, &completed_cb, NULL,
                        MHD_OPTION_END);
  if (NULL == d)
    return 0;
  stat_daemons++;
  if (! stats_registered)
  {
    stats_registered = 1;
    (void) atexit (&print_stats);
  }

  if (0 != new_connection (d, &sock))
  {
    MHD_stop_daemon (d);
    return 0;
  }

  pos = 4;
  while ( (pos + 2 <= size) &&
          (nseg < MAX_SEGMENTS) )
  {
    unsigned int hdr = (unsigned int) data[pos]
                       | ((unsigned int) data[pos + 1] << 8);
    unsigned int op = hdr >> 14;
    size_t slen = (size_t) (hdr & 0x3FFF);
    size_t elen;

    pos += 2;
    nseg++;
    if (slen > size - pos)
      slen = size - pos;

    if (1 == op)
    {
      /* Ground-truth declaration, not wire data. */
      if (fuzz_pristine && (slen <= MAX_EXPECT_BODY))
      {
        memcpy (expect_body, data + pos, slen);
        expect_body_len = slen;
        oracle_on = 1;
      }
      pos += slen;
      continue;
    }
    if ( (3 == op) &&
         (nconn < MAX_CONNECTIONS) )
    {
      close_connection (d, &sock);
      if (0 != new_connection (d, &sock))
        break;
      nconn++;
    }

    elen = expand_nonce (data + pos, slen, xbuf, sizeof (xbuf));
    pos += slen;
    if (0 != elen)
      send_all (d, sock, xbuf, elen);
    pump (d, sock, (2 == op) ? 12u : 3u);
    if (0 == slen)
      pump (d, sock, 4);
  }

  close_connection (d, &sock);
  pump (d, sock, 4);
  MHD_stop_daemon (d);
  return 0;
}


/* ------------------------------------------------------------------ */
/* Structure-aware HTTP request generator                              */
/* ------------------------------------------------------------------ */

struct sbuf
{
  uint8_t *p;
  size_t len;
  size_t cap;
};


static void
sb_raw (struct sbuf *b,
        const void *v,
        size_t n)
{
  if (b->len + n > b->cap)
    n = b->cap - b->len;
  memcpy (b->p + b->len, v, n);
  b->len += n;
}


static void
sb_str (struct sbuf *b,
        const char *s)
{
  sb_raw (b, s, strlen (s));
}


static void
sb_u64 (struct sbuf *b,
        uint64_t v,
        int hex,
        unsigned int min_digits)
{
  char tmp[32];
  unsigned int n = 0;

  do
  {
    unsigned int dig = (unsigned int) (v % (hex ? 16u : 10u));
    tmp[n++] = (char) ((dig < 10) ? ('0' + dig) : ('a' + dig - 10));
    v /= (hex ? 16u : 10u);
  }
  while ( (0 != v) && (n < sizeof (tmp)) );
  while ( (n < min_digits) && (n < sizeof (tmp)) )
    tmp[n++] = '0';
  while (0 != n)
  {
    char c = tmp[--n];
    sb_raw (b, &c, 1);
  }
}


static const char *const gen_methods[] = {
  "GET", "POST", "PUT", "HEAD", "DELETE", "OPTIONS", "TRACE", "PATCH",
  "CONNECT", "BREW", "get", "M-SEARCH", "\tGET", "GET "
};

static const char *const gen_versions[] = {
  "HTTP/1.1", "HTTP/1.0", "HTTP/1.1", "HTTP/1.1", "HTTP/0.9", "HTTP/1.2",
  "HTTP/2.0", "http/1.1", "HTTP/1.", "HTTP/11"
};

static const char *const gen_targets[] = {
  "/", "/a", "/a/b/c", "/a?x=1", "/a?x=1&y=2", "/?novalue", "/?a=1&b",
  "/?a&b&c", "/%41%42", "/a%00b", "/%zz", "/a?%41=%42", "*",
  "http://example.org/a", "/a?x=1&novalue", "/..%2f..%2fetc",
  "/a?=", "/a?&", "/very/long/path/that/keeps/going/and/going/and/going"
};

static const char *const gen_hdr_names[] = {
  "Host", "Accept", "User-Agent", "Connection", "Cookie", "Content-Type",
  "Expect", "TE", "Trailer", "X-Custom", "Referer", "Accept-Encoding",
  "content-length", "transfer-encoding", "X-A-Very-Long-Header-Name-Indeed"
};

static const char *const gen_hdr_values[] = {
  "example.org", "*/*", "fuzz/1.0", "keep-alive", "close",
  "a=1; b=2; c", "100-continue", "trailers", "X-Trail", "value",
  "", " ", "\ttabbed", "a, b, c", "chunked", "identity, chunked"
};

/** Deliberately includes tokens MHD does not know: bug #1 lives here. */
static const char *const gen_algos[] = {
  "MD5", "SHA-256", "SHA-512-256", "MD5-sess", "SHA-256-sess",
  "SHA-512-256-sess", "sha-256", "SHA256", "BOGUS", "", "\"SHA-256\"",
  "MD5 ", "SHA-1", "xyzzy", "SHA-512", "\"BOGUS\"", "0"
};

static const char *const gen_ctypes[] = {
  "application/x-www-form-urlencoded",
  "multipart/form-data; boundary=--abc",
  "multipart/form-data; boundary=\"XY\"",
  "multipart/form-data",
  "text/plain"
};


/**
 * Append a random query string, optionally ending in an argument
 * without '=' (which is the shape needed for the read-buffer shift-back
 * bug).
 */
static void
gen_query (struct fuzz_rng *rng,
           struct sbuf *b,
           int force_trailing_novalue)
{
  unsigned int n = fuzz_below (rng, 4);
  unsigned int i;

  if ( (0 == n) && (! force_trailing_novalue) )
    return;
  sb_str (b, "?");
  for (i = 0; i < n; i++)
  {
    if (0 != i)
      sb_str (b, "&");
    sb_str (b, "k");
    sb_u64 (b, i, 0, 1);
    if (! fuzz_chance (rng, 3))
    {
      sb_str (b, "=");
      sb_str (b, fuzz_chance (rng, 4) ? "%41%42" : "v");
    }
  }
  if (force_trailing_novalue)
  {
    if (0 != n)
      sb_str (b, "&");
    sb_str (b, "novalue");
  }
}


static void
gen_headers (struct fuzz_rng *rng,
             struct sbuf *b,
             unsigned int n)
{
  unsigned int i;

  for (i = 0; i < n; i++)
  {
    sb_str (b, gen_hdr_names[fuzz_below (rng,
                                         (uint32_t) (sizeof (gen_hdr_names)
                                                     / sizeof (char *)))]);
    sb_str (b, fuzz_chance (rng, 8) ? " :" : ":");
    if (! fuzz_chance (rng, 6))
      sb_str (b, " ");
    sb_str (b, gen_hdr_values[fuzz_below (rng,
                                          (uint32_t) (sizeof (gen_hdr_values)
                                                      / sizeof (char *)))]);
    if (fuzz_chance (rng, 12))
      sb_str (b, "\r\n\tfolded-continuation");
    if (fuzz_chance (rng, 20))
      sb_str (b, "\n");     /* bare LF */
    else if (fuzz_chance (rng, 25))
      sb_str (b, "\r");     /* bare CR */
    else
      sb_str (b, "\r\n");
  }
}


/**
 * Emit a chunked body.  When @a oracle is non-zero the body is
 * strictly RFC 9112 conformant and the decoded payload is recorded in
 * #expect_body, so that the harness can verify what MHD hands to the
 * application.  Chunk extensions are emitted frequently on purpose.
 */
static void
gen_chunked_body (struct fuzz_rng *rng,
                  struct sbuf *b,
                  int oracle)
{
  unsigned int nchunks = 1 + fuzz_below (rng, 4);
  unsigned int i;

  if (oracle)
    expect_body_len = 0;
  for (i = 0; i < nchunks; i++)
  {
    unsigned int clen = 1 + fuzz_below (rng, 24);
    unsigned int j;

    sb_u64 (b, clen, 1, fuzz_chance (rng, 4) ? 4 : 1);
    /* chunk extension -- the parsing of the terminating CRLF of this
       very line was broken (bug #3) */
    if (! fuzz_chance (rng, 2))
    {
      switch (fuzz_below (rng, 5))
      {
      case 0:
        sb_str (b, ";ext");
        break;
      case 1:
        sb_str (b, ";ext=val");
        break;
      case 2:
        sb_str (b, ";ext=\"quoted value\"");
        break;
      case 3:
        sb_str (b, ";a=1;b=2;c");
        break;
      default:
        sb_str (b, ";x=\"a;b\"");
        break;
      }
    }
    sb_str (b, "\r\n");
    for (j = 0; j < clen; j++)
    {
      char c = (char) ('A' + ((i * 7 + j) % 26));

      sb_raw (b, &c, 1);
      if (oracle && (expect_body_len < MAX_EXPECT_BODY))
        expect_body[expect_body_len++] = (uint8_t) c;
    }
    sb_str (b, "\r\n");
  }
  sb_str (b, "0");
  if (fuzz_chance (rng, 4))
    sb_str (b, ";final=\"x\"");
  sb_str (b, "\r\n");
  if (fuzz_chance (rng, 3))
    sb_str (b, "X-Trailer: value\r\n");
  sb_str (b, "\r\n");
}


static void
gen_digest_header (struct fuzz_rng *rng,
                   struct sbuf *b,
                   const char *uri,
                   int use_nonce_token,
                   int overlong_response,
                   int prefer_valid)
{
  unsigned int nresp;
  unsigned int i;

  sb_str (b, "Authorization: Digest ");
  sb_str (b, "username=\"");
  if (fuzz_chance (rng, prefer_valid ? 20 : 6))
  {
    /* userhash notation: a long hex string is accepted here too */
    unsigned int n = 2 * (16 + fuzz_below (rng, 48));
    for (i = 0; i < n; i++)
      sb_str (b, "a");
  }
  else
    sb_str (b, DIGEST_USER);
  sb_str (b, "\", ");
  if (fuzz_chance (rng, prefer_valid ? 25 : 8))
    sb_str (b, "userhash=true, ");
  sb_str (b, "realm=\"");
  sb_str (b, fuzz_chance (rng, prefer_valid ? 25 : 8)
          ? "OtherRealm" : DIGEST_REALM);
  sb_str (b, "\", nonce=\"");
  if (use_nonce_token)
    sb_str (b, "%%NONCE%%");
  else
  {
    unsigned int n = 8 + fuzz_below (rng, 80);
    for (i = 0; i < n; i++)
      sb_str (b, "0");
  }
  sb_str (b, "\", uri=\"");
  sb_str (b, uri);
  sb_str (b, "\", qop=");
  sb_str (b, fuzz_chance (rng, prefer_valid ? 25 : 8) ? "auth-int" : "auth");
  sb_str (b, ", nc=");
  sb_u64 (b, 1 + fuzz_below (rng, 3), 1, 8);
  sb_str (b, ", cnonce=\"deadbeef\", algorithm=");
  if (prefer_valid && (! fuzz_chance (rng, 5)))
    sb_str (b, "SHA-256");   /* must match the algorithm of the challenge */
  else
    sb_str (b, gen_algos[fuzz_below (rng,
                                     (uint32_t) (sizeof (gen_algos)
                                                 / sizeof (char *)))]);
  sb_str (b, ", opaque=\"0123456789abcdef\", response=\"");
  if (overlong_response)
    nresp = 66 + 2 * fuzz_below (rng, 32);      /* 66 .. 128 hex digits */
  else
    nresp = 2 * (1 + fuzz_below (rng, 66));
  for (i = 0; i < nresp; i++)
  {
    char c = "0123456789abcdef"[fuzz_below (rng, 16)];

    sb_raw (b, &c, 1);
  }
  sb_str (b, "\"\r\n");
}


enum gen_shape
{
  SHAPE_PLAIN = 0,
  SHAPE_NOHDR_QARG,
  SHAPE_CL_BODY,
  SHAPE_CHUNKED,
  SHAPE_DIGEST_SIMPLE,
  SHAPE_DIGEST_REPLAY,
  SHAPE_BASIC,
  SHAPE_POST_FORM,
  SHAPE_WEIRD,
  SHAPE_COUNT
};


/**
 * Build one HTTP request into @a b.
 *
 * @return non-zero if the request is exactly reproducible, i.e. the
 *         #expect_body oracle may be used
 */
static int
gen_one_request (struct fuzz_rng *rng,
                 struct sbuf *b,
                 enum gen_shape shape,
                 int second_of_pair)
{
  switch (shape)
  {
  case SHAPE_NOHDR_QARG:
    /* No header lines at all + a trailing query argument without '=';
       combined with a small connection memory pool this is the shape
       that reaches the read-buffer "shift back" computation. */
    sb_str (b, "GET /");
    gen_query (rng, b, 1);
    sb_str (b, " ");
    sb_str (b, fuzz_chance (rng, 2) ? "HTTP/1.0" : "HTTP/1.1");
    sb_str (b, "\r\n\r\n");
    return 0;

  case SHAPE_CL_BODY:
    {
      unsigned int blen = fuzz_below (rng, 64);
      unsigned int i;

      sb_str (b, "POST /a HTTP/1.1\r\nHost: x\r\nContent-Length: ");
      sb_u64 (b, blen, 0, 1);
      sb_str (b, "\r\n\r\n");
      expect_body_len = 0;
      for (i = 0; i < blen; i++)
      {
        char c = (char) ('a' + (i % 26));

        sb_raw (b, &c, 1);
        if (expect_body_len < MAX_EXPECT_BODY)
          expect_body[expect_body_len++] = (uint8_t) c;
      }
      return 1;
    }

  case SHAPE_CHUNKED:
    sb_str (b, "POST /a HTTP/1.1\r\nHost: x\r\n"
            "Transfer-Encoding: chunked\r\n\r\n");
    gen_chunked_body (rng, b, 1);
    return 1;

  case SHAPE_DIGEST_SIMPLE:
    sb_str (b, "GET /a HTTP/1.1\r\nHost: x\r\n");
    gen_digest_header (rng, b, "/a", 0, fuzz_chance (rng, 2), 0);
    sb_str (b, "\r\n");
    return 0;

  case SHAPE_DIGEST_REPLAY:
    if (! second_of_pair)
      sb_str (b, "GET /a HTTP/1.1\r\nHost: x\r\n\r\n");
    else
    {
      sb_str (b, "GET /a HTTP/1.1\r\nHost: x\r\n");
      gen_digest_header (rng, b, "/a", 1, 1, 1);
      sb_str (b, "\r\n");
    }
    return 0;

  case SHAPE_BASIC:
    sb_str (b, "GET /a HTTP/1.1\r\nHost: x\r\nAuthorization: Basic ");
    {
      unsigned int n = fuzz_below (rng, 40);
      unsigned int i;

      for (i = 0; i < n; i++)
      {
        char c =
          "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
          [fuzz_below (rng, 65)];

        sb_raw (b, &c, 1);
      }
    }
    sb_str (b, "\r\n\r\n");
    return 0;

  case SHAPE_POST_FORM:
    {
      const char *ct = gen_ctypes[fuzz_below (rng,
                                              (uint32_t) (sizeof (gen_ctypes)
                                                          / sizeof (char *)))];

      sb_str (b, "POST /a HTTP/1.1\r\nHost: x\r\nContent-Type: ");
      sb_str (b, ct);
      sb_str (b, "\r\nTransfer-Encoding: chunked\r\n\r\n");
      gen_chunked_body (rng, b, 0);
      return 0;
    }

  case SHAPE_WEIRD:
    sb_str (b, gen_methods[fuzz_below (rng,
                                       (uint32_t) (sizeof (gen_methods)
                                                   / sizeof (char *)))]);
    sb_str (b, " ");
    sb_str (b, gen_targets[fuzz_below (rng,
                                       (uint32_t) (sizeof (gen_targets)
                                                   / sizeof (char *)))]);
    sb_str (b, " ");
    sb_str (b, gen_versions[fuzz_below (rng,
                                        (uint32_t) (sizeof (gen_versions)
                                                    / sizeof (char *)))]);
    sb_str (b, fuzz_chance (rng, 8) ? "\n" : "\r\n");
    gen_headers (rng, b, fuzz_below (rng, 6));
    sb_str (b, "\r\n");
    return 0;

  case SHAPE_PLAIN:
  case SHAPE_COUNT:
  default:
    sb_str (b, gen_methods[fuzz_below (rng, 3)]);
    sb_str (b, " /");
    gen_query (rng, b, fuzz_chance (rng, 3));
    sb_str (b, " HTTP/1.1\r\n");
    gen_headers (rng, b, fuzz_below (rng, 4));
    sb_str (b, "\r\n");
    return 0;
  }
}


/**
 * Serialise @a body into the segment format understood by
 * LLVMFuzzerTestOneInput(), starting at @a out[*out_len].
 */
static void
emit_segments (struct fuzz_rng *rng,
               struct sbuf *out,
               const uint8_t *body,
               size_t body_len,
               int new_conn_first)
{
  size_t off = 0;
  int first = 1;

  while (off < body_len)
  {
    size_t chunk;
    unsigned int op;
    uint8_t hdr[2];
    unsigned int hv;

    switch (fuzz_below (rng, 6))
    {
    case 0:
      chunk = 1;
      break;
    case 1:
      chunk = 2 + fuzz_below (rng, 6);
      break;
    case 2:
      chunk = 8 + fuzz_below (rng, 40);
      break;
    default:
      chunk = body_len - off;
      break;
    }
    if (chunk > body_len - off)
      chunk = body_len - off;
    if (chunk > 0x3FFF)
      chunk = 0x3FFF;
    op = (first && new_conn_first) ? 3u : (fuzz_chance (rng, 4) ? 2u : 0u);
    hv = (op << 14) | (unsigned int) chunk;
    hdr[0] = (uint8_t) (hv & 0xFF);
    hdr[1] = (uint8_t) (hv >> 8);
    if (out->len + 2 + chunk > out->cap)
      return;
    sb_raw (out, hdr, 2);
    sb_raw (out, body + off, chunk);
    off += chunk;
    first = 0;
  }
}


static size_t
fuzz_generate (struct fuzz_rng *rng,
               uint8_t *buf,
               size_t cap)
{
  struct sbuf out;
  uint8_t req[GEN_BUF_SIZE];
  struct sbuf rb;
  enum gen_shape shape;
  uint8_t cfg_bytes[4];
  int oracle;
  unsigned int nreq;
  unsigned int i;

  expect_body_len = 0;

  out.p = buf;
  out.len = 0;
  out.cap = cap;

  if (! forced_shape_read)
  {
    const char *e = getenv ("MHD_FUZZ_SHAPE");

    forced_shape_read = 1;
    if (NULL != e)
      forced_shape = atoi (e);
  }
  if (0 <= forced_shape)
    shape = (enum gen_shape) (forced_shape % (int) SHAPE_COUNT);
  else
    shape = (enum gen_shape) fuzz_below (rng, (uint32_t) SHAPE_COUNT);

  /* --- configuration bytes --- */
  cfg_bytes[0] = fuzz_byte (rng);
  cfg_bytes[1] = fuzz_byte (rng);
  cfg_bytes[2] = fuzz_byte (rng);
  cfg_bytes[3] = fuzz_byte (rng);
  switch (shape)
  {
  case SHAPE_NOHDR_QARG:
    /* small connection memory pool: indices 1..9 of mem_limit_tbl */
    cfg_bytes[0] = (uint8_t) (1 + fuzz_below (rng, 9));
    break;
  case SHAPE_DIGEST_SIMPLE:
  case SHAPE_DIGEST_REPLAY:
    cfg_bytes[0] = (uint8_t) (fuzz_chance (rng, 2) ? 0 : 12);
    cfg_bytes[1] = (uint8_t) ((cfg_bytes[1] | 0x01u) & ~0x04u);
    /* SHA-256 challenge: 32 byte digest -> 128 hex chars pass the
       'response' length check while hash1_bin[] is only 32 bytes */
    cfg_bytes[3] = (uint8_t) ((cfg_bytes[3] & 0xF0u) | 0x00u);
    break;
  case SHAPE_POST_FORM:
    cfg_bytes[1] |= 0x04u;
    break;
  case SHAPE_CHUNKED:
  case SHAPE_CL_BODY:
    cfg_bytes[1] &= (uint8_t) ~0x04u;   /* keep the body oracle clean */
    break;
  default:
    break;
  }
  cfg_bytes[1] |= 0x08u;                /* always iterate the values */
  sb_raw (&out, cfg_bytes, 4);

  nreq = (SHAPE_DIGEST_REPLAY == shape) ? 2u : (1u + (fuzz_chance (rng, 6)
                                                      ? 1u : 0u));
  oracle = 0;
  for (i = 0; i < nreq; i++)
  {
    rb.p = req;
    rb.len = 0;
    rb.cap = sizeof (req);
    oracle = gen_one_request (rng, &rb, shape, (int) i);
    if (oracle && (1 == nreq) && (expect_body_len <= MAX_EXPECT_BODY))
    {
      /* Declare the ground truth for the body oracle (op 1). */
      unsigned int hv = (1u << 14) | (unsigned int) expect_body_len;
      uint8_t hdr[2];

      hdr[0] = (uint8_t) (hv & 0xFF);
      hdr[1] = (uint8_t) (hv >> 8);
      sb_raw (&out, hdr, 2);
      sb_raw (&out, expect_body, expect_body_len);
    }
    emit_segments (rng, &out, req, rb.len,
                   (0 != i) || fuzz_chance (rng, 8));
  }
  (void) oracle;
  return out.len;
}


/* ------------------------------------------------------------------ */
/* Built-in seed corpus                                                */
/* ------------------------------------------------------------------ */

/**
 * The built-in seed corpus is described symbolically and rendered into
 * the wire format at run time, so that segment lengths never have to be
 * spelled out by hand.
 */
struct seed_part
{
  unsigned int op;              /**< 0 send, 1 expected body, 3 new conn */
  const char *txt;              /**< NUL terminated payload */
};

struct seed_def
{
  const char *name;
  unsigned char cfg[4];
  struct seed_part parts[4];
};

#define P_END { 0, NULL }

static const struct seed_def seeds[] = {
  { "plain", { 0x00, 0x08, 0x03, 0x00 },
    { { 0, "GET / HTTP/1.1\r\nHost: x\r\n\r\n" }, P_END, P_END, P_END } },

  { "content-length-body", { 0x00, 0x08, 0x03, 0x00 },
    { { 1, "hello" },
      { 0, "POST /a HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nhello" },
      P_END, P_END } },

  /* chunk extensions: the terminating CRLF of the chunk-size line used
     to be left in the stream (bug #3, commit c13f4c64) */
  { "chunked-with-extensions", { 0x00, 0x08, 0x03, 0x00 },
    { { 1, "ABCDE" },
      { 0, "POST /a HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n"
        "\r\n2;ext=val\r\nAB\r\n3;a=\"b;c\"\r\nCDE\r\n0\r\n\r\n" },
      P_END, P_END } },

  { "chunked-split", { 0x00, 0x08, 0x03, 0x00 },
    { { 1, "ABCDEF" },
      { 0, "POST /a HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n"
        "\r\n3\r\nABC\r\n3;x=\"y\"" },
      { 2, "\r\nDEF\r\n0\r\n\r\n" },
      P_END } },

  /* small connection memory pool + trailing query argument without '='
     and no header lines at all (bug #2, commit 29eaa56b) */
  { "small-pool-trailing-query-arg", { 0x06, 0x08, 0x03, 0x00 },
    { { 0, "GET /?novalue HTTP/1.0\r\n\r\n" }, P_END, P_END, P_END } },

  { "small-pool-trailing-query-arg-2", { 0x03, 0x08, 0x03, 0x00 },
    { { 0, "GET /?a=1&b HTTP/1.0\r\n\r\n" }, P_END, P_END, P_END } },

  /* unrecognised 'algorithm' token -> MHD_DIGEST_AUTH_ALGO3_INVALID
     (bug #1, commit bd49ce93) */
  { "digest-unknown-algorithm", { 0x00, 0x09, 0x03, 0x00 },
    { { 0, "GET /a HTTP/1.1\r\nHost: x\r\nAuthorization: Digest "
        "username=\"user\", realm=\"TestRealm\", nonce=\"0000\", "
        "uri=\"/a\", algorithm=BOGUS, response=\"00\"\r\n\r\n" },
      P_END, P_END, P_END } },

  /* full digest handshake: harvest the nonce from the 401 and replay it
     with a 128 hex digit 'response' value (bug #4, commit 5a73c1ae) */
  { "digest-overlong-response", { 0x00, 0x09, 0x03, 0x00 },
    { { 0, "GET /a HTTP/1.1\r\nHost: x\r\n\r\n" },
      { 3, "GET /a HTTP/1.1\r\nHost: x\r\nAuthorization: Digest "
        "username=\"user\", realm=\"TestRealm\", nonce=\"%%NONCE%%\", "
        "uri=\"/a\", qop=auth, nc=00000001, cnonce=\"deadbeef\", "
        "algorithm=SHA-256, response=\""
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        "\"\r\n\r\n" },
      P_END, P_END } },

  { "digest-userhash", { 0x00, 0x09, 0x03, 0x00 },
    { { 0, "GET /a HTTP/1.1\r\nHost: x\r\n\r\n" },
      { 3, "GET /a HTTP/1.1\r\nHost: x\r\nAuthorization: Digest "
        "username=\""
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "\", userhash=true, realm=\"TestRealm\", nonce=\"%%NONCE%%\", "
        "uri=\"/a\", qop=auth, nc=00000001, cnonce=\"deadbeef\", "
        "algorithm=SHA-256, response=\"0123456789abcdef\"\r\n\r\n" },
      P_END, P_END } },

  { "basic-auth", { 0x00, 0x0a, 0x03, 0x00 },
    { { 0, "GET /a HTTP/1.1\r\nHost: x\r\n"
        "Authorization: Basic dXNlcjpwYXNz\r\n\r\n" },
      P_END, P_END, P_END } },

  { "multipart-post", { 0x00, 0x0c, 0x03, 0x00 },
    { { 0, "POST /a HTTP/1.1\r\nHost: x\r\n"
        "Content-Type: multipart/form-data; boundary=--abc\r\n"
        "Transfer-Encoding: chunked\r\n\r\n"
        "52\r\n----abc\r\nContent-Disposition: form-data; name=\"k\"\r\n\r\n"
        "value\r\n----abc--\r\n\r\n0\r\n\r\n" },
      P_END, P_END, P_END } },

  { "urlencoded-post", { 0x00, 0x0c, 0x03, 0x00 },
    { { 1, "a=1&b=%41&c" },
      { 0, "POST /a HTTP/1.1\r\nHost: x\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        "Content-Length: 11\r\n\r\na=1&b=%41&c" },
      P_END, P_END } },

  { "folded-header", { 0x00, 0x08, 0x00, 0x00 },
    { { 0, "GET /a HTTP/1.1\r\nHost: x\r\nX-Fold: a\r\n\tb\r\n\r\n" },
      P_END, P_END, P_END } },

  { "pipelined", { 0x00, 0x08, 0x03, 0x00 },
    { { 0, "GET /a HTTP/1.1\r\nHost: x\r\n\r\n"
        "GET /b?q HTTP/1.1\r\nHost: x\r\n\r\n" },
      P_END, P_END, P_END } }
};

static uint8_t seed_render_buf[4096];


static size_t
fuzz_seed_count (void)
{
  return sizeof (seeds) / sizeof (seeds[0]);
}


static const uint8_t *
fuzz_seed_get (size_t idx,
               size_t *len)
{
  const struct seed_def *sd = &seeds[idx];
  struct sbuf b;
  unsigned int i;

  b.p = seed_render_buf;
  b.len = 0;
  b.cap = sizeof (seed_render_buf);
  sb_raw (&b, sd->cfg, 4);
  for (i = 0; i < sizeof (sd->parts) / sizeof (sd->parts[0]); i++)
  {
    size_t n;
    unsigned int hv;
    uint8_t hdr[2];

    if (NULL == sd->parts[i].txt)
      break;
    n = strlen (sd->parts[i].txt);
    if (n > 0x3FFF)
      n = 0x3FFF;
    hv = (sd->parts[i].op << 14) | (unsigned int) n;
    hdr[0] = (uint8_t) (hv & 0xFF);
    hdr[1] = (uint8_t) (hv >> 8);
    sb_raw (&b, hdr, 2);
    sb_raw (&b, sd->parts[i].txt, n);
  }
  *len = b.len;
  return seed_render_buf;
}
