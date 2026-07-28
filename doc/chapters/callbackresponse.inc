All responses we have built so far were complete before they were
queued.  @code{MHD_create_response_from_buffer()} needs the whole
answer to be sitting in memory already, and
@code{MHD_create_response_from_fd()} needs it to be a file that the
operating system can read for us.  Neither fits an answer that is
computed while it is being sent: the output of a long-running report,
a log file that is filtered on the fly, the result of a database
cursor, or simply a document that is far too large to be worth
assembling in a buffer first.

For those cases @emph{libmicrohttpd} lets the application hand over a
callback instead of the data.  Whenever @emph{MHD} has room on the
socket, it calls that function and asks for the next few bytes.  The
application only ever needs one modest buffer, and the client starts
receiving the answer long before the last byte has been produced.


@heading Creating the response

The response object is created with

@verbatim
struct MHD_Response *
MHD_create_response_from_callback (uint64_t size,
                                   size_t block_size,
                                   MHD_ContentReaderCallback crc,
                                   void *crc_cls,
                                   MHD_ContentReaderFreeCallback crfc);
@end verbatim
@noindent

The five arguments are:

@table @code
@item size
The total length of the body in bytes, or the constant
@code{MHD_SIZE_UNKNOWN} if the application does not know it in
advance.  If a concrete number is given, @emph{MHD} announces it as
@code{Content-Length} and expects the callback to deliver exactly that
many bytes.

@item block_size
The buffer size @emph{MHD} should use when it queries the callback.
The value must not be zero---@code{MHD_create_response_from_callback()}
returns @code{NULL} otherwise.  @emph{MHD} allocates a buffer of that
size together with the response object.  Note that this buffer is only
used for responses of known size; when chunked transfer encoding is in
use (see below) the data is collected in the connection's own memory
pool instead, and @code{block_size} has no influence on how much
@emph{MHD} asks for.  In either case the value is advisory: the
callback must always look at the @code{max} argument it is passed and
never write more than that.

@item crc
The content reader callback itself, described in the next section.

@item crc_cls
An arbitrary pointer that is passed back to @code{crc} on every
invocation.  This is where the per-request state goes.

@item crfc
A callback that is invoked once, when the response object is
destroyed, so that @code{crc_cls} can be released.  May be
@code{NULL} if there is nothing to clean up.
@end table


@heading The content reader callback

The callback has the following signature:

@verbatim
typedef ssize_t
(*MHD_ContentReaderCallback) (void *cls,
                              uint64_t pos,
                              char *buf,
                              size_t max);
@end verbatim
@noindent

@code{cls} is the @code{crc_cls} pointer given at creation time.
@code{buf} points to the memory @emph{MHD} wants filled and
@code{max} is the number of bytes that may be written there.

The @code{pos} argument deserves a closer look, because its meaning
depends on how the response is used.  For a response created from a
file descriptor, @emph{MHD} uses it as a file offset and reads with
@code{pread()}; that is what makes such a response object reusable for
many connections.  For a response that is created fresh for each
request---which is what we do here---@emph{MHD} guarantees that
@code{pos} is simply the sum of all non-negative values the callback
has returned so far.  In other words: for a stream, @code{pos} is a
monotonically increasing count of the bytes already produced, and the
callback will never be asked to go back.  A generator that has no use
for random access can ignore @code{pos} completely.  Do note that the
guarantee only holds as long as the response object is used for one
request; if the same object is queued for several connections, the
same content reader may be asked for the same data more than once, and
sharing one mutable buffer between them would be wrong.

The return value tells @emph{MHD} what happened:

@table @asis
@item a positive number
That many bytes were written to @code{buf}.  Returning more than
@code{max} is a fatal application error and makes @emph{MHD} close the
connection.

@item @code{MHD_CONTENT_READER_END_OF_STREAM}
The body is complete.  With chunked encoding @emph{MHD} terminates the
chunk sequence properly and appends any footers; without chunked
encoding and an unknown size it simply closes the connection.  If a
concrete @code{size} was announced, ending the stream early is not
legal, and @emph{MHD} treats it essentially like an error---the client
receives fewer bytes than the @code{Content-Length} promised.

@item @code{MHD_CONTENT_READER_END_WITH_ERROR}
Something went wrong while generating the data; see below.

@item @code{0}
No data is available @emph{right now}, but the stream is not over.
@end table

@noindent
That last case is the dangerous one.  The header file states that
returning zero is legal only when @emph{MHD} is @emph{not} using an
internal sockets polling mode, and this is not a formality:
@emph{MHD} does not diagnose the situation, it simply arranges for the
next poll to time out immediately and calls the callback again.  A
callback that returns zero while a request is stalled for a third of a
second is called several million times in that period and pins a CPU
core at 100%.  In external polling mode the effect is milder---the
callback is retried whenever the application calls one of the
@code{MHD_run*()} functions---but it is still a spin.  The proper
answer for "no data yet" is to suspend the connection, which is
covered further down.


@heading Keeping state per request

Because the callback is a plain C function, everything it needs to
know has to travel through @code{crc_cls}.  The natural shape of a
streaming handler is therefore: allocate a context on the heap,
allocate its data buffer, create the response with that context as
@code{crc_cls}, and let the free callback dispose of both.

@verbatim
struct ResponseContext
{
  char *buf;            /* heap buffer, refilled again and again */
  size_t fill;          /* number of valid bytes in buf */
  size_t off;           /* number of bytes of buf given to MHD */
  unsigned int block;   /* number of blocks produced so far */
};
@end verbatim
@noindent

The two offsets are what make the buffer independent of @emph{MHD}'s
appetite.  A block is generated once and may then be handed out over
several invocations, because @code{max} can be smaller than what we
have ready:

@verbatim
static ssize_t
content_reader (void *cls, uint64_t pos, char *buf, size_t max)
{
  struct ResponseContext *ctx = cls;
  size_t ready;

  (void) pos;

  if (ctx->off == ctx->fill)
    {
      /* Everything we had was passed on, produce the next block. */
      if (BLOCK_COUNT == ctx->block)
        return MHD_CONTENT_READER_END_OF_STREAM;
      generate_block (ctx);
    }
  ready = ctx->fill - ctx->off;
  if (ready > max)
    ready = max;
  memcpy (buf, &ctx->buf[ctx->off], ready);
  ctx->off += ready;
  return (ssize_t) ready;
}
@end verbatim
@noindent

@code{generate_block()} is the place where a real application would
run its expensive computation, query, or network fetch.  The important
property is that the same buffer is reused every time, so the memory
the server needs does not grow with the size of the document.

The handler assembles all of this and, from that moment on, hands
ownership of the context to the response object:

@verbatim
  ctx = malloc (sizeof (struct ResponseContext));
  if (NULL == ctx)
    return MHD_NO;
  ctx->buf = malloc (BUFFER_SIZE);
  if (NULL == ctx->buf)
    {
      free (ctx);
      return MHD_NO;
    }
  ctx->fill = 0;
  ctx->off = 0;
  ctx->block = 0;

  response = MHD_create_response_from_callback (MHD_SIZE_UNKNOWN,
                                                IO_BLOCK_SIZE,
                                                &content_reader,
                                                ctx,
                                                &free_context);
  if (NULL == response)
    {
      /* No response object exists, so nobody will call the free
         callback for us. */
      free_context (ctx);
      return MHD_NO;
    }
  ret = MHD_queue_response (connection, MHD_HTTP_OK, response);
  MHD_destroy_response (response);
@end verbatim
@noindent

Note the error path: as long as
@code{MHD_create_response_from_callback()} has not returned a response,
the free callback will never run and the application must clean up
itself.


@heading Releasing the state

The free callback is trivial:

@verbatim
static void
free_context (void *cls)
{
  struct ResponseContext *ctx = cls;

  free (ctx->buf);
  free (ctx);
}
@end verbatim
@noindent

@emph{MHD} invokes it when the last reference to the response object
goes away.  The call to @code{MHD_destroy_response()} in the handler
does not trigger it, because queuing the response took a reference;
the callback runs when the connection is finished with the response.
That happens after a completed body, but equally after a client that
closed the socket in the middle of the download, after a timeout, and
when the daemon is stopped.  This is precisely what makes the free
callback the right place for the cleanup: there is no other hook that
covers all of these cases.


@heading Unknown size and chunked encoding

Passing @code{MHD_SIZE_UNKNOWN} as the size leaves @emph{MHD} with the
problem of telling the client where the body ends.  For an HTTP/1.1
client it solves it by switching to chunked transfer encoding: it adds
a @code{Transfer-Encoding: chunked} header and frames every piece the
callback returns as one chunk, terminating the body with a zero-length
chunk when the callback reports the end of the stream.  Nothing has to
be done for this; it is a consequence of the unknown size.

@verbatim
< HTTP/1.1 200 OK
< Content-Type: text/plain
< Transfer-Encoding: chunked
@end verbatim
@noindent

An HTTP/1.0 client cannot be sent chunks.  In that case @emph{MHD}
falls back to the only other framing the protocol offers and marks the
connection as one that must be closed: the body is sent raw, without
@code{Content-Length}, and its end is the end of the connection.  The
data arrives intact, but the client has no way to distinguish a
complete answer from one that was cut short.

If the size @emph{is} known---and in the example program the URL
@code{/sized} shows this variant---it should be announced, simply by
passing the number instead of @code{MHD_SIZE_UNKNOWN}.  @emph{MHD}
then emits a normal @code{Content-Length} header, no chunk framing is
added, and the callback is queried with @code{max} limited by both
@code{block_size} and the number of bytes still outstanding.  The
callback must produce exactly the announced number of bytes.


@heading Aborting a response

Generating data can fail halfway through---the database connection
drops, a file disappears, an allocation fails.  Since the response
headers, and probably a good part of the body, have already been sent,
there is no way to turn the answer into an error page any more.
Returning @code{MHD_CONTENT_READER_END_WITH_ERROR} is the way to give
up: @emph{MHD} logs the condition and closes the connection
immediately, without writing the terminating chunk.

What the client sees depends on the framing.  With chunked encoding it
is an abnormally terminated chunk stream, and a well-behaved client
reports it as such---@code{curl} for instance fails with "transfer
closed with outstanding read data remaining" and a non-zero exit
status.  With an announced @code{Content-Length} the client notices
that the body is shorter than promised.  Only in the HTTP/1.0 case
discussed above, where the end of the body is the end of the
connection, is the failure indistinguishable from a normal ending;
that is a property of the protocol and not something @emph{MHD} can
repair.  The URL @code{/error} of the example program aborts the
stream after a few blocks so that this can be observed.


@heading When the data is not ready yet

So far the generator could always produce the next block on the spot.
If it cannot---because the data is coming from another thread, another
process, or the network---then, as explained above, returning
@code{0} in an internal polling mode turns the daemon into a busy
loop.  The supported answer is to take the connection out of the event
loop until the data has arrived, with the pair

@verbatim
void MHD_suspend_connection (struct MHD_Connection *connection);
void MHD_resume_connection (struct MHD_Connection *connection);
@end verbatim
@noindent

The daemon has to be started with the @code{MHD_ALLOW_SUSPEND_RESUME}
flag; both functions call @code{MHD_PANIC()} and abort the process
otherwise.  The flag implies @code{MHD_USE_ITC}, so that a resumed
connection wakes the polling thread up instead of waiting for the next
timeout.  Suspending is not available for daemons running with
@code{MHD_USE_THREAD_PER_CONNECTION}, and the daemon must not be
stopped while connections are still suspended.

@code{MHD_suspend_connection()} may only be called from the access
handler or from the content reader callback, which means the
connection handle has to be stored in the context struct so that the
callback can reach it.  The pattern is then:

@verbatim
  if (! ctx->data_available)
    {
      MHD_suspend_connection (ctx->connection);
      return 0;
    }
@end verbatim
@noindent

@code{MHD_resume_connection()}, in contrast, may be called from any
thread and at any time.  In particular it is explicitly allowed to
call it before the suspension has taken effect: the producer may
already be done by the time the callback gets around to suspending.
@emph{MHD} handles this by remembering the resume request and, when the
suspension is finally processed, cancelling it instead of parking the
connection, so the wakeup can never be lost.  This is what makes the
"check, suspend, return 0" sequence above safe without a lock of its
own.

The difference is dramatic in practice.  A callback that stalls for
three hundred milliseconds and returns @code{0} is entered several
million times and burns a full core; the same callback suspending the
connection is entered exactly once more and the daemon uses no
measurable CPU time at all.


@heading Trailers

Chunked responses may carry trailers, that is header fields that are
transmitted after the body.  They are added with

@verbatim
MHD_add_response_footer (response, "X-Checksum", "deadbeef");
@end verbatim
@noindent

@emph{MHD} writes them out after the terminating zero-length chunk:

@verbatim
0
X-Checksum: deadbeef

@end verbatim
@noindent

Footers may still be added while the body is being generated---even
from inside the content reader callback, immediately before returning
@code{MHD_CONTENT_READER_END_OF_STREAM}---which is what makes them
useful in the first place: a checksum or a row count over data that
has only just been produced cannot be put into the headers, because
those are long gone.  This is safe as long as the response object
belongs to a single request, as it does in the pattern used here.
@emph{MHD} does not generate a @code{Trailer} response header by
itself; if the client should be told in advance which fields to
expect, add it with @code{MHD_add_response_header()}.  Be aware that
many clients discard trailers silently.


@heading Example code

The complete program is available as @code{callbackresponse.c}.  It
serves a document of sixty-four blocks that are produced one at a time
into a single heap buffer.  @code{GET /} streams it with
@code{MHD_SIZE_UNKNOWN} and thus with chunked encoding,
@code{GET /sized} streams the same bytes with a @code{Content-Length}
announced up front, and @code{GET /error} aborts in the middle.


@heading Remarks

Calls into the content reader of one response object are serialized by
@emph{MHD}, so a per-request context needs no locking of its own as
long as no other thread touches it.  As soon as a producer thread is
involved---the suspend/resume case---the shared fields do need
protection.

The chunk boundaries are not under the application's control and carry
no meaning: a client may receive the bytes of one callback invocation
spread over several chunks or, in other configurations, several
invocations combined.  Chunked encoding is a transport detail, and any
record structure the application needs must be part of the body
itself.

Finally, returning very small amounts of data per invocation is
correct but wasteful, since every invocation may become its own chunk
with its own framing overhead.  If the producer has more data ready, it
should fill as much of @code{buf} as @code{max} permits.


@heading Exercises

@itemize @bullet

@item
Add a URL that reports how far the transfer has progressed by writing
the value of @code{pos} into every line, and confirm with a slow
client (@code{curl --limit-rate}) that it really is the number of
bytes already sent, and not a block counter.

@item
Register a request completion callback with
@code{MHD_OPTION_NOTIFY_COMPLETED} and print the termination code.
Then download the document, interrupt the client in the middle, and
watch in which order the completion callback and the content reader's
free callback are invoked, and that the free callback runs in both
cases.

@item
Turn the generator into an asynchronous one.  Start a thread that
appends a line to a shared buffer once per second, keep the connection
handle in the context struct, and suspend the connection whenever the
buffer is empty.  Do not forget @code{MHD_ALLOW_SUSPEND_RESUME} when
starting the daemon.  Then remove the call to
@code{MHD_suspend_connection()}, leaving only the @code{return 0}, and
compare the CPU usage of the server process.

@item
Compute a checksum over the generated document while it is being sent
and append it as a trailer.  Watch it on the wire---most command line
clients will not show it to you, so a raw @code{nc} or a small script
speaking HTTP by hand is the easier tool here.

@end itemize
