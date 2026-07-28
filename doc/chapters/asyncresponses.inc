The previous chapter left one question open.  A content reader that
has no data ready may return @code{0}, but doing so turns the daemon
into a busy loop, and the honest answer---suspend the connection---was
only sketched there.  This chapter builds the thing itself: a server
whose slow work happens in threads of its own, whose connections are
parked while that work is under way, and which is driven by an
external @code{select()} loop so that the application stays in charge
of its own event handling.

The combination is a common one.  Most requests are cheap and can be
answered on the spot; a few of them start a report, a backup or a
query that runs for seconds.  Handling the slow ones inline would
block every other client for as long as they take.  Giving every
connection its own thread---@code{MHD_USE_THREAD_PER_CONNECTION}---is
no answer either, both because it scales badly and because suspending
is not available in that mode at all.  What is wanted is a single
event loop that never blocks, plus a worker per slow job.


@heading Who may call what

Almost every difficulty in this design comes from one rule, so it is
worth stating before any code:

@table @asis
@item @code{MHD_queue_response()}
Must be called from the thread that runs the daemon, from inside the
access handler.  A worker thread must never queue a response.

@item @code{MHD_suspend_connection()}
May only be called from the access handler or from a content reader
callback---that is, from @emph{MHD}'s own thread, while @emph{MHD} is
calling into the application.

@item @code{MHD_resume_connection()}
May be called from any thread at any time, and this is the exception
that makes the whole design work.  It is the only @emph{MHD} function
a worker thread ever needs.
@end table

@noindent
So the split is: the worker computes and, when it has something,
resumes.  Everything that touches the connection or the response
happens on the daemon's thread, where @emph{MHD} calls the application
back.  The worker and the daemon share exactly one object, a
per-request context, and the only thing the worker does with the
connection handle it holds is pass it to
@code{MHD_resume_connection()}.

The daemon has to be started with @code{MHD_ALLOW_SUSPEND_RESUME}; both
suspend and resume call @code{MHD_PANIC()} and abort the process
otherwise.  Note also that suspending does not work with a thread pool:
@code{MHD_resume_connection()} asserts that the daemon has none.


@heading The event loop

Leaving out @code{MHD_USE_INTERNAL_POLLING_THREAD} puts @emph{MHD}
into external polling mode: it starts no thread of its own and does
nothing until the application asks it to.  The loop is the usual one,
and the example adds its own descriptor to the very same sets---there
is nothing special about @emph{MHD}'s:

@verbatim
  FD_ZERO (&rs); FD_ZERO (&ws); FD_ZERO (&es);
  max = 0;
  if (MHD_YES != MHD_get_fdset (daemon, &rs, &ws, &es, &max))
    break;                      /* fatal internal error */
  FD_SET (wake_pipe[0], &rs);   /* our own wakeup pipe */
  if (max < wake_pipe[0])
    max = wake_pipe[0];

  if (MHD_YES == MHD_get_timeout64 (daemon, &mhd_timeout))
    { ...fill tv...; tvp = &tv; }
  else
    tvp = NULL;                 /* nothing to wait for */

  select ((int) max + 1, &rs, &ws, &es, tvp);
  MHD_run_from_select (daemon, &rs, &ws, &es);
@end verbatim
@noindent

The interesting branch is the one that sets @code{tvp} to @code{NULL}.
@code{MHD_get_timeout64()} returns @code{MHD_NO} when @emph{MHD} has
nothing whatsoever to wait for, and with every connection suspended
that is precisely the situation: suspended connections do not time
out, so there is no deadline to wake up for.  The loop then blocks in
@code{select()} indefinitely.  Whether the server works at all depends
on something waking it up.


@heading Waking the loop up

That something is @emph{MHD}'s inter-thread communication channel.
@code{MHD_ALLOW_SUSPEND_RESUME} is defined as
@code{8192 | MHD_USE_ITC}, so requesting suspend support requests the
ITC as well; @code{MHD_get_fdset()} puts the reading end of that
channel into the read set, ahead of everything else; and
@code{MHD_resume_connection()} writes a byte to it.  A worker thread
that resumes a connection therefore breaks the main thread out of
@code{select()}, even though the two share nothing but the daemon
handle.

This deserves emphasis because the header file is misleading about it:
the comment on @code{MHD_USE_ITC} says the flag is ignored with
external polling.  That is true for the flag in isolation, but not for
the channel: @code{MHD_ALLOW_SUSPEND_RESUME} creates it regardless of
the polling mode, and in external mode it is the application's own
@code{select()} that watches it.  Without that, a resumed connection
would sit untouched until some unrelated event happened to wake the
loop.

There is no race to guard against here.  If the worker resumes in the
window between @code{MHD_get_fdset()} and @code{select()}, the byte is
already in the channel when @code{select()} is entered, and
@code{select()} returns immediately---the channel is level triggered,
so a wakeup cannot be missed.  The same property makes it safe for a
worker to resume a connection that has not finished suspending yet:
@emph{MHD} remembers the request and cancels the pending suspension
instead of parking the connection.  Neither side needs to know what
the other is doing.


@heading Answering in one piece

The simplest of the two patterns is for an answer that is only useful
as a whole---a generated report, the result of a query.  Nothing can be
sent before it is finished, so the connection is suspended in the
access handler and the response is queued when @emph{MHD} comes back:

@verbatim
static enum MHD_Result
handle_slow (struct MHD_Connection *connection, void **req_cls)
{
  struct Job *job = *req_cls;

  if (NULL == job)
    {
      /* First call for this request: start the work and ask MHD to
         come back to us. */
      job = job_create (connection, 0);
      if (NULL == job)
        return MHD_NO;
      if (MHD_NO == job_start (job))
        { job_unref (job); job_unref (job); return MHD_NO; }
      *req_cls = job;
      return MHD_YES;
    }
  pthread_mutex_lock (&job->lock);
  if (0 == job->finished)
    {
      job->suspended = 1;
      MHD_suspend_connection (connection);
      pthread_mutex_unlock (&job->lock);
      return MHD_YES;
    }
  ...copy the result out from under the lock...
  pthread_mutex_unlock (&job->lock);
  ...MHD_create_response_from_buffer_copy() and MHD_queue_response()...
}
@end verbatim
@noindent

The control flow is worth following, because it is not obvious that it
terminates.  @emph{MHD} calls the access handler for a request more
than once; the first call is the one where @code{*req_cls} is still
@code{NULL}, and returning @code{MHD_YES} without queueing anything
tells @emph{MHD} to carry on.  On the second call the worker is
running but not finished, so the connection is suspended and the
handler returns again.  When the worker resumes the connection,
@emph{MHD} calls the handler a third time---on its own thread, with
the same @code{*req_cls}---and this time @code{finished} is set and the
response is queued.

That third call is the answer to the question this pattern exists for.
The worker never queues anything; it merely makes the daemon call the
application back at a moment when the answer is ready.


@heading Answering as it is produced

The second pattern is the more useful one when the answer is long, and
it is what makes a browser show results as they appear rather than
after a long blank pause.  Here the response is queued
@emph{immediately}, with a content reader and an unknown size, so the
headers go out at once and the body follows as the worker fills it in:

@verbatim
  job = job_create (connection, 1);
  response = MHD_create_response_from_callback (MHD_SIZE_UNKNOWN,
                                                IO_BLOCK_SIZE,
                                                &stream_reader,
                                                job,
                                                &stream_done);
  ...
  MHD_add_response_header (response, MHD_HTTP_HEADER_CONTENT_TYPE,
                           "text/event-stream");
  ret = MHD_queue_response (connection, MHD_HTTP_OK, response);
  MHD_destroy_response (response);
@end verbatim
@noindent

Because the size is unknown, @emph{MHD} uses chunked transfer encoding,
and every piece the content reader hands back is framed as its own
chunk and goes out on the wire straight away.  The content reader is
where suspending happens:

@verbatim
static ssize_t
stream_reader (void *cls, uint64_t pos, char *buf, size_t max)
{
  struct Job *job = cls;
  size_t ready;

  pthread_mutex_lock (&job->lock);
  if (job->off == job->fill)
    {
      job->off = 0;
      job->fill = 0;
      if (0 != job->finished)
        {
          pthread_mutex_unlock (&job->lock);
          return MHD_CONTENT_READER_END_OF_STREAM;
        }
      /* Nothing to send yet.  Take the connection out of the event
         loop; the worker will put it back in. */
      job->suspended = 1;
      MHD_suspend_connection (job->connection);
      pthread_mutex_unlock (&job->lock);
      return 0;
    }
  ready = job->fill - job->off;
  if (ready > max)
    ready = max;
  memcpy (buf, &job->payload[job->off], ready);
  job->off += ready;
  pthread_mutex_unlock (&job->lock);
  return (ssize_t) ready;
}
@end verbatim
@noindent

The return value is still @code{0}, exactly as in the busy-waiting
version the previous chapter warned about.  The difference is the line
above it.  Suspending removes the connection from the event loop, so
@emph{MHD} has no reason to come back until the worker says so, and
the process goes to sleep.  The example ships with a test that measures
this: streaming a document that takes one second to produce costs the
server no measurable CPU time at all while the connection is suspended,
and very nearly a full second---one core, saturated---when the
@code{MHD_suspend_connection()} call is removed and only the
@code{return 0} is left.  The bytes that arrive are identical in both
cases, which is what makes this such an easy mistake to keep.


@heading The shared state

Everything the two threads share sits in one structure per request:

@verbatim
struct Job
{
  pthread_mutex_t lock;
  pthread_cond_t cond;
  struct MHD_Connection *connection;
  char payload[MAX_PAYLOAD];
  size_t fill;
  size_t off;
  unsigned int rc;
  int finished;
  int suspended;
  int abandoned;
  ...
};
@end verbatim
@noindent

There is no registry of pending requests involved in answering them,
and no lookup: the pointer travels in @code{*req_cls} for the first
pattern and in the content reader's @code{crc_cls} for the second, and
both the daemon and the worker are handed it directly.  A shared list
of all jobs is still useful, but only for shutting down in an orderly
fashion, and it is protected by a lock of its own that is always taken
before any job's lock, never after.

The structure is reference counted, with one reference held by
@emph{MHD} and one by the worker.  The @emph{MHD} side lets go in the
free callback of the response for a streamed answer, and in the
@code{MHD_OPTION_NOTIFY_COMPLETED} callback for the other pattern; the
worker lets go when it returns.  Dropping the last reference does not
free the job, though, because the worker still has to be joined and
only the main thread may do that.  The main loop therefore ends with a
sweep that joins and frees whatever has no references left.


@heading When the client goes away

This is the part that is easy to get wrong, because it does not happen
during development and does happen constantly in production.  A client
that closes the connection halfway through a download leaves a worker
running with a pointer to a connection @emph{MHD} is about to free.

The two callbacks that tell the application a request is over---the
response's free callback and @code{MHD_OPTION_NOTIFY_COMPLETED}---are
therefore where the worker is cut loose:

@verbatim
static void
job_detach (struct Job *job)
{
  pthread_mutex_lock (&job->lock);
  job->abandoned = 1;
  job->connection = NULL;
  pthread_cond_signal (&job->cond);
  pthread_mutex_unlock (&job->lock);
  job_unref (job);
}
@end verbatim
@noindent

and the worker checks that flag before every resume:

@verbatim
static void
job_resume_locked (struct Job *job)
{
  if ( (0 == job->suspended) || (0 != job->abandoned) )
    return;
  job->suspended = 0;
  MHD_resume_connection (job->connection);
}
@end verbatim
@noindent

Note that this function is called with the job's lock @emph{held}, and
calls into @emph{MHD} without releasing it.  That is deliberate and it
is what makes the pattern safe.  @emph{MHD} destroys the connection
only after the completion callback has returned, and that callback
cannot run while the worker holds the lock; so for as long as the
worker is inside @code{MHD_resume_connection()}, the connection it
passes is guaranteed to still exist.  Dropping the lock first and
resuming afterwards would open exactly the window this is meant to
close.

The reverse order never occurs: @emph{MHD} invokes the free and
completion callbacks without holding the internal locks that
@code{MHD_resume_connection()} acquires, so there is no way for the
two to deadlock.

The condition variable in the same function is a convenience rather
than a necessity.  Signalling it wakes a worker that is asleep between
steps, so that the work stops within microseconds of the client
disappearing instead of running to completion for nobody.


@heading Shutting down

Stopping a daemon that still has suspended connections is an API
violation, and a suspended connection is one that only a worker can
release.  The order is therefore fixed:

@enumerate
@item
Stop handing out new jobs.

@item
Tell every worker to give up, and @emph{join} them.  After this point
no connection can be suspended any more: the workers resume before
they exit, and the content reader only ever suspends while a worker is
running.

@item
Keep running the event loop until the connections have drained, so
that the last bytes actually reach the clients.

@item
@code{MHD_stop_daemon()}.
@end enumerate

@noindent
Skipping the join in step two is the tempting shortcut, and it is the
one that leaves a connection parked forever with nothing left alive to
wake it.


@heading Example code

The complete program is available as @code{asyncresponse.c}.  It runs
one external @code{select()} loop and serves four URLs:

@table @code
@item /
A small page whose JavaScript opens the stream below and appends a row
for every event as it arrives.  The rows visibly trickle in, one per
step, which is the most direct demonstration of what the chapter is
about.

@item /events
The stream: a response is queued at once, and the content reader
suspends between steps.  The body is a sequence of server-sent events,
which needs no library on the browser side.

@item /slow
The other pattern: the connection is suspended in the access handler
and a complete answer is queued once the worker is done.

@item /fast
Answered on the spot.  The page has a button that requests it and
reports the round trip time; it stays in the low milliseconds while
jobs are running, which is the point of suspending rather than
blocking.
@end table

@noindent
The program takes the port, the duration of a step in milliseconds and
the number of steps on the command line.  Passing @code{0} as the port
makes the operating system choose a free one, which the program then
reports via @code{MHD_DAEMON_INFO_BIND_PORT}:

@verbatim
$ ./asyncresponse 0 250 20
Listening on port 44321
@end verbatim
@noindent

The accompanying @code{test_asyncresponse.c} starts exactly that
binary and checks over HTTP that @code{/slow} waits for its worker,
that the body of @code{/events} really arrives in pieces spread over
the lifetime of the request rather than in one burst at the end, that
@code{/fast} is still served promptly while jobs are parked, that a
client which hangs up in the middle takes neither the server nor the
worker with it, and that the process exits cleanly when it is signalled
while a connection is suspended.  It also compares the server's CPU
time against the wall clock time of a transfer, which is the only one
of those checks that notices the difference between a suspended
connection and a busy-waiting one.


@heading Remarks

@emph{MHD} does not detect that a client has disconnected while a
connection is suspended, and the connection timeout does not run
either.  A suspended connection stays suspended until somebody resumes
it, without exception.  Any timeout on the work itself is therefore the
application's responsibility.

Suspended connections still count against the connection limits, both
the global one and the per-IP one.  A server that parks connections for
minutes needs its limits sized for the number of jobs it expects to
have in flight, not for the number it expects to be transmitting.

If the client vanishes in the middle of a chunked response, the next
write fails and @emph{MHD} logs it---with
@code{MHD_USE_ERROR_LOG} enabled the example prints @code{Failed to
send the chunked response body ... The socket is no longer available
for sending}.  That is the normal course of events for an aborted
download and not a sign of a problem.

Finally, none of this is specific to @code{select()}.  The same
argument holds for @code{poll()} and for @code{epoll}, where the
daemon's descriptor can be obtained with
@code{MHD_DAEMON_INFO_EPOLL_FD} and added to an epoll set of the
application's own; @code{suspend_resume_epoll.c} among the
distribution's examples shows that variant.


@heading Exercises

@itemize @bullet

@item
Give the jobs a deadline.  Since a suspended connection never times
out on its own, add a check to the main loop that resumes---and
answers with @code{503}---any job that has been running for too long,
and confirm with a step duration long enough to trigger it.

@item
Remove the @code{MHD_suspend_connection()} call from the content
reader, leaving only the @code{return 0}, and watch the server process
with @code{top} while a single client downloads the stream.  Then put
it back and watch again.  Both servers send the same bytes.

@item
Take the resume out of the worker's final block, so that a finished job
leaves its connection parked, and then stop the server while a job is
in flight.  Watch what the shutdown does---and what @code{valgrind}
has to say about it---and work out which of the four steps above was
violated.

@item
Replace the per-request thread with a fixed pool of worker threads and
a queue of pending jobs.  The reference counting and the
@code{abandoned} flag should not need to change at all; if they do, the
ownership rules were not as clean as they looked.

@item
Serve the stream to two browser windows at once and confirm from the
timestamps that the two jobs run concurrently and are interleaved by a
single-threaded event loop.

@end itemize
