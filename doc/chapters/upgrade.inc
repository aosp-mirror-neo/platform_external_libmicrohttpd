HTTP is a request/response protocol: the client asks, the server
answers, and the connection is either closed or reused for the next
request.  Some applications need something else entirely --- a
bidirectional byte stream that neither side has to poll for.  Rather
than opening a second connection on another port, @emph{RFC 9110} lets
a client ask the server to switch the already established connection
over to a different protocol.  The client sends an ordinary request
carrying an @code{Upgrade:} header field, and if the server agrees it
answers with the status code @code{101 Switching Protocols}.  Once
that response has gone out, HTTP is over: the two sides simply talk
whatever protocol they agreed on over the same TCP connection.

Since version 0.9.52 @emph{libmicrohttpd} supports this protocol
switch.  The API is deliberately protocol-agnostic --- @emph{MHD}
performs the HTTP part of the handshake and then hands you the socket.
What you send over that socket afterwards is entirely your business;
@emph{MHD} neither parses nor generates a single byte of it any more.

The best known user of this mechanism is the Websocket protocol
(@emph{RFC 6455}), which uses the upgrade API as a means to an end and
then needs a good deal of machinery of its own for framing, masking
and the closing handshake.  This chapter takes the opposite approach:
it shows the upgrade API on its own, with a protocol so simple that no
helper library is needed.  Our server switches to a line-based echo
protocol: every line the client sends is sent straight back, until the
client sends the line @code{QUIT}.

@heading Enabling upgrades

Upgrading is not allowed by default, because handing raw sockets to
application code has consequences the library cannot control.  You opt
in with the @code{MHD_ALLOW_UPGRADE} flag:

@verbatim
daemon = MHD_start_daemon (MHD_USE_THREAD_PER_CONNECTION |
                           MHD_USE_INTERNAL_POLLING_THREAD |
                           MHD_ALLOW_UPGRADE |
                           MHD_USE_ERROR_LOG,
                           PORT, NULL, NULL,
                           &access_handler, NULL,
                           MHD_OPTION_END);
@end verbatim
@noindent

The choice of threading mode matters more here than anywhere else in
this tutorial, because it decides whether your code is allowed to
block.

With @code{MHD_USE_THREAD_PER_CONNECTION} every connection already has
a thread of its own, and that thread is the one that will run your
upgrade callback.  Blocking in it stalls exactly one client, so you
may write the straightforward loop of @code{recv()} and @code{send()}
calls that everybody has in their head.  This is what makes the
example in this chapter short enough to read in one go.

Without it --- that is, with a single internal polling thread, a
thread pool, epoll, or an external event loop --- your callback runs
@emph{inside} @emph{MHD}'s event loop.  Blocking there freezes every
other connection the same loop is serving.  In that case the callback
must return immediately, and you have to register the socket in your
own event loop (or hand it to a thread you started yourself) and drive
the conversation from there.

@heading Deciding whether to upgrade

A client that wants to switch protocols says so twice: it names the
protocol in the @code{Upgrade:} header field, and it lists the token
@code{Upgrade} in the @code{Connection:} header field.  Both fields
are comma-separated lists, so a browser may well send
@code{Connection: keep-alive, Upgrade}.  Comparing the whole field
value against the string @code{"Upgrade"} would reject such a request;
the example therefore contains a small helper @code{has_token()} that
walks the list.  Note also that a protocol switch is a HTTP/1.1
feature; @code{MHD_queue_response()} will refuse an upgrade response
on a HTTP/1.0 connection.

@verbatim
  if ( (0 != strcmp (method, MHD_HTTP_METHOD_GET)) ||
       (0 != strcmp (version, MHD_HTTP_VERSION_1_1)) ||
       (! has_token (MHD_lookup_connection_value (connection,
                                                  MHD_HEADER_KIND,
                                                  MHD_HTTP_HEADER_CONNECTION),
                     "Upgrade")) ||
       (! has_token (MHD_lookup_connection_value (connection,
                                                  MHD_HEADER_KIND,
                                                  MHD_HTTP_HEADER_UPGRADE),
                     PROTOCOL)) )
    return answer_plain (connection,
                         MHD_HTTP_UPGRADE_REQUIRED,
                         PAGE_UPGRADE_REQUIRED,
                         1);
@end verbatim
@noindent

Refusing is not an error condition: the client asked a question and
gets an ordinary HTTP answer.  Which answer depends on who is at
fault.  If the request is malformed --- for instance an
@code{Upgrade:} field without the matching @code{Connection:} token
--- @code{MHD_HTTP_BAD_REQUEST} is appropriate.  If the request is
perfectly well-formed but simply does not speak the protocol this
resource requires, @code{MHD_HTTP_UPGRADE_REQUIRED} (426) is the
better answer, and it should carry an @code{Upgrade:} header field
naming the protocol the server would have accepted.  Our example
folds both cases into a 426 for brevity.  Either way you queue a
perfectly normal response and the connection stays a HTTP connection.

@heading Creating the upgrade response

If we do want to switch, we create a special response object with
@code{MHD_create_response_for_upgrade()}.  It takes the callback that
will receive the socket and a closure pointer for it, and returns
@code{NULL} on error.  The response has no body --- it is a header and
nothing else.

@verbatim
  response = MHD_create_response_for_upgrade (&upgrade_handler,
                                              NULL);
  if (NULL == response)
    return MHD_NO;
  MHD_add_response_header (response,
                           MHD_HTTP_HEADER_UPGRADE,
                           PROTOCOL);
  ret = MHD_queue_response (connection,
                            MHD_HTTP_SWITCHING_PROTOCOLS,
                            response);
  MHD_destroy_response (response);
  return ret;
@end verbatim
@noindent

Two details are easy to get wrong here.

The first is the @code{Connection: Upgrade} response header field, and
the surprise is that you must @emph{not} add it.
@code{MHD_create_response_for_upgrade()} puts it into the response
itself, and @code{MHD_queue_response()} then verifies that it is still
there and still contains the @code{upgrade} token before it accepts
the response.  @emph{MHD} does merge repeated @code{Connection:}
header fields into a single field rather than emitting two of them,
but it only de-duplicates the @code{close} token, so adding
@code{Upgrade} a second time puts @code{Connection: Upgrade, Upgrade}
on the wire.  Clients tolerate that, but there is no reason to send
it.

What @emph{MHD} does @emph{not} invent for you is the @code{Upgrade:}
field naming the new protocol --- that one is yours to add, since only
you know what you are switching to.  Do not forget it:
@code{MHD_queue_response()} does not check for it, so in a normal
build the client simply receives a 101 that fails to say what it
switched to, while a library built with assertions enabled aborts when
it performs the switch.

The second is the status code.  @code{MHD_queue_response()} rejects an
upgrade response with any status other than
@code{MHD_HTTP_SWITCHING_PROTOCOLS}, and conversely it rejects status
101 combined with a response that is not an upgrade response.  On any
of these mistakes it returns @code{MHD_NO} and, with
@code{MHD_USE_ERROR_LOG} enabled, explains itself on @code{stderr};
this is by far the quickest way to debug a handshake that does not
happen.

The response object itself follows the usual rules.
@code{MHD_queue_response()} takes its own reference, so calling
@code{MHD_destroy_response()} immediately afterwards is correct and is
what all the other examples in this tutorial do.  The object is only
really freed once the last connection using it is done with it, which
for an upgrade means after the callback has returned.  As with any
other response you may build one upgrade response and queue it for
many connections; the callback is then simply invoked once per
connection.

@heading The upgrade callback

After the 101 response has been written to the socket, @emph{MHD}
calls the @code{MHD_UpgradeHandler} you registered:

@verbatim
static void
upgrade_handler (void *cls,
                 struct MHD_Connection *connection,
                 void *req_cls,
                 const char *extra_in,
                 size_t extra_in_size,
                 MHD_socket sock,
                 struct MHD_UpgradeResponseHandle *urh)
@end verbatim
@noindent

@table @code
@item cls
The closure that was passed to
@code{MHD_create_response_for_upgrade()}.  Since the same response
object may serve many connections, this is per-@emph{response} state,
not per-connection state.

@item connection
The original HTTP connection.  It is handed over so that you can have
a last look at the request --- @code{MHD_lookup_connection_value()}
still works here, which is how a real protocol picks up, say, a
subprotocol name or an authentication token.  Do not queue anything on
it any more.

@item req_cls
Whatever your access handler left in @code{*req_cls}.  This is the
natural place to put per-connection state that the access handler
already computed.

@item extra_in / extra_in_size
Bytes of your new protocol that the client sent immediately behind the
request header, and that @emph{MHD} therefore already read off the
socket while parsing the request.  They are @emph{gone} from the
socket: if you go straight to @code{recv()} you silently lose them.
Process this buffer first, exactly as if you had read it yourself.
The buffer belongs to @emph{MHD} and is only valid for the duration of
the call, so copy anything you want to keep.  A client that waits for
the 101 before it starts talking will produce
@code{extra_in_size == 0}, which is why this argument is so easy to
overlook and so annoying when it finally bites.

@item sock
The socket.  For a plain HTTP connection this is the connection to the
client; for HTTPS it is one end of a socketpair with @emph{MHD}
relaying the TLS traffic, so socket options and @code{getpeername()}
will not give you what you expect.  Read and write it as you please,
and you may call @code{shutdown()} on it, but you must never call
@code{close()}.

@item urh
The handle for @code{MHD_upgrade_action()}, described below.
@end table

The loop itself is then unremarkable, apart from consuming
@code{extra_in} before the first @code{recv()}:

@verbatim
  make_blocking (sock);
  es.line_len = 0;
  done = echo_feed (sock, &es, extra_in, extra_in_size);
  while (0 == done)
  {
    got = recv (sock, buf, sizeof (buf), 0);
    if (0 > got)
    {
      if (EINTR == errno)
        continue;
      break;                    /* read error */
    }
    if (0 == got)
      break;                    /* client closed the connection */
    done = echo_feed (sock, &es, buf, (size_t) got);
  }
  MHD_upgrade_action (urh,
                      MHD_UPGRADE_ACTION_CLOSE);
@end verbatim
@noindent

@heading Blocking or not blocking

The call to @code{make_blocking()} deserves a warning, because the
current behaviour is the opposite of what the threading modes suggest.
@emph{MHD} puts every accepted client socket into non-blocking mode,
and it does so regardless of the threading mode --- in fact the
library refuses to perform the switch at all, logging @code{Cannot
execute "upgrade" as the socket is in the blocking mode}, if it finds
the socket blocking.  So even under
@code{MHD_USE_THREAD_PER_CONNECTION}, where you are perfectly entitled
to block, the socket you are handed is non-blocking and a
@code{recv()} on an idle connection returns @code{-1} with
@code{EAGAIN} instead of waiting.

If you want the simple blocking loop shown above, you therefore have
to ask for it.  The example does so with a small
@code{make_blocking()} helper --- @code{fcntl()} clearing
@code{O_NONBLOCK} on POSIX systems, @code{ioctlsocket()} on W32 ---
which is the only operating-system-dependent code in the whole
program.

Under any other threading mode you leave the socket alone, keep it
non-blocking, and add it to your own event loop instead.

@heading Closing the connection

The last obligation of the callback is to hand the socket back:

@verbatim
  MHD_upgrade_action (urh,
                      MHD_UPGRADE_ACTION_CLOSE);
@end verbatim
@noindent

This is not a formality.  An upgraded connection is put into an
internal ``suspended'' state, and it stays there --- socket open,
connection structure allocated, slot counted against the connection
limit --- until the application says it is done.  Only
@code{MHD_UPGRADE_ACTION_CLOSE} says that.  Calling @code{close()} on
the socket yourself does not, and additionally leaves @emph{MHD}
holding a file descriptor number that the operating system may already
have handed to somebody else.  Call the action exactly once, on every
path out of the callback, including the error paths.

@code{MHD_upgrade_action()} takes two further actions in the current
release, @code{MHD_UPGRADE_ACTION_CORK_ON} and
@code{MHD_UPGRADE_ACTION_CORK_OFF}.  They switch @code{TCP_CORK} (or
@code{TCP_NOPUSH}) on the underlying socket so that several small
writes can be coalesced into a single segment.  They are a hint, not a
guarantee: the call returns @code{MHD_NO} if the platform has no such
option or if the socket is not a TCP socket, which is the normal case
for HTTPS connections.  The header file marks this part of the API as
not yet finalised, so do not build anything load-bearing on it.

@heading Remarks

@code{MHD_stop_daemon()} does @emph{not} interrupt an upgraded
connection.  It marks the connection as closed internally and logs
@code{Initiated daemon shutdown while "upgraded" connection was not
closed}, but it neither shuts down nor closes the socket --- and then
it waits for the connection's thread, which means it blocks until your
callback has returned.  A callback parked in a blocking @code{recv()}
therefore hangs the shutdown for as long as the client keeps the
connection open.  Any server that wants to terminate on demand needs
its own way out of that loop: a global shutdown flag combined with a
@code{shutdown()} on the sockets you are holding, a self-pipe added to
a @code{select()} in the loop, or a receive timeout on the socket.
Our example sidesteps the problem by only stopping the daemon when the
user presses return at a moment when nothing is connected.

Error handling in the callback is entirely yours.  @emph{MHD} will not
tell you that a client vanished and will not time an upgraded
connection out --- @code{MHD_OPTION_CONNECTION_TIMEOUT} stops applying
the moment the connection is upgraded.  Treat @code{0} from
@code{recv()} as a clean disconnect and a negative return as a broken
one, and remember that a peer which disappears without a FIN produces
neither until the TCP stack gives up, which can take a very long time.
Whatever happens, end by calling @code{MHD_upgrade_action()} with
@code{MHD_UPGRADE_ACTION_CLOSE}.

Finally, keep in mind that an upgraded connection is a connection that
@emph{MHD} can no longer recycle, and that intermediaries are entitled
to be unhelpful: @code{Upgrade:} is listed in @code{Connection:} and
is therefore a hop-by-hop header field.  A proxy that does not
understand your protocol is allowed to drop it, in which case your
server never sees an upgrade request at all and the client gets an
ordinary HTTP response where it expected a 101.  This is the main
reason why deployed protocols on top of this mechanism --- Websockets
above all --- make the handshake verifiable by both ends instead of
trusting that the request arrived intact.

The complete program is available as @code{upgrade.c} in the
@code{examples} section.  Start it and talk to it with any tool that
lets you type raw bytes at a socket --- @code{telnet localhost 8888}
will do --- by sending

@verbatim
GET / HTTP/1.1
Host: localhost
Connection: Upgrade
Upgrade: echo

@end verbatim
@noindent

followed by an empty line.  The server answers with

@verbatim
HTTP/1.1 101 Switching Protocols
Date: ...
Connection: Upgrade
Upgrade: echo

@end verbatim
@noindent

and from then on echoes every line back until you type @code{QUIT}.
Note the absence of a @code{Content-Length:} field: a 101 response has
no body, and everything after the empty line already belongs to the
new protocol.

For a real-world protocol built on exactly this API, read
@emph{RFC 6455} and note how much of it exists only to make the
handshake and the framing verifiable --- none of which the upgrade API
itself has an opinion about.

@heading Exercises

@itemize @bullet

@item
Point a browser at the server.  The browser sends a plain @code{GET /}
and receives the @code{426} page.  Now add a second resource that
serves a small HTML page and switch the upgrade to a different URL, so
that the same server can be both browsed and upgraded.

@item
Make the echo server useful: keep a list of the sockets of all
upgraded connections and forward every line one client sends to all
the others, turning the example into a minimal chat server.  You will
need a mutex around the list, and you will discover why the closing
rules matter --- a socket must leave the list before its callback
returns.

@item
Fix the shutdown behaviour discussed in the remarks.  Add a global
``quitting'' flag and a list of active sockets, have @code{main()} set
the flag and call @code{shutdown (sock, SHUT_RDWR)} on every entry
before it calls @code{MHD_stop_daemon()}, and verify that the daemon
now stops even while a client is connected and silent.

@item
Change the daemon flags to plain
@code{MHD_USE_INTERNAL_POLLING_THREAD} without
@code{MHD_USE_THREAD_PER_CONNECTION} and observe that the server now
serves exactly one upgraded client and stops answering everybody else.
Then repair it: leave the socket non-blocking, start a thread from
within the callback, and return immediately.

@item
Have the client send a line longer than @code{LINE_SIZE}.  The example
silently drops the excess.  What should a real protocol do instead,
and which status code would you have used if the problem had been
detectable during the handshake?

@end itemize
