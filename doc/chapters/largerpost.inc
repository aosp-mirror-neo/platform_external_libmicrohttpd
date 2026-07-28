The previous chapter introduced a way to upload data to the server, but the developed example program
has some shortcomings, such as not being able to handle larger chunks of data. In this chapter, we
are going to discuss a more advanced server program that allows clients to upload a file in order to
have it stored on the server's filesystem. The server shall also watch and limit the number of
clients concurrently uploading, responding with a proper busy message if necessary.


@heading Prepared answers
We choose to operate the server with the @code{MHD_USE_INTERNAL_POLLING_THREAD} method. This makes it easier to
synchronize the global states at the cost of possible delays for other connections if the processing
of a request is too slow. One of these variables that needs to be shared for all connections is the
total number of clients that are uploading.

@verbatim
#define MAXCLIENTS      2
static unsigned int    nr_of_uploading_clients = 0;
@end verbatim
@noindent

If there are too many clients uploading, we want the server to respond to all requests with a busy
message.
@verbatim
const char* busypage =
  "<html><body>This server is busy, please try again later.</body></html>";
@end verbatim
@noindent

Otherwise, the server will send a @emph{form} that informs the user of the current number of uploading clients,
and ask her to pick a file on her local filesystem which is to be uploaded.
@verbatim
const char* askpage = "<html><body>\n\
                       Upload a file, please!<br>\n\
                       There are %u clients uploading at the moment.<br>\n\
                       <form action=\"/filepost\" method=\"post\" \
                         enctype=\"multipart/form-data\">\n\
                       <input name=\"file\" type=\"file\">\n\
                       <input type=\"submit\" value=\" Send \"></form>\n\
                       </body></html>";
@end verbatim
@noindent

If the upload has succeeded, the server will respond with a message saying so.
@verbatim
const char* completepage = "<html><body>The upload has been completed.</body></html>";
@end verbatim
@noindent

We want the server to report malformed requests and internal errors, such as file access
problems, adequately.
@verbatim
const char* servererrorpage
  = "<html><body>Invalid request.</body></html>";
const char* fileexistspage
  = "<html><body>This file already exists.</body></html>";
const char* fileioerror
  = "<html><body>IO error writing to disk.</body></html>";
const char* postprocerror
  = "<html><body>Error processing POST data.</body></html>";
@end verbatim
@noindent

It would be tolerable to send all these responses undifferentiated with a @code{200 HTTP_OK}
status code but in order to improve the @code{HTTP} conformance of our server a bit, we extend the
@code{send_page} function so that it accepts individual status codes.

@verbatim
static enum MHD_Result
send_page (struct MHD_Connection *connection,
	   const char* page, unsigned int status_code)
{
  enum MHD_Result ret;
  struct MHD_Response *response;

  response = MHD_create_response_from_buffer_copy (strlen (page), page);
  if (!response) return MHD_NO;

  ret = MHD_queue_response (connection, status_code, response);
  MHD_destroy_response (response);

  return ret;
}
@end verbatim
@noindent

Note how we ask @emph{MHD} to make its own copy of the message data---that is what the
@code{_copy} suffix stands for. The reason behind this will become clear later.


@heading Connection cycle
The decision whether the server is busy or not is made right at the beginning of the connection. To
do that at this stage is especially important for @emph{POST} requests because if no response is
queued at this point, and @code{MHD_YES} returned, @emph{MHD} will not send any queued messages until
a postprocessor has been created and the post iterator is called at least once.

@verbatim
static enum MHD_Result
answer_to_connection (void *cls, struct MHD_Connection *connection,
		      const char *url,
                      const char *method, const char *version,
		      const char *upload_data,
                      size_t *upload_data_size, void **req_cls)
{
  if (NULL == *req_cls)
    {
      struct connection_info_struct *con_info;

      if (nr_of_uploading_clients >= MAXCLIENTS)
        return send_page(connection, busypage, MHD_HTTP_SERVICE_UNAVAILABLE);
@end verbatim
@noindent

If the server is not busy, the @code{connection_info} structure is initialized as usual, with
the addition of a filepointer for each connection.  The status code is set to zero, which
we use as the marker for "no answer decided yet".

@verbatim
      con_info = malloc (sizeof (struct connection_info_struct));
      if (NULL == con_info) return MHD_NO;
      con_info->answercode = 0;
      con_info->fp = NULL;

      if (0 == strcmp (method, "POST"))
        {
          ...
        }
      else con_info->connectiontype = GET;

      *req_cls = (void*) con_info;

      return MHD_YES;
    }
@end verbatim
@noindent

For @emph{POST} requests, the postprocessor is created and we register a new uploading client. From
this point on, there are many possible places for errors to occur that make it necessary to interrupt
the uploading process. We need a means of having the proper response message ready at all times.
Therefore, the @code{connection_info} structure is extended to hold the most current response
message so that whenever a response is sent, the client will get the most informative message.
@verbatim
      if (0 == strcmp (method, "POST"))
        {
          con_info->postprocessor
	    = MHD_create_post_processor (connection, POSTBUFFERSIZE,
                                         iterate_post, (void*) con_info);

          if (NULL == con_info->postprocessor)
            {
              free (con_info);
              return MHD_NO;
            }

          nr_of_uploading_clients++;

          con_info->connectiontype = POST;
        }
      else con_info->connectiontype = GET;
@end verbatim
@noindent

If the connection handler is called for the second time, @emph{GET} requests will be answered with
the @emph{form}. We can keep the buffer under function scope, because we asked @emph{MHD} to make its
own copy of it for as long as it is needed.
@verbatim
  if (0 == strcmp (method, "GET"))
    {
      char buffer[1024];

      snprintf (buffer, sizeof (buffer), askpage, nr_of_uploading_clients);
      return send_page (connection, buffer, MHD_HTTP_OK);
    }
@end verbatim
@noindent


The rest of the @code{answer_to_connection} function is very similar to the @code{simplepost.c}
example, except the more flexible content of the responses. The @emph{POST} data is processed until
there is none left and the execution falls through to return an error page if the connection
constituted no expected request method. Note that once we know the answer---because something
went wrong---we no longer feed the data to the post processor, but we still have to consume it,
or the client would never get to read our response.
@verbatim
  if (0 == strcmp (method, "POST"))
    {
      struct connection_info_struct *con_info = *req_cls;

      if (0 != *upload_data_size)
        {
          if (0 == con_info->answercode)
            {
              if (MHD_YES !=
                  MHD_post_process (con_info->postprocessor,
	                            upload_data, *upload_data_size))
                {
                  con_info->answerstring = postprocerror;
                  con_info->answercode = MHD_HTTP_INTERNAL_SERVER_ERROR;
                }
            }
          *upload_data_size = 0;

          return MHD_YES;
        }

      if (NULL != con_info->fp)
        {
          fclose (con_info->fp);
          con_info->fp = NULL;
        }
      if (0 == con_info->answercode)
        {
          con_info->answerstring = completepage;
          con_info->answercode = MHD_HTTP_OK;
        }
      return send_page (connection, con_info->answerstring,
	       		con_info->answercode);
    }

  return send_page(connection, errorpage, MHD_HTTP_BAD_REQUEST);
}
@end verbatim
@noindent


@heading Storing the data
Unlike the @code{simplepost.c} example, here it is to be expected that post iterator will be called
several times now. This means that for any given connection (there might be several concurrent of them)
the posted data has to be written to the correct file. That is why we store a file handle in every
@code{connection_info}, so that it is preserved between successive iterations.
@verbatim
static enum MHD_Result
iterate_post (void *coninfo_cls, enum MHD_ValueKind kind,
	      const char *key,
	      const char *filename, const char *content_type,
              const char *transfer_encoding, const char *data,
	      uint64_t off, size_t size)
{
  struct connection_info_struct *con_info = coninfo_cls;
  FILE *fp;
@end verbatim
@noindent

Because the following actions depend heavily on correct file processing, which might be error prone,
we record the page to answer with as soon as anything goes wrong.  Note that the iterator always
returns @code{MHD_YES}: returning @code{MHD_NO} would abort the post processor and thus make it
impossible to send our carefully chosen error page to the client.

In the "askpage" @emph{form}, we told the client to label its post data with the "file" key. Anything else
would be an error.

@verbatim
  if (0 != strcmp (key, "file"))
    {
      con_info->answerstring = servererrorpage;
      con_info->answercode = MHD_HTTP_BAD_REQUEST;
      return MHD_YES;
    }
@end verbatim
@noindent

If the iterator is called for the first time, no file will have been opened yet. The @code{filename}
string contains the name of the file (without any paths) the user selected on his system. We want to
take this as the name the file will be stored on the server and make sure no file of that name exists
(or is being uploaded) before we create one (note that the code below technically contains a
race between the two "fopen" calls, but we will overlook this for portability sake).
@verbatim
  if (!con_info->fp)
    {
      if (0 != con_info->answercode)  /* something went wrong before */
        return MHD_YES;

      if (NULL != (fp = fopen (filename, "rb")) )
        {
          fclose (fp);
          con_info->answerstring = fileexistspage;
          con_info->answercode = MHD_HTTP_FORBIDDEN;
          return MHD_YES;
        }

      con_info->fp = fopen (filename, "ab");
      if (!con_info->fp)
        {
          con_info->answerstring = fileioerror;
          con_info->answercode = MHD_HTTP_INTERNAL_SERVER_ERROR;
          return MHD_YES;
        }
    }
@end verbatim
@noindent


Occasionally, the iterator function will be called even when there are 0 new bytes to process. The
server only needs to write data to the file if there is some.
@verbatim
  if (size > 0)
    {
      if (!fwrite (data, sizeof (char), size, con_info->fp))
        {
          con_info->answerstring = fileioerror;
          con_info->answercode = MHD_HTTP_INTERNAL_SERVER_ERROR;
        }
    }
@end verbatim
@noindent

If this point has been reached without setting an answer code, everything worked well for this
iteration. If the upload has finished, this iterator function will not be called again and
@code{answer_to_connection} will declare success.
@verbatim
  return MHD_YES;
}
@end verbatim
@noindent


The new client was registered when the postprocessor was created. Likewise, we unregister the client
on destroying the postprocessor when the request is completed.
@verbatim
static void
request_completed (void *cls, struct MHD_Connection *connection,
     		        void **req_cls,
                        enum MHD_RequestTerminationCode toe)
{
  struct connection_info_struct *con_info = *req_cls;

  if (NULL == con_info) return;

  if (con_info->connectiontype == POST)
    {
      if (NULL != con_info->postprocessor)
        {
          MHD_destroy_post_processor (con_info->postprocessor);
          nr_of_uploading_clients--;
        }

      if (con_info->fp) fclose (con_info->fp);
    }

  free (con_info);
  *req_cls = NULL;
}
@end verbatim
@noindent


This is essentially the whole example @code{largepost.c}.


@heading Remarks
Now that the clients are able to create files on the server, security aspects are becoming even more
important than before. Aside from proper client authentication, the server should always make sure
explicitly that no files will be created outside of a dedicated upload directory.  In particular,
filenames must be checked to not contain strings like "../".
