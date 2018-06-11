# Copyright 2017 Google Inc. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS-IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Common Webapp2 handlers."""

import cgi
import functools
import httplib
from inspect import isclass
import logging
import sys
import traceback
import webapp2

from google.appengine.api import modules

from upvote.gae.shared.common import utils
from upvote.gae.utils import json_utils


_COMMON_ERROR_CODES = [
    httplib.BAD_REQUEST, httplib.FORBIDDEN, httplib.NOT_FOUND,
    httplib.INTERNAL_SERVER_ERROR]


def _HtmlEscape(s):
  """Escape a string to make it HTML-safe."""
  return cgi.escape(s, quote=True).replace("'", '&#39;')


def RecordRequest(original_function):
  """Decorator function to increment RequestCounter on response success."""

  # functools.wraps restores the original properties of the wrapped function.
  # This is useful for debugging and tracing.
  @functools.wraps(original_function)
  def _RecordRequest(handler, *args, **kwargs):
    """Wraps `original_function` to increment RequestCounter after calling.

    The call to `original_function` should cause all intentional or
    unintentional errors to raise an exception:
      * Intentional errors should be indicated with the abort call and will be
        caught with the registered ErrorHandler for the application.
      * Unintentional errors will be caught by the `handle_exception` handler
    Each of these handlers will increment the proper status values on
    RequestCounter.

    Args:
      handler: The handler's `self` argument
      *args: The args to be passed to original_function
      **kwargs: The kwargs to be passed to original_function

    Returns:
      A wrapped version of `original_function`
    """
    ret = original_function(handler, *args, **kwargs)

    handler.RequestCounter.Increment(handler.response.status_int)

    return ret

  return _RecordRequest


class UpvoteRequestHandler(webapp2.RequestHandler):
  """Base class for all Upvote RequestHandlers."""

  @property
  def RequestCounter(self):
    """Returns a monitoring.RequestCounter specific to this webapp2.RequestHandler.

    Subclasses should override this method in order to enable monitoring of
    requests made to this RequestHandler.

    Returns:
      A monitoring.RequestCounter to be used for tracking requests to this
      RequestHandler.
    """
    return None

  @property
  def json_encoder(self):
    if not hasattr(self, '_json_encoder'):
      self._json_encoder = json_utils.JSONEncoder()
    return self._json_encoder

  def handle_exception(self, exception, unused_debug_mode):
    """Handle any uncaught exceptions.

    Args:
      exception: The exception that was thrown.
      unused_debug_mode: True if the application is running in debug mode.
    """
    # Default to a 500.
    http_status = httplib.INTERNAL_SERVER_ERROR

    # Calls to abort() raise a child class of HTTPException, so extract the
    # HTTP status and explanation if possible.
    if isinstance(exception, webapp2.HTTPException):
      http_status = getattr(exception, 'code', httplib.INTERNAL_SERVER_ERROR)

      # Write out the exception's explanation to the response body
      escaped_explanation = _HtmlEscape(str(exception))
      self.response.write(escaped_explanation)

    # If the RequestHandler has a corresponding request counter, increment it.
    if self.RequestCounter is not None:
      self.RequestCounter.Increment(http_status)

    # If the exception occurs within a unit test, make sure the stacktrace is
    # easily discerned from the console.
    if not utils.RunningInProd():
      exc_type, exc_value, exc_traceback = sys.exc_info()
      traceback.print_exception(exc_type, exc_value, exc_traceback)

    # Set the response code and log the exception regardless.
    self.response.set_status(http_status)
    logging.exception(exception)

  def respond_json(self, response_data):
    try:
      response_json = self.json_encoder.encode(response_data)
    except TypeError as e:
      logging.error('Failed to serialize JSON response: %s', e)
      self.abort(httplib.INTERNAL_SERVER_ERROR, 'Failed to serialize response')
    else:
      self.response.content_type = 'application/json'
      self.response.write(response_json)


class AckHandler(webapp2.RequestHandler):
  """Simple handler for responding with HTTP 200."""

  def get(self):
    self.response.status = httplib.OK
    self.response.write('ACK (%s)' % modules.get_current_module_name())


def _GetHandlerFromRequest(request):
  """Safely extracts a request handler from a Request.

  Args:
    request: A webapp2.Request instance.

  Returns:
    The handler that corresponds to the given Request (which can be a class or
    method), or None if there is no such handler (e.g. 404's).
  """
  route = getattr(request, 'route', None)
  if route is not None:
    return getattr(route, 'handler', None)


def CreateErrorHandler(http_status):
  """Creates a WSGIApplication error handler function for an HTTP status."""

  def ErrorHandler(request, response, exception):
    """Error handling method to be registered to WSGIApplication.error_handlers.

    Args:
      request: A webapp2.Request instance.
      response: A webapp2.Response instance.
      exception: The uncaught exception.
    """
    handler = _GetHandlerFromRequest(request)

    # If the target RequestHandler is an UpvoteRequestHandler, see if there's an
    # associated RequestCounter and increment it to reflect the error.
    if isclass(handler) and issubclass(handler, UpvoteRequestHandler):
      request_counter = handler().RequestCounter
      if request_counter is not None:
        request_counter.Increment(http_status)

    response.set_status(http_status)
    logging.exception(exception)
    raise exception

  return ErrorHandler


def CreateErrorHandlersForApplications(
    wsgi_apps, error_codes=None):
  """Helper method for creating error handlers for the given HTTP statuses.

  Args:
    wsgi_apps: A list of webapp2.WSGIApplication instances.
    error_codes: A list of HTTP status integers to create error handlers for.
  """
  error_codes = _COMMON_ERROR_CODES if error_codes is None else error_codes
  for wsgi_app in wsgi_apps:
    for error_code in error_codes:
      wsgi_app.error_handlers[error_code] = CreateErrorHandler(error_code)
