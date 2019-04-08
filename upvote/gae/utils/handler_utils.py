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
from google.appengine.datastore.datastore_query import Cursor
from google.appengine.ext import ndb

from upvote.gae.datastore import utils as datastore_utils
from upvote.gae.datastore.models import user as user_models
from upvote.gae.utils import env_utils
from upvote.gae.utils import json_utils
from upvote.gae.utils import string_utils
from upvote.gae.utils import xsrf_utils


_COMMON_ERROR_CODES = [
    httplib.BAD_REQUEST, httplib.FORBIDDEN, httplib.NOT_FOUND,
    httplib.INTERNAL_SERVER_ERROR]


class Error(Exception):
  """Base error for upvote_app api handlers."""


class QueryError(Error):
  """Raised when a model query encounters an error."""


class QueryTypeError(QueryError):
  """Indicates a type conflict with the query parameters."""


def _HtmlEscape(s):
  """Escape a string to make it HTML-safe."""
  return cgi.escape(s, quote=True).replace("'", '&#39;')


def RequirePermission(permission):
  """Decorator function to enforce access requirements for handlers."""
  def _CheckPermission(original_function):
    """Check function."""
    def _Check(*args, **kwargs):
      """Check user permissions and return error or original function."""
      self = args[0]
      if isinstance(self, UserFacingHandler):
        if self.user.is_admin or self.user.HasPermission(permission):
          return original_function(*args, **kwargs)
        else:
          explanation = 'User %s doesn\'t have permission to %s' % (
              self.user.nickname, permission)
          self.abort(httplib.FORBIDDEN, explanation=explanation)
      else:
        raise ValueError
    return _Check
  return _CheckPermission


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
  """Base class for all Upvote RequestHandlers.

  NOTE: Request handler implementors should not subclass UpvoteRequestHandler,
  but instead use one of the more specialized subclasses below.
  """

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
    if not env_utils.RunningInProd():
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


class CronJobHandler(UpvoteRequestHandler):
  """Request handler intended for cron jobs only.

  For more details, see:
  https://cloud.google.com/appengine/docs/standard/python/config/cron#securing_urls_for_cron
  """

  def dispatch(self):
    if 'X-AppEngine-Cron' not in self.request.headers:
      self.abort(httplib.FORBIDDEN, 'X-AppEngine-Cron header is required')
    super(CronJobHandler, self).dispatch()


class UserFacingHandler(UpvoteRequestHandler):
  """Handler for servicing user-facing requests."""

  def initialize(self, request, response):
    """Initalizes the handler.

    Overridden to set the XSRF cookie.
    Args:
      request: The requst to handle.
      response: The response of the handler.
    """
    super(UserFacingHandler, self).initialize(request, response)
    # Ensure there is an User associated with the AppEngine user making
    # this request.
    self.user = user_models.User.GetOrInsert()

    # Set the XSRF cookie.
    if self.request and self.response:
      running_locally = env_utils.RunningLocally()
      domain = self.request.host
      if ':' in domain:
        domain = domain.split(':')[0]
      self.response.set_cookie(
          xsrf_utils.ANGULAR_XSRF_COOKIE_NAME, value=xsrf_utils.GenerateToken(),
          domain=domain, secure=(not running_locally))

  @property
  def json_encoder(self):
    if not hasattr(self, '_json_encoder'):
      self._json_encoder = json_utils.JSONEncoderJavaScript()
    return self._json_encoder

  @property
  def cursor(self):
    if not hasattr(self, '_cursor'):
      cursor = Cursor(urlsafe=self.request.get('cursor'))
      self._cursor = cursor
    return self._cursor

  @property
  def per_page(self):
    fetch_limit = 10
    try:
      fetch_limit = int(self.request.get('perPage', 10))
    except ValueError:
      logging.warning(
          'Cannot make %s into integer', self.request.get('perPage'))
    return fetch_limit

  def RequirePermission(self, permission):
    """Check whether user has a given permission."""
    if not self.user.is_admin and not self.user.HasPermission(permission):
      self.abort(
          httplib.FORBIDDEN,
          explanation='User doesn\'t have permission to %s' % permission)

  def respond_with_page(self, content, cursor, has_more):
    """Sets the handler response to the page contents provided.

    Args:
      content: list, A list of the objects to be used as the page contents.
      cursor: datastore_query.Cursor, The cursor representing the resumption
          point for the next page of the query.
      has_more: bool, Whether there are more results after this page.
    """
    safe_cursor = cursor.urlsafe() if cursor else None
    response_dict = {
        'content': content,
        'cursor': safe_cursor,
        'more': has_more,
        'per_page': self.per_page}
    logging.info('Responding with a page of %d item(s)', len(content))
    self.respond_json(response_dict)

  def respond_with_query_page(self, query, callback=None):
    """Sets the handler response to a page of query results.

    Args:
      query: ndb.Query or None, A query object which will be executed and the
          results used as the page contents. If None, the response will simulate
          the results of an empty query.
      callback: function, A function that will be applied to the list of query
          results.
    """
    # NOTE: AFAICT, ndb has no notion of a "Null Query" so we need an
    # extra code path for when we don't want to return any results.
    if not query:
      logging.info('No query results are being returned')
      self.respond_with_page([], None, False)
      return

    content, cursor, more = query.fetch_page(
        self.per_page, start_cursor=self.cursor)
    if callback:
      content = callback(content)
    self.respond_with_page(content, cursor, more)


class _MetaUserFacingQueryHandler(type):
  """Meta class that enforces a MODEL_CLASS property on query handlers."""

  def __new__(mcs, name, parents, dct):
    # Only enforce MODEL_CLASS definition for UserFacingQueryHandler subclasses.
    if name != 'UserFacingQueryHandler':
      model_class = dct.get('MODEL_CLASS')
      if model_class is None:
        raise NotImplementedError('%s must set MODEL_CLASS' % name)
      elif not issubclass(model_class, ndb.Model):
        raise NotImplementedError(
            '%s.MODEL_CLASS must be a subclass of ndb.Model' % name)

    return super(_MetaUserFacingQueryHandler, mcs).__new__(
        mcs, name, parents, dct)


def _CoerceQueryParam(field, query_param):
  """Attempts to coerce `query_param` to match the ndb type of `field`.

  Args:
    field: The ndb field being queried.
    query_param: The query term to be coerced.

  Returns:
    The query param coerced if a coercion was possible.

  Raises:
    QueryTypeError: If there is an error with the type conversion.
  """
  if isinstance(field, ndb.IntegerProperty):
    try:
      return int(query_param)
    except ValueError:
      raise QueryTypeError(
          'Query param "%s" could not be converted to integer' % query_param)
  elif isinstance(field, ndb.BooleanProperty):
    if query_param.lower() == 'true':
      return True
    elif query_param.lower() == 'false':
      return False
    else:
      raise QueryTypeError(
          'Query param "%s" could not be converted to boolean' % query_param)
  elif isinstance(field, ndb.KeyProperty):
    key = datastore_utils.GetKeyFromUrlsafe(query_param)
    if not key:
      raise QueryTypeError(
          'Query param "%s" could not be converted to ndb.Key' % query_param)
    return key
  else:
    return query_param


class UserFacingQueryHandler(UserFacingHandler):
  """Base handler class for model queries.

  The primary use of this module is to access Upvote's stored Entities. This
  class provides a generic interface for this use-case.
  """
  # Enforce MODEL_CLASS definition.
  __metaclass__ = _MetaUserFacingQueryHandler

  # NOTE: This needs to be set to an ndb.Model on subclasses.
  MODEL_CLASS = None

  # Indicates whether or not the type of the ID for MODEL_CLASS is integral
  HAS_INTEGRAL_ID_TYPE = True

  def _ConvertToIDType(self, str_id):
    """Converts the string form of the model ID to the correct type.

    Args:
      str_id: The ID string.

    Returns:
      The ID query coerced to the correct type.

    Raises:
      QueryError: If type coercion fails.
    """
    if self.HAS_INTEGRAL_ID_TYPE:
      try:
        return int(str_id)
      except ValueError:
        raise QueryError('%s ID must be integral' % self.MODEL_CLASS.__name__)
    return str_id

  def _Query(self, callback=None):
    """Determines the query to run (field or list) and runs it.

    Makes this determination based on the presence of the searchBase query
    parameter. The searchBase parameter differentiates the two queries because
    an empty searchBase will never yield a valid field query.

    Args:
      callback: func(entity), If provided, the callback to apply to each query
          result.
    """
    search_base = self.request.get('searchBase', None)
    search_term = self.request.get('search', None)

    has_base = search_base is not None
    has_term = search_term is not None
    if has_base or has_term:
      # If either a search base or a search term are provided, both must be.
      if not (has_base and has_term):
        self.abort(
            httplib.BAD_REQUEST,
            explanation='Both search and searchBase must be provided')
      search_dict = {search_base: search_term}
    else:
      search_dict = {}

    try:
      query = self._QueryModel(search_dict)
    except QueryError as e:
      self.abort(httplib.BAD_REQUEST, explanation=str(e))
    else:
      self.respond_with_query_page(query, callback)

  def _QueryModel(self, search_dict, ancestor=None):
    """Queries the model class for field-value pairs.

    Args:
      search_dict: A dictionary mapping from field name to search by to the
          search term.
      ancestor: ndb.Key, If provided, the ancestor for the query.

    Returns:
      The model query.

    Raises:
      QueryError: If the queried field is not a property of the model.
      QueryTypeError: If search_term does not match the type of the search_base
          model property.
    """
    filter_nodes = []
    for search_base, search_term in search_dict.items():
      field_name = string_utils.CamelToSnakeCase(search_base)

      # If the model class offers a translation function for property queries,
      # invoke it and set the field and search term to the result.
      try:
        field_name, search_term = self.MODEL_CLASS.TranslatePropertyQuery(
            field_name, search_term)
      except AttributeError:
        pass
      else:
        logging.info('Converted query to (%s = %s)', field_name, search_term)

      # Check for the property on the model itself (as opposed to, say, catching
      # a getattr exception) to ensure that the field being accessed is an ndb
      # property as opposed to a Python attribute.
      if not datastore_utils.HasProperty(self.MODEL_CLASS, field_name):
        raise QueryError('Invalid searchBase %s' % field_name)

      field = getattr(self.MODEL_CLASS, field_name)

      # If the field is of a non-string type, attempt to coerce the argument to
      # conform to this type
      search_term = _CoerceQueryParam(field, search_term)

      filter_nodes.append(ndb.FilterNode(field_name, '=', search_term))

    query = self.MODEL_CLASS.query(ancestor=ancestor)
    if filter_nodes:
      query = query.filter(ndb.AND(*filter_nodes))
    return query


class AdminOnlyHandler(UserFacingHandler):
  """Request handler restricted to admins only."""

  def dispatch(self):
    if not self.user.is_admin:
      self.abort(
          httplib.FORBIDDEN,
          'User %s does not have admin privileges' % self.user.nickname)
    super(AdminOnlyHandler, self).dispatch()


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


def ConfigureErrorHandlers(wsgi_app, error_codes=None):
  """Helper method for creating error handlers for the given HTTP statuses.

  Args:
    wsgi_app: A webapp2.WSGIApplication instance.
    error_codes: A list of HTTP status integers to create error handlers for.
  """
  error_codes = _COMMON_ERROR_CODES if error_codes is None else error_codes
  for error_code in error_codes:
    wsgi_app.error_handlers[error_code] = CreateErrorHandler(error_code)
