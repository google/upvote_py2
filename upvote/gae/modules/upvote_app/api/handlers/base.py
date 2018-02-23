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

"""Base handler for Upvote views."""
import httplib
import logging

from google.appengine.datastore.datastore_query import Cursor
from google.appengine.ext import ndb

from upvote.gae.datastore import utils as model_utils
from upvote.gae.datastore.models import base
from upvote.gae.shared.common import handlers
from upvote.gae.shared.common import json_utils
from upvote.gae.shared.common import utils
from upvote.gae.shared.common import xsrf_utils
from upvote.shared import utils as upvote_utils


class Error(Exception):
  """Base error for upvote_app api handlers."""


class QueryError(Error):
  """Raised when a model query encounters an error."""


class QueryTypeError(QueryError):
  """Indicates a type conflict with the query parameters."""


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
    key = model_utils.GetKeyFromUrlsafe(query_param)
    if not key:
      raise QueryTypeError(
          'Query param "%s" could not be converted to ndb.Key' % query_param)
    return key
  else:
    return query_param


def RequireCapability(capability):
  """Decorator function to enforce access requriements for handlers."""
  def _CheckCapability(original_function):
    """Check function."""
    def _Check(*args, **kwargs):
      """Check user permissions and return error or original function."""
      self = args[0]
      if isinstance(self, BaseHandler):
        if self.user.is_admin or self.user.HasPermissionTo(capability):
          return original_function(*args, **kwargs)
        else:
          explanation = 'User %s doesn\'t have permission to %s' % (
              self.user.nickname, capability)
          self.abort(httplib.FORBIDDEN, explanation=explanation)
      else:
        raise ValueError
    return _Check
  return _CheckCapability


class BaseHandler(handlers.UpvoteRequestHandler):
  """Base handler class."""

  def initialize(self, request, response):
    """Initalizes the handler.

    Overriden to set the XSRF cookie.
    Args:
      request: The requst to handle.
      response: The response of the handler.
    """
    super(BaseHandler, self).initialize(request, response)
    # Ensure there is an User associated with the AppEngine user making
    # this request.
    self.user = base.User.GetOrInsert()

    # Set the XSRF cookie.
    if self.request and self.response:
      running_locally = utils.RunningLocally()
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

  def RequireCapability(self, capability):
    """Check whether user has a given capability."""
    if not self.user.is_admin and not self.user.HasPermissionTo(capability):
      self.abort(
          httplib.FORBIDDEN,
          explanation='User doesn\'t have permission to %s' % capability)

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
      self.respond_with_page([], None, False)
      return

    content, cursor, more = query.fetch_page(
        self.per_page, start_cursor=self.cursor)
    if callback:
      content = callback(content)
    self.respond_with_page(content, cursor, more)


class _MetaBaseQueryHandler(type):
  """Meta class that enforces a MODEL_CLASS property on query handlers."""

  def __new__(mcs, name, parents, dct):
    # Only enforce MODEL_CLASS definition for BaseQueryHandler subclasses.
    if name != 'BaseQueryHandler':
      model_class = dct.get('MODEL_CLASS')
      if model_class is None:
        raise NotImplementedError('%s must set MODEL_CLASS' % name)
      elif not issubclass(model_class, ndb.Model):
        raise NotImplementedError(
            '%s.MODEL_CLASS must be a subclass of ndb.Model' % name)

    return super(_MetaBaseQueryHandler, mcs).__new__(mcs, name, parents, dct)


class BaseQueryHandler(BaseHandler):
  """Base handler class for model queries.

  The primary use of this module is to access Upvote's stored Entities. This
  class provides a generic interface for this use-case.
  """
  # Enforce MODEL_CLASS definition.
  __metaclass__ = _MetaBaseQueryHandler

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
      field_name = upvote_utils.CamelToSnakeCase(search_base)

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
      if not model_utils.HasProperty(self.MODEL_CLASS, field_name):
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
