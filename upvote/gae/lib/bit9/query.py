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

"""Defines the Query class used to build queries for Models."""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from upvote.gae.lib.bit9 import constants
from upvote.gae.lib.bit9 import exceptions as excs
from upvote.gae.lib.bit9 import query_nodes
from absl import logging


class Query(object):
  """Provides incremental construction of and execution for a model query."""

  def __init__(self, model_cls):
    self._model_cls = model_cls
    self._filters = []
    self._limit = None
    self._offset = None
    self._expands = set()
    self._sort = None

  def filter(self, *filters):
    """Add property filter(s) to the query."""
    logging.info(
        'Adding query filter(s): %s',
        ', '.join('"{}"'.format(filter_) for filter_ in filters))

    for filter_ in filters:
      prop = filter_.prop
      if not self._model_cls.is_valid_property(prop):
        raise excs.QueryError(
            '{!r} cannot be used to query {}'.format(
                prop, self._model_cls.__name__))

    self._filters.extend(filters)
    return self

  def limit(self, limit):
    """Add a result limit to the query."""
    logging.info('Adding query limit: %s', limit)

    if limit < 0:
      raise excs.QueryError('Limit must be non-negative')
    self._limit = limit
    return self

  def expand(self, *props):
    """Expand foreign key(s) in the query results."""
    logging.info(
        'Adding query expands: %s',
        ', '.join('{} -> {}'.format(prop, prop.expands_to) for prop in props))

    for prop in props:
      if not self._model_cls.is_valid_property(prop):
        raise excs.QueryError(
            '{}.{} cannot be used with {}'.format(
                prop.model_cls_name, prop.name, self._model_cls.__name__))
      elif not prop.expandable:
        raise excs.QueryError(
            'Property {} not marked as expandable'.format(prop))

    self._expands |= set(props)
    return self

  def order(self, prop):
    """Order the query results by the given property.

    Args:
      prop: Property or OrderNode (i.e. a negated Property), The property to be
          sorted on can be given as "Model.prop" to get an ascending sort or
          "-Model.prop" to get a descending one.

    Returns:
      A reference to the query.

    Raises:
      ValueError: An improper argument was provided.
      QueryError: The provided property is not associated with the Model being
          queried.
    """
    if isinstance(prop, query_nodes.OrderNode):
      order = prop
      prop = order.prop
    else:
      order = query_nodes.OrderNode(prop)

    logging.info('Adding query sort: %s', order)

    if not self._model_cls.is_valid_property(order.prop):
      raise excs.QueryError(
          'Invalid Property argument "{}" cannot be used with {}'.format(
              order.prop, self._model_cls.__name__))
    self._sort = order
    return self

  def _build_query_args(self):
    """Builds a list of HTTP query args corresponding to this Query instance."""
    # Sort query arguments to facilitate testing.
    query_args = sorted(['q={}'.format(filter_) for filter_ in self._filters])
    if self._sort is not None:
      query_args.append('sort={}'.format(self._sort))
    if self._offset is not None:
      query_args.append('offset={}'.format(self._offset))
    if self._limit is not None:
      query_args.append('limit={}'.format(self._limit))
    query_args.extend(
        sorted('expand={}'.format(prop.name) for prop in self._expands))

    return query_args

  def count(self, context):
    """Retrieve the count of results that would be returned by the query.

    Args:
      context: Context, The API context to be used to make the request.

    Returns:
      int, The number of objects that would be returned by this query instance.
    """
    self._limit = -1  # The REST API interprets a limit of -1 as 'count'.

    logging.info(
        'Executing %s query count: %s', self._model_cls.__name__,
        '&'.join(self._build_query_args()))

    response = context.ExecuteRequest(
        constants.METHOD.GET, api_route=self._model_cls.ROUTE,
        query_args=self._build_query_args())

    return response['count']

  def execute(self, context):
    """Execute the query and return the result.

    Args:
      context: Context, The API context to be used to make the request.

    Returns:
      list<Model>, The results of the query.
    """
    logging.info(
        'Executing %s query: %s', self._model_cls.__name__,
        '&'.join(self._build_query_args()))

    response = context.ExecuteRequest(
        constants.METHOD.GET, api_route=self._model_cls.ROUTE,
        query_args=self._build_query_args())

    return [self._model_cls.from_dict(obj) for obj in response]
