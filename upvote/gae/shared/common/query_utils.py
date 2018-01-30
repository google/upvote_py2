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

"""Utilities for performing ndb queries."""

import itertools

from google.appengine.ext import deferred

from upvote.shared import constants

_BATCH_SIZE = 2000
_SMALL_BATCH_SIZE = 500


def PaginatedFetch(query, page_size=_SMALL_BATCH_SIZE, **query_options):
  """Fetches the results of a query by aggregating result batches.

  This query strategy reduces the possibility of datastore timeouts which can
  occur as a consequence of entity contention or a large query.

  Args:
    query: ndb.Query, the ndb query to paginate through and collect the results.
    page_size: int, The number of entities to request in each page.
    **query_options: dict, q_options kwarg param to pass to the fetch query.

  Returns:
    A list of query results.
  """
  return PaginatedMap(query, None, page_size=page_size, **query_options)


def PaginatedMap(query, callback, page_size=_SMALL_BATCH_SIZE, **query_options):
  """Maps a callback over the results of a query by aggregating result batches.

  This query strategy reduces the possibility of datastore timeouts which can
  occur as a consequence of entity contention or a large query.

  Args:
    query: ndb.Query, the ndb query to paginate through and collect the results.
    callback: func, The function to be applied to each result.
    page_size: int, The number of entities to request in each page.
    **query_options: dict, q_options kwarg param to pass to the fetch query.

  Returns:
    A list of query results with the callback applied.
  """
  reduce_callback = lambda current, next_: current + [next_]
  return PaginatedMapReduce(
      query, callback, reduce_callback, initial=[], page_size=page_size,
      **query_options)


def PaginatedMapReduce(
    query, map_callback, reduce_callback, initial=None,
    page_size=_SMALL_BATCH_SIZE, **query_options):
  """Performs a map-reduce operation over the results of a query using batches.

  This query strategy reduces the possibility of datastore timeouts which can
  occur as a consequence of entity contention or a large query.

  Args:
    query: ndb.Query, the ndb query to paginate through and map-reduce the
        results.
    map_callback: func, The function to be applied to each result before reduce.
    reduce_callback: func, The function to be used to reduce the mapped results.
    initial: any, The initial value for reduce.
    page_size: int, The number of entities to request in each page.
    **query_options: dict, q_options kwarg param to pass to the fetch query.

  Returns:
    The result of the map-reduce operation on the query results.
  """
  last_page = []
  result = initial
  more = True
  cursor = None
  while more:
    # Asynchronously fetch the next page.
    page_future = query.fetch_page_async(
        page_size, start_cursor=cursor, **query_options)

    # Apply the callback to each of the previous page's results and add them to
    # the existing results.
    result = reduce(  # pylint: disable=bad-builtin
        reduce_callback, itertools.imap(map_callback, last_page), result)

    # Resolve the future to get the results and pagination state.
    last_page, cursor, more = page_future.get_result()

  result = reduce(  # pylint: disable=bad-builtin
      reduce_callback, itertools.imap(map_callback, last_page), result)
  return result


def Paginate(query, page_size=_SMALL_BATCH_SIZE, **query_options):
  """Performs the given query and breaks the results up into batches.

  Args:
    query: ndb.Query, the ndb query to paginate through and collect the results.
    page_size: int, The number of entities to request in each page.
    **query_options: dict, Any query option keyword args to pass to the query.

  Yields:
    Lists of results from the given query, at most page_size in length.
  """
  results = []
  cursor = None
  more = True

  while more:
    # Asynchronously fetch the next page.
    page_future = query.fetch_page_async(
        page_size, start_cursor=cursor, **query_options)

    # According to the docs, if more is True, there are *probably* more results.
    if results:
      yield results

    results, cursor, more = page_future.get_result()

  # Don't forget the last batch.
  if results:
    yield results


def PaginatedCount(query, page_size=_SMALL_BATCH_SIZE):
  """Counts the results of a query by accumulating result batches.

  This query strategy reduces the possibility of datastore timeouts which can
  occur as a consequence of entity contention or a large query.

  Args:
    query: ndb.Query, the ndb query to paginate through and collect the results.
    page_size: int, The number of entities to request in each page.

  Returns:
    The number of results in the query.
  """
  total = 0
  page = None
  for page in Paginate(query, page_size=page_size, keys_only=True):
    # Assume the length of the page is the maximum requested.
    total += page_size
  # Correct the above assumption using the length of the last page.
  if page is not None:
    total -= page_size - len(page)
  return total


def QueuedPaginatedApply(
    query, callback, extra_args=None, extra_kwargs=None,
    pre_queue_callback=None, page_size=_BATCH_SIZE,
    queue=constants.TASK_QUEUE.DEFAULT, **query_options):
  """Applies a callback to each result of a query using a task queue.

  This function is intended for applications which must apply some action (e.g.
  starting a task) to each result of a query. If this query is large, normal
  iteration methods may result in datastore or taskqueue timeouts.

  The `pre_queue_callback` parameter warrants special attention. It provides a
  facility to avoid passing datastore entities as arguments to a deferred
  function. Entities often cannot be pickled (and, thus, cannot be passed as
  arguments to a deferred function), for instance when they contain lambdas or
  static methods. Additionally, entity references can become stale and result in
  lost updates.

  NOTE: This function does not return the results of the query.

  NOTE: `callback` and `pre_queue_callback` must be bound functions.

  Args:
    query: ndb.Query, The ndb query to paginate through.
    callback: func, The function to apply to each queued result.
        This result will be of the type returned by `pre_queue_callback` or
        ndb.Entity if `pre_queue_callback` is not provided.
    extra_args: list, Additional args to provide to the callback function on
        invocation.
    extra_kwargs: dict, Additional kwargs to provide to the callback function on
        invocation.
    pre_queue_callback: func(ndb.Entity), The function applied to each page's
        entities before they are passed to the task queue. This can be used to
        extract the key or other information necessary for use in `callback`.
    page_size: int, The number of entities to request in each page.
    queue: string, The name of the task queue to use for paginating. If no queue
        is provided, the default queue will be used.
    **query_options: dict, q_options kwarg param to pass to the fetch query.
  """
  # Defer the implementation function.
  deferred.defer(
      _QueuedPaginatedApply, query, callback, extra_args, extra_kwargs,
      pre_queue_callback, page_size, queue, _queue=queue, **query_options)


def _QueuedPaginatedApply(
    query, callback, extra_args, extra_kwargs, pre_queue_callback, page_size,
    queue, last_page_results=None, more=True, cursor=None, **query_options):
  """Implementation function for QueuedPaginatedApply."""
  if extra_args is None: extra_args = []
  if extra_kwargs is None: extra_kwargs = {}
  if last_page_results is None: last_page_results = []

  # Begin to retrieve the next page.
  if more:
    page_future = query.fetch_page_async(
        page_size, start_cursor=cursor, **query_options)

  # Run callback on each result.
  for result in last_page_results:
    callback(result, *extra_args, **extra_kwargs)

  # Wait for the next page to be retrieved.
  if more:
    results, cursor, more = page_future.get_result()
    queue_results = map(pre_queue_callback, results)
    # Defer task for next page.
    deferred.defer(
        _QueuedPaginatedApply, query, callback, extra_args, extra_kwargs,
        pre_queue_callback, page_size, queue, last_page_results=queue_results,
        cursor=cursor, more=more, _queue=queue, **query_options)


def QueuedPaginatedBatchApply(
    query, callback, extra_args=None, extra_kwargs=None,
    pre_queue_callback=None, page_size=_BATCH_SIZE,
    queue=constants.TASK_QUEUE.DEFAULT, **query_options):
  """Applies a callback to all results of a query using a task queue."""
  # Call the implementation function.
  deferred.defer(
      _QueuedPaginatedBatchApply, query, callback, extra_args, extra_kwargs,
      pre_queue_callback, page_size, queue, _queue=queue, **query_options)


def _QueuedPaginatedBatchApply(
    query, callback, extra_args, extra_kwargs, pre_queue_callback, page_size,
    queue, last_page_results=None, more=True, cursor=None, **query_options):
  """Implementation function for QueuedPaginatedBatchApply."""
  if extra_args is None: extra_args = []
  if extra_kwargs is None: extra_kwargs = {}
  if last_page_results is None: last_page_results = []

  # Begin to retrieve the next page.
  if more:
    page_future = query.fetch_page_async(
        page_size, start_cursor=cursor, **query_options)

  # Run callback on the list of results.
  if last_page_results:
    callback(last_page_results, *extra_args, **extra_kwargs)

  # Wait for the next page to be retrieved.
  if more:
    results, cursor, more = page_future.get_result()
    queue_results = map(pre_queue_callback, results)
    # Defer task for next page.
    deferred.defer(
        _QueuedPaginatedBatchApply, query, callback, extra_args, extra_kwargs,
        pre_queue_callback, page_size, queue, last_page_results=queue_results,
        cursor=cursor, more=more, _queue=queue, **query_options)
