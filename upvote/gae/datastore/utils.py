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

"""Module containing Datstore-related utilities."""

import contextlib
import functools
import itertools

from google.appengine.ext import deferred
from google.appengine.ext import ndb
from google.appengine.ext.ndb import polymodel

from upvote.shared import constants


_BATCH_SIZE = 2000
_SMALL_BATCH_SIZE = 500


class Error(Exception):
  """Base error for the ndb utils module."""


class PropertyError(Exception):
  """Indicates an error with the provided properties."""


def CopyEntity(entity, new_key=None, new_parent=None, **updated_properties):
  """Create a new entity based on `entity`.

  If no `new_key` or 'id' property is provided, the returned entity's id will be
  set to None and will be generated when the entity is put into the datastore.

  Args:
    entity: ndb.Model, The basis for the copied entity. All fields and keys will
        be the same as those on `entity` unless overridden.
    new_key: ndb.Key, If provided, the key of the returned copy.
    new_parent: ndb.Key, If provided, the parent key of the returned copy.
    **updated_properties: The name-value mappings of properties to override on
        `entity`.

  Returns:
    ndb.Model, the new entity.

  Raises:
    PropertyError: An invalid property was provided in `updated_properties`.
    datastore_errors.BadArgumentError: All datastore-related errors including
        when `new_key` was provided along with either `new_parent` or an 'id'
        entry in `updated_properties`.
  """
  entity_values = entity._values.copy()  # pylint: disable=protected-access
  entity_properties = entity._properties  # pylint: disable=protected-access
  model = entity.__class__  # pylint: disable=protected-access

  # PolyModels have a 'class' attribute which is not a valid parameter for any
  # ndb Model constructor.
  if isinstance(entity, polymodel.PolyModel):
    # 'class' will not be set if the entity has not been stored.
    if 'class' in entity_values:
      del entity_values['class']

  # Filter out ComputedProperties and properties on the instance that no longer
  # appear on the Model. Neither of these can be passed to the constructor.
  entity_values = {
      prop_name: value
      for prop_name, value in entity_values.iteritems()
      if prop_name in model._properties and  # pylint: disable=protected-access
      not isinstance(entity_properties[prop_name], ndb.ComputedProperty)}

  # Check updated_properties for invalid properties
  for property_name in updated_properties:
    prop = entity_properties.get(property_name, None)
    if not prop and property_name != 'id':
      raise PropertyError(
          'Property "%s" cannot be set: Not found on model %s' % (
              property_name, type(entity).__name__))
    elif getattr(prop, '_auto_now', None):
      # DateTimeProperties marked with auto_now cannot be overridden. Without
      # this error, the operation would fail silently upon datastore insertion.
      raise PropertyError(
          'Property "%s" of type %s cannot be set: auto_now is True' % (
              property_name, type(prop).__name__))
    elif isinstance(prop, ndb.ComputedProperty):
      # ComputedProperties are read-only.
      raise PropertyError(
          'Property "%s" of type %s cannot be set: read-only' % (
              property_name, type(prop).__name__))

  entity_values.update(updated_properties)
  return model(key=new_key, parent=new_parent, **entity_values)


def DeleteProperty(entity, property_name):
  """Delete a property from an ndb entity.

  This function will not only delete the value of the property, but also the
  property object itself. After this function call, there will be no trace of
  the specified property on the entity.

  This can be useful for removing deprecated data on entities whose schemas have
  changed.

  NOTE: This function does not save the changes made to the provided entity. An
  additional put is required to save these changes.

  Args:
    entity: ndb.Model, The entity from which the property will be deleted.
    property_name: str, The name of the property to be deleted.
  """
  if property_name in entity._properties:  # pylint: disable=protected-access
    # NOTE: If the _properties dict is not cloned prior to deletion,
    # the entire Model class (and any future entities created from same) will
    # have the property deleted.
    # See SO discussion: http://stackoverflow.com/a/12701172/862857
    entity._clone_properties()  # pylint: disable=protected-access
    del entity._properties[property_name]  # pylint: disable=protected-access
  DeletePropertyValue(entity, property_name)


def DeletePropertyValue(entity, property_name):
  """Delete a property's value from an ndb entity.

  NOTE: This function does not save the changes made to the provided entity. An
  additional put is required to save these changes.

  Args:
    entity: ndb.Model, The entity from which the property value will be removed.
    property_name: str, The name of the property whose value will be removed.
  """
  if property_name in entity._values:  # pylint: disable=protected-access
    del entity._values[property_name]  # pylint: disable=protected-access


def HasProperty(entity, property_name):
  """Returns whether `entity` has a property by the provided name."""
  return property_name in entity._properties  # pylint: disable=protected-access


def HasValue(entity, property_name):
  """Returns whether `entity` has a property value with the provided name."""
  return property_name in entity._values  # pylint: disable=protected-access


def GetLocalComputedPropertyValue(entity, computed_property_name):
  """Return the local value of a ComputedProperty instead of re-computing.

  Args:
    entity: ndb.Model, The entity from which the ComputedProperty will be read.
    computed_property_name: str, The name of the ComputedProperty whose value
        will be read.

  Returns:
    The local value of the property.

  Raises:
    PropertyError: The property was not found or was not a ComputedProperty.
  """
  computed_property = entity._properties.get(computed_property_name, None)  # pylint: disable=protected-access
  if not computed_property:
    raise PropertyError('Property %s not found' % computed_property_name)
  elif not isinstance(computed_property, ndb.ComputedProperty):
    raise PropertyError(
        'Property %s is of type %s. Expected ComputedProperty.' % (
            computed_property_name, type(entity).__name__))
  return super(  # pylint: disable=protected-access
      ndb.ComputedProperty, computed_property)._get_value(entity)


@ndb.transactional
def PutMultiInTransaction(entities, async_=False):
  put_func = ndb.put_multi_async if async_ else ndb.put_multi
  put_func(entities)


def KeyHasAncestor(key, ancestor):
  """Return whether `ancestor` is an ancestor of key.

  An ancestor is defined as a key whose chain of (kind, value) pairs appears as
  a distinct prefix to another key's (kind, value) chain. For example:

    Key('Foo', 'id1') is an ancestor of Key('Foo', 'id1', 'Bar', 'id2')
    However, Key('Foo', 'id1') is not an ancestor of Key('Foo', 'id1')

  Args:
    key: ndb.Key, The key whose ancestry is being tested.
    ancestor: ndb.Key, The key being tested for the ancestor of `key`.

  Returns:
    bool, Whether `ancestor` is an ancestor of `key`.
  """
  key_ancestor = key.parent()
  while key_ancestor:
    if key_ancestor == ancestor:
      return True
    key_ancestor = key_ancestor.parent()
  return False


def ConcatenateKeys(*keys):
  """Return a key that is a concatenation of the keys in `keys`.

  Each Key's kind-value pairs are concatenated in root-to-leaf order.
  For example:

    Key('A', 1, 'B', 2) + Key('C', 3) = Key('A', 1, 'B', 2, 'C', 3)

  Args:
    *keys: iterable of ndb.Key, The keys to be concatenated.

  Returns:
    ndb.Key, If `keys` has elements, a single key representing the concatenation
        of the keys in the iterable.
    None, If `keys` is empty, None is returned.
  """
  if not keys:
    return None
  pairs = itertools.chain.from_iterable(key.pairs() for key in keys)
  return ndb.Key(pairs=pairs)


def GetKeyFromUrlsafe(urlsafe_key):
  """Return the key represented by the `urlsafe_key` string.

  This wrapper exists because of an open issue regarding inconsistent errors.
  See https://github.com/googlecloudplatform/datastore-ndb-python/issues/143

  Args:
    urlsafe_key: str, A url-safe string representation of an ndb.Key

  Returns:
    If the key string is a valid ndb.Key, return this ndb.Key.
    If construction fails, return None.
  """
  try:
    return ndb.Key(urlsafe=urlsafe_key)
  except:  # pylint:disable=bare-except
    return


@contextlib.contextmanager
def NdbContext(ctx):
  saved = ndb.get_context()
  ndb.set_context(ctx)
  yield
  ndb.set_context(saved)


def _FutureFactory(future_cls, *args, **kwargs):
  """Create a Future object."""

  # NOTE: Futures do not execute callbacks from within the transaction
  # scope that they were created in. Since we rely on this behavior in some
  # places, we wrap all manually-created Futures to achieve this behavior.
  ctx = ndb.get_context()

  class _TxnPreservingFuture(future_cls):
    """Executes the Future's callbacks inside the current txn."""

    def add_callback(self, callback, *args, **kwds):
      @functools.wraps(callback)
      def _Wrapped(*inner_args, **inner_kwargs):
        with NdbContext(ctx):
          callback(*inner_args, **inner_kwargs)
      return super(
          _TxnPreservingFuture, self).add_callback(_Wrapped, *args, **kwds)

    def add_immediate_callback(self, callback, *args, **kwds):
      @functools.wraps(callback)
      def _Wrapped(*inner_args, **inner_kwargs):
        with NdbContext(ctx):
          callback(*inner_args, **inner_kwargs)
      return super(
          _TxnPreservingFuture, self).add_immediate_callback(
              _Wrapped, *args, **kwds)

  return _TxnPreservingFuture(*args, **kwargs)


def GetNoOpFuture(result=None):
  """Return an ndb.Future whose result is None."""
  future = _FutureFactory(ndb.Future)
  future.set_result(result)
  return future


def GetMultiFuture(futures):
  """Constructs a ChainingMultiFuture object with `futures` as dependents.

  This is essentially a "join" on the provided futures.

  Args:
    futures: iterable of ndb.Futures, The futures to be joined.

  Returns:
    An ndb.MultiFuture instance that resolves when all provided `futures`
    resolve.
  """
  mf = _FutureFactory(ndb.MultiFuture)
  for future in futures:
    mf.add_dependent(future)
  mf.complete()
  return mf


class ChainingMultiFuture(ndb.MultiFuture):
  """A MultiFuture which coalesces its list of results into a single list."""

  def set_result(self, result):
    result = list(itertools.chain.from_iterable(result))
    super(ndb.MultiFuture, self).set_result(result)


def GetChainingMultiFuture(futures):
  """Constructs a ChainingMultiFuture object with `futures` as dependents."""
  mf = _FutureFactory(ChainingMultiFuture)
  for future in futures:
    mf.add_dependent(future)
  mf.complete()
  return mf


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
