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

"""Taskqueue utility methods."""

import collections
import functools
import logging
import pickle

from google.appengine.api import taskqueue

from google.appengine.ext import deferred
from google.appengine.ext import ndb

from upvote.shared import constants

_DEFER_KWARGS = (
    '_countdown', '_eta', '_name', '_target', '_retry_options', '_url',
    '_transactional', '_headers', '_queue')


def QueueSize(queue=constants.TASK_QUEUE.DEFAULT, deadline=10):
  queue = taskqueue.Queue(name=queue)
  queue_stats = queue.fetch_statistics(deadline=deadline)
  return queue_stats.tasks


def CappedDefer(
    callable_obj, max_size, queue=constants.TASK_QUEUE.DEFAULT, *args,
    **kwargs):
  can_defer = QueueSize(queue=queue) < max_size
  if can_defer:
    deferred.defer(callable_obj, _queue=queue, *args, **kwargs)
  return can_defer


def _IndirectDefer(*payloads):
  """Run a group of serialized tasks.

  If a single task fails, the exception will be logged and task execution will
  continue.

  Args:
    *payloads: Serialized blobs created using deferred.serialize.
  """
  for payload in payloads:
    try:
      deferred.run(payload)
    except Exception:  # pylint: disable=broad-except
      _, args, kwargs = pickle.loads(payload)
      logging.exception(
          'Indirect defer failed (args=%s, kwargs=%s)', args, kwargs)


def GroupTransactionalDefers(func):
  """Decorator that groups transactional defers into a single task.

  This is necessary because of the Taskqueue API's limit of 5 transactional
  defers per transaction.

  This wrapper intercepts all transactional deferred.defer calls, groups them by
  queue, and, just before the transaction is committed, creates one
  transactional defer task per queue.

  NOTE: This decorator MUST be placed below/inside of ndb.transactional
  decorators on the decorated function:
  YES:
    @ndb.transactional
    @GroupTransactionalDefers
    def myfunc(): pass
  NO:
    @GroupTransactionalDefers
    @ndb.transactional
    def myfunc(): pass

  Args:
    func: Function in which deferred will be wrapped.

  Returns:
    If non-transactional, the normal Task object.
    Else, None. (Transactional tasks are created transparently at the end of the
    decorated function's execution.)
  """
  old_defer = deferred.defer

  def GroupingDefer(payloads, *args, **kwargs):
    """Alternative deferred.defer() method that groups transactional defers."""
    is_transactional = kwargs.pop('_transactional', False)
    if not is_transactional:
      return old_defer(*args, **kwargs)

    call_kwargs = {
        k: v for k, v in kwargs.iteritems() if k not in _DEFER_KWARGS}
    task_kwargs = {k: v for k, v in kwargs.iteritems() if k in _DEFER_KWARGS}
    call_payload = deferred.serialize(*args, **call_kwargs)
    payload = deferred.serialize(
        old_defer, deferred.run, call_payload, **task_kwargs)
    queue_name = kwargs.get('_queue', constants.TASK_QUEUE.DEFAULT)
    payloads[queue_name].append(payload)
    return

  @functools.wraps(func)
  def WrappedFunc(*args, **kwargs):
    """Function wrapper to group transactional defers into single tasks."""
    payloads = collections.defaultdict(list)
    deferred.defer = functools.partial(GroupingDefer, payloads)
    try:
      assert not payloads, (
          'There are non-zero pickled payloads, and the decorated function has '
          'not been run yet. Something is very wrong.')
      result = func(*args, **kwargs)
      assert len(payloads) <= 5, (
          '%s taskqueues used in a transaction (max=5)' % len(payloads))
      assert ndb.in_transaction(), (
          'Transactional defers not permitted outside transactions '
          '(Ensure that this decorator is below/inside any '
          'transactional decorators.)')

      for queue, payload_list in payloads.iteritems():
        old_defer(
            _IndirectDefer, *payload_list, _queue=queue, _transactional=True)

      return result
    finally:
      deferred.defer = old_defer

  return WrappedFunc
