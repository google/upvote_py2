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
import types

from google.appengine.api import taskqueue

from google.appengine.ext import deferred
from google.appengine.ext import ndb

from upvote.gae.datastore import utils
from upvote.shared import constants


_COMMIT_KEY = 'DO-COMMIT'
_DELAYED_TASKS = {}


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


class _TransactionalGroupingTask(taskqueue.Task):
  """Task which conditionally delays enqueuing when grouping is enabled."""

  def add_async(
      self, queue_name=constants.TASK_QUEUE.DEFAULT, transactional=False):
    ctx_id = id(ndb.get_context())

    force_commit = (_COMMIT_KEY in self.headers)
    grouping_enabled = (ctx_id in _DELAYED_TASKS)
    if transactional and grouping_enabled and not force_commit:
      _DELAYED_TASKS[ctx_id][queue_name].append(self)
      return utils.GetNoOpFuture()
    else:
      return self.add_async_forced(queue_name, transactional)

  def add_async_forced(self, *args, **kwargs):
    return super(_TransactionalGroupingTask, self).add_async(*args, **kwargs)


# Override the global Task implementation although we'll only be enabling our
# code paths when the grouping decorator is active.
taskqueue.Task = _TransactionalGroupingTask


def _IndirectTaskEnqueue(queue_name, *tasks):
  """Run a group of serialized tasks.

  If a single task fails, the exception will be logged and task execution will
  continue.

  Args:
    queue_name: Name of the queue to which the tasks should be added.
    *tasks: Serialized blobs created using deferred.serialize.
  """
  for task in tasks:
    try:
      task.add_async_forced(queue_name=queue_name).get_result()
    except Exception:  # pylint: disable=broad-except
      logging.exception('Indirect task execution failed: %r', task)


def GroupTransactionalTaskletDefers(func):
  """Decorator that groups transactional_tasklet defers into a single task.

  This is necessary because of the Taskqueue API's limit of 5 transactional
  defers per transaction.

  This wrapper intercepts all transactional deferred.defer calls, groups them by
  queue, and, just before the transaction is committed, creates one
  transactional defer task per queue.

  NOTE: This decorator MUST be placed below/inside of ndb.transactional_tasklet
  decorators on the decorated function:
  YES:
    @ndb.transactional_tasklet
    @GroupTransactionalTaskletDefers
    def myfunc(): pass
  NO:
    @GroupTransactionalTaskletDefers
    @ndb.transactional
    def myfunc(): pass

  Args:
    func: Function in which deferred will be wrapped.

  Returns:
    If non-transactional, the normal Task object.
    Else, None. (Transactional tasks are created transparently at the end of the
    decorated function's execution.)
  """

  @functools.wraps(func)
  def WrappedFunc(*args, **kwargs):
    """Function wrapper to group transactional defers into single tasks."""
    ctx_id = id(ndb.get_context())
    _DELAYED_TASKS.setdefault(ctx_id, collections.defaultdict(list))

    try:
      result = func(*args, **kwargs)

      stop_iter = None
      if isinstance(result, types.GeneratorType):
        # Emulate the NDB event loop.
        try:
          while True:
            response = result.send((yield result.next()))
            while isinstance(response, ndb.Future):
              response = result.send((yield response))
        except StopIteration as e:
          stop_iter = e
      else:
        ret = ndb.Future()
        ret.set_result(result)
        yield ret

      # Flush all pending async tasks.
      # NOTE: This isn't strictly speaking necessary but protects
      # against cases where the user forgets to yield or manually wait on all
      # async operations. These would normally get executed when the transaction
      # concludes but that will be after this defer decorator ends.
      ndb.get_context().flush().wait()

      task_maps = _DELAYED_TASKS[ctx_id]

      assert len(task_maps) <= 5, (
          '%s taskqueues used in a transaction (max=5)' % len(task_maps))
      assert ndb.in_transaction(), (
          'Transactional defer grouping is permitted outside a transaction. '
          '(Ensure that this decorator is below/inside any '
          'transactional decorators.)')

      for queue, task_list in task_maps.iteritems():
        deferred.defer(
            _IndirectTaskEnqueue, queue, *task_list, _queue=queue,
            _transactional=True, _headers={_COMMIT_KEY: True})

      if stop_iter is not None:
        raise stop_iter  # pylint: disable=raising-bad-type
    finally:
      _DELAYED_TASKS[ctx_id].clear()

  return WrappedFunc


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
  # Re-wrap the function to extract the return value from the generator
  # constructed by GroupTransactionalTaskletDefers.
  wrapped = GroupTransactionalTaskletDefers(func)

  @functools.wraps(func)
  def WrappedFunc(*args, **kwargs):
    """Function wrapper to group transactional defers into single tasks."""
    gen = wrapped(*args, **kwargs)
    result = gen.next()
    try:
      gen.next()
    except StopIteration:
      pass
    else:
      assert False, 'Bad generator state: Use GroupTransactionalTaskletDefers.'

    return result

  return WrappedFunc
