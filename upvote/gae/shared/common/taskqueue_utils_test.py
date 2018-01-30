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

"""Tests for taskqueue_utils."""

from google.appengine.api import taskqueue

from google.appengine.ext import deferred
from google.appengine.ext import ndb

from upvote.gae.shared.common import basetest
from upvote.gae.shared.common import taskqueue_utils
from upvote.shared import constants


class QueueSizeTest(basetest.UpvoteTestCase):

  def testSuccess(self):
    self.assertEqual(0, taskqueue_utils.QueueSize())
    expected_size = 10
    for _ in xrange(expected_size):
      deferred.defer(dir)
    self.assertEqual(expected_size, taskqueue_utils.QueueSize())


class CappedDeferTest(basetest.UpvoteTestCase):

  def testSuccess(self):

    max_size = 6
    total_size = 10

    expected_results = [True] * max_size + [False] * (total_size - max_size)
    actual_results = [
        taskqueue_utils.CappedDefer(dir, max_size) for _ in xrange(total_size)]

    self.assertEqual(expected_results, actual_results)


_DEFAULT = constants.TASK_QUEUE.DEFAULT
_METRICS = constants.TASK_QUEUE.METRICS


def _FreeFunction(a=0):
  return a + 1


class GroupTransactionalDefersTest(basetest.UpvoteTestCase):

  def testSuccess(self):
    @ndb.transactional
    @taskqueue_utils.GroupTransactionalDefers
    def _Foo():
      for i in xrange(6):
        deferred.defer(
            _FreeFunction, a=i, _queue=_METRICS, _transactional=True)

    _Foo()
    self.assertEqual(1, taskqueue_utils.QueueSize(_METRICS))
    self.RunDeferredTasks(_METRICS)
    self.assertEqual(6, taskqueue_utils.QueueSize(_METRICS))
    self.RunDeferredTasks(_METRICS)
    self.assertEqual(0, taskqueue_utils.QueueSize(_METRICS))

  def testSuccess_NonTransactional(self):
    @ndb.transactional
    @taskqueue_utils.GroupTransactionalDefers
    def _Foo():
      for i in xrange(6):
        deferred.defer(
            _FreeFunction, a=i, _queue=_METRICS, _transactional=True)
        # Add non-transactional deferred tasks, as well.
        deferred.defer(_FreeFunction, a=i, _queue=_METRICS)

    _Foo()

    # Ensure that non-transactional tasks weren't grouped while the
    # transactional tasks were.
    self.assertEqual(1 + 6, taskqueue_utils.QueueSize(_METRICS))
    self.RunDeferredTasks(_METRICS)
    self.assertEqual(6, taskqueue_utils.QueueSize(_METRICS))
    self.RunDeferredTasks(_METRICS)
    self.assertEqual(0, taskqueue_utils.QueueSize(_METRICS))

  def testSuccess_MultiQueue(self):
    @ndb.transactional
    @taskqueue_utils.GroupTransactionalDefers
    def _Foo():
      for i in xrange(6):
        deferred.defer(
            _FreeFunction, a=i, _queue=_DEFAULT, _transactional=True)
        deferred.defer(
            _FreeFunction, a=i, _queue=_METRICS, _transactional=True)

    _Foo()

    # Ensure that each queue's transactional tasks are processed separatedly.
    self.assertEqual(1, taskqueue_utils.QueueSize(_METRICS))
    self.assertEqual(1, taskqueue_utils.QueueSize(_DEFAULT))
    self.RunDeferredTasks(_METRICS)
    self.RunDeferredTasks(_DEFAULT)
    self.assertEqual(6, taskqueue_utils.QueueSize(_METRICS))
    self.assertEqual(6, taskqueue_utils.QueueSize(_DEFAULT))
    self.RunDeferredTasks(_METRICS)
    self.RunDeferredTasks(_DEFAULT)
    self.assertEqual(0, taskqueue_utils.QueueSize(_METRICS))
    self.assertEqual(0, taskqueue_utils.QueueSize(_DEFAULT))

  def testSuccess_DeferredRepairedOnExit(self):
    @ndb.transactional
    @taskqueue_utils.GroupTransactionalDefers
    def _Foo():
      deferred.defer(_FreeFunction, _queue=_DEFAULT, _transactional=True)
    _Foo()

    @ndb.transactional
    def _Bar():
      for _ in xrange(6):
        deferred.defer(_FreeFunction, _queue=_DEFAULT, _transactional=True)

    with self.assertRaises(taskqueue.DatastoreError):
      _Bar()

  def testSuccess_TxnFunction(self):
    @taskqueue_utils.GroupTransactionalDefers
    def _Foo():
      deferred.defer(_FreeFunction, _queue=_METRICS, _transactional=True)

    ndb.transaction(_Foo)

  def testSuccess_Tasklet(self):
    @ndb.transactional_tasklet
    @taskqueue_utils.GroupTransactionalDefers
    def _Foo():
      deferred.defer(_FreeFunction, _queue=_METRICS, _transactional=True)

    _Foo().get_result()

  def testNoLeftoverPayloads(self):

    @ndb.transactional
    @taskqueue_utils.GroupTransactionalDefers
    def _Foo():
      deferred.defer(_FreeFunction, _queue=_METRICS, _transactional=True)

    # Repeated calls to the decorated function shouldn't fail due to serialized
    # payloads being left over from previous calls.
    for _ in xrange(10):
      _Foo()

  def testBadDecoratorOrder(self):
    @taskqueue_utils.GroupTransactionalDefers
    @ndb.transactional
    def _Foo():
      deferred.defer(_FreeFunction, _queue=_METRICS, _transactional=True)

    with self.assertRaises(AssertionError):
      _Foo()


if __name__ == '__main__':
  basetest.main()
