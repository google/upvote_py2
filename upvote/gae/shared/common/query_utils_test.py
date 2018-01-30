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

"""Tests for query_utils."""

import itertools
import math
import operator

import mock

from google.appengine.ext import ndb

from absl.testing import absltest
from upvote.gae.shared.common import basetest
from upvote.gae.shared.common import query_utils
from upvote.shared import constants


class TestModel(ndb.Model):
  foo = ndb.StringProperty()
  bar = ndb.IntegerProperty()


def CreateEntity(foo='foo', bar=0):
  entity = TestModel(foo=foo, bar=bar)
  entity.put()
  return entity


def CreateEntities(count, **kwargs):
  return [CreateEntity(**kwargs) for _ in xrange(count)]


_GLOBAL_CBK_MOCK = mock.MagicMock()


def CallMock(*args, **kwargs):
  _GLOBAL_CBK_MOCK(*args, **kwargs)


def GetKey(key):
  return key.get()


def ReturnFoo(entity):
  return entity.foo


def ReturnBar(entity):
  return entity.bar


class QueryUtilsTest(basetest.UpvoteTestCase):

  def setUp(self):
    super(QueryUtilsTest, self).setUp()

  def tearDown(self):
    super(QueryUtilsTest, self).tearDown()
    _GLOBAL_CBK_MOCK.reset_mock()

  def testPaginatedMap(self):
    CreateEntities(3)
    result = query_utils.PaginatedMap(TestModel.query(), ReturnFoo)
    self.assertEqual(3, len(result))
    self.assertEqual('foo', result[0])

  def testPaginatedMap_TwoPages(self):
    CreateEntities(3)
    cbk_mock = mock.MagicMock()

    result = query_utils.PaginatedMap(TestModel.query(), cbk_mock, page_size=2)
    self.assertEqual(3, len(result))
    self.assertEqual(3, cbk_mock.call_count)

  def testPaginatedMap_ThreePages(self):
    CreateEntities(3)
    cbk_mock = mock.MagicMock()

    result = query_utils.PaginatedMap(TestModel.query(), cbk_mock, page_size=1)
    self.assertEqual(3, len(result))
    self.assertEqual(3, cbk_mock.call_count)

  def testPaginatedMap_QueryOptions(self):
    CreateEntities(3)

    result = query_utils.PaginatedMap(TestModel.query(), GetKey, keys_only=True)

    self.assertEqual(3, len(result))
    self.assertTrue(all(isinstance(entity, TestModel) for entity in result))

  def testPaginatedMapReduce(self):
    CreateEntities(3)
    map_cbk_mock = mock.MagicMock()
    reduce_cbk_mock = mock.MagicMock()
    reduce_cbk_mock.return_value = None

    result = query_utils.PaginatedMapReduce(
        TestModel.query(), map_cbk_mock, reduce_cbk_mock, page_size=1)
    self.assertIsNone(result)
    self.assertEqual(3, map_cbk_mock.call_count)
    self.assertEqual(3, reduce_cbk_mock.call_count)

  def testPaginatedMapReduce_Initial(self):
    CreateEntities(3, bar=1)

    result = query_utils.PaginatedMapReduce(
        TestModel.query(), ReturnBar, operator.add, initial=5, page_size=1)
    self.assertEqual(5 + 3, result)

  def testPaginatedFetch(self):
    CreateEntities(3)
    result = query_utils.PaginatedFetch(TestModel.query(), page_size=2)
    map_result = query_utils.PaginatedMap(TestModel.query(), None, page_size=2)
    self.assertEqual(3, len(result))
    self.assertEqual(map_result, result)

  def testPaginate(self):

    page_size = 10
    for entity_count in xrange(50):

      # Create some number of entities.
      CreateEntities(entity_count)

      # Verify that we get the expected number of pages.
      pages = list(query_utils.Paginate(TestModel.query(), page_size=page_size))
      expected_page_count = int(math.ceil(float(entity_count) / page_size))
      self.assertEqual(expected_page_count, len(pages))

      # Verify that we get the expected number of entities.
      entities = list(itertools.chain(*pages))
      self.assertEqual(entity_count, len(entities))

      # Delete everything.
      for entity in entities:
        entity.key.delete()

  def testQueuedPaginatedApply(self):
    CreateEntities(3)
    query_utils.QueuedPaginatedApply(TestModel.query(), CallMock, page_size=1)

    for _ in xrange(4):
      self.assertTaskCount(constants.TASK_QUEUE.DEFAULT, 1)
      self.RunDeferredTasks()

    self.assertTaskCount(constants.TASK_QUEUE.DEFAULT, 0)

    self.assertEqual(3, _GLOBAL_CBK_MOCK.call_count)

  def testQueuedPaginatedApply_ExtraArgs(self):
    CreateEntities(3)
    query_utils.QueuedPaginatedApply(
        TestModel.query(), CallMock, extra_args=['a', 'b'],
        extra_kwargs={'c': 'c'})

    for _ in xrange(2):
      self.assertTaskCount(constants.TASK_QUEUE.DEFAULT, 1)
      self.RunDeferredTasks()

    self.assertTaskCount(constants.TASK_QUEUE.DEFAULT, 0)

    self.assertTrue(_GLOBAL_CBK_MOCK.called_with('foo', 'a', 'b', c='c'))

  def testQueuedPaginatedApply_Transform(self):
    CreateEntities(3)
    query_utils.QueuedPaginatedApply(
        TestModel.query(), CallMock, pre_queue_callback=ReturnFoo, page_size=1)

    for _ in xrange(4):
      self.assertTaskCount(constants.TASK_QUEUE.DEFAULT, 1)
      self.RunDeferredTasks()

    self.assertTaskCount(constants.TASK_QUEUE.DEFAULT, 0)

    self.assertTrue(_GLOBAL_CBK_MOCK.called_with('foo'))

  def testQueuedPaginatedApply_DifferentQueue(self):
    CreateEntities(3)
    query_utils.QueuedPaginatedApply(TestModel.query(), CallMock, queue='foo')

    for _ in xrange(2):
      self.assertTaskCount('foo', 1)
      self.assertTaskCount(constants.TASK_QUEUE.DEFAULT, 0)
      self.RunDeferredTasks('foo')

    self.assertTaskCount('foo', 0)

    self.assertEqual(3, _GLOBAL_CBK_MOCK.call_count)

  def testQueuedPaginatedApply_QueryOptions(self):
    entities = CreateEntities(3)
    query_utils.QueuedPaginatedApply(
        TestModel.query(), CallMock, keys_only=True)

    for _ in xrange(2):
      self.assertTaskCount(constants.TASK_QUEUE.DEFAULT, 1)
      self.RunDeferredTasks()

    self.assertTaskCount(constants.TASK_QUEUE.DEFAULT, 0)

    self.assertEqual(3, _GLOBAL_CBK_MOCK.call_count)
    self.assertTrue(_GLOBAL_CBK_MOCK.called_with(entities[0].key))

  def testQueuedPaginatedBatchApply(self):
    entities = CreateEntities(3)
    query_utils.QueuedPaginatedBatchApply(
        TestModel.query(), CallMock, page_size=2)

    for _ in xrange(3):
      self.assertTaskCount(constants.TASK_QUEUE.DEFAULT, 1)
      self.RunDeferredTasks()

    self.assertTaskCount(constants.TASK_QUEUE.DEFAULT, 0)

    self.assertTrue(_GLOBAL_CBK_MOCK.called_with(entities[:2]))
    self.assertTrue(_GLOBAL_CBK_MOCK.called_with(entities[2:]))
    self.assertEqual(2, _GLOBAL_CBK_MOCK.call_count)

  def testQueuedPaginatedBatchApply_ExtraArgs(self):
    entities = CreateEntities(1)
    query_utils.QueuedPaginatedBatchApply(
        TestModel.query(), CallMock, extra_args=['a', 'b'],
        extra_kwargs={'c': 'c'})

    for _ in xrange(2):
      self.assertTaskCount(constants.TASK_QUEUE.DEFAULT, 1)
      self.RunDeferredTasks()

    self.assertTaskCount(constants.TASK_QUEUE.DEFAULT, 0)

    self.assertTrue(_GLOBAL_CBK_MOCK.called_with(entities, 'a', 'b', c='c'))


if __name__ == '__main__':
  absltest.main()
