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

"""Unit tests for datastore_utils.py."""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

import datetime
import itertools
import math

import mock
from six.moves import range

from google.appengine.api import datastore_errors
from google.appengine.ext import ndb
from google.appengine.ext.ndb import polymodel
from upvote.gae.datastore import utils as datastore_utils
from upvote.gae.lib.testing import basetest
from upvote.shared import constants


class CopyEntityTest(basetest.UpvoteTestCase):

  def setUp(self):
    super(CopyEntityTest, self).setUp()

    class A(ndb.Model):
      a = ndb.StringProperty()

    self.default_model = A

  def testUpdateProperties(self):
    inst = self.default_model(a='abc')
    inst.put()

    new = datastore_utils.CopyEntity(inst, a='xyz')
    new.put()

    self.assertEqual('abc', inst.a)
    self.assertEqual('xyz', new.a)
    self.assertNotEqual(new.key, inst.key)

  def testFailToSet_AutoNowProperty(self):
    class A(ndb.Model):
      a = ndb.DateTimeProperty(auto_now=True)

    inst = A()
    inst.put()
    with self.assertRaises(datastore_utils.PropertyError):
      datastore_utils.CopyEntity(
          inst, a=datetime.datetime.utcnow())

  def testFailToSet_ComputedProperty(self):
    class A(ndb.Model):
      a = ndb.StringProperty()
      b = ndb.ComputedProperty(lambda self: self.a[0])

    inst = A(a='xyz')
    inst.put()

    self.assertEqual('x', inst.b)

    with self.assertRaises(datastore_utils.PropertyError):
      datastore_utils.CopyEntity(inst, b='a')

  def testModelWithComputedProperty(self):
    class A(ndb.Model):
      a = ndb.StringProperty()
      b = ndb.ComputedProperty(lambda self: self.a[0])

    inst = A(a='xyz')
    inst.put()

    self.assertEqual('x', inst.b)

    new = datastore_utils.CopyEntity(inst, a='abc')
    new.put()

    self.assertEqual('a', new.b)

  def testPolyModel(self):
    class A(datastore_utils.polymodel.PolyModel):
      a = ndb.StringProperty()

    class B(A):
      pass

    inst = B(a='abc')
    inst.put()

    new = datastore_utils.CopyEntity(inst, a='xyz')
    new.put()

    self.assertEqual('xyz', new.a)
    self.assertIsInstance(new, B)

  def testPolyModel_NoClass(self):
    class A(datastore_utils.polymodel.PolyModel):
      a = ndb.StringProperty()

    class B(A):
      pass

    inst = B(a='abc')
    a_copy = datastore_utils.CopyEntity(inst, a='xyz')
    a_copy.put()
    inst.put()

    self.assertEqual('xyz', a_copy.a)
    self.assertEqual('abc', inst.a)

  def testNewId(self):
    inst = self.default_model(a='abc')
    inst.put()

    new = datastore_utils.CopyEntity(inst, id='an_id')
    new.put()

    self.assertEqual('abc', new.a)
    self.assertEqual('an_id', new.key.id())

  def testNewIdWithParent(self):
    inst = self.default_model(a='abc')
    inst.put()

    parent = ndb.Key('C', 'c', 'B', 'b')
    expected = ndb.Key('C', 'c', 'B', 'b', 'A', 'an_id')
    new = datastore_utils.CopyEntity(
        inst, new_parent=parent, id='an_id')
    new.put()

    self.assertEqual(expected, new.key)

  def testIdWithKey(self):
    inst = self.default_model(a='abc')
    inst.put()

    with self.assertRaises(datastore_errors.BadArgumentError):
      datastore_utils.CopyEntity(
          inst, new_key=ndb.Key('A', 'a_key'), id='an_id')

  def testParentWithKey(self):
    inst = self.default_model(a='abc')
    inst.put()

    parent = ndb.Key('C', 'c', 'B', 'b')
    with self.assertRaises(datastore_errors.BadArgumentError):
      datastore_utils.CopyEntity(
          inst, new_key=ndb.Key('A', 'a_key'), new_parent=parent)

  def testUnknownProperty(self):
    inst = self.default_model(a='abc')
    inst.put()

    with self.assertRaises(datastore_utils.PropertyError):
      datastore_utils.CopyEntity(inst, not_a_property='a')

  def testDeletedProperty(self):
    inst = self.default_model(a='abc')
    inst.put()

    class A(ndb.Model):  # pylint: disable=unused-variable
      b = ndb.StringProperty()

    inst = inst.key.get(use_cache=False)

    copy = datastore_utils.CopyEntity(inst)
    self.assertFalse(hasattr(copy, 'a'))


class DeletePropertyTest(basetest.UpvoteTestCase):

  def setUp(self):
    super(DeletePropertyTest, self).setUp()

  def testSameSchema(self):

    # Initial schema
    class A(ndb.Model):
      a = ndb.StringProperty()
      b = ndb.StringProperty()

    # Create an entity using the initial schema
    inst = A(a='abc', b='def')
    inst.put()

    self.assertIsNotNone(inst.b)

    # Delete the property and save the entity
    datastore_utils.DeleteProperty(inst, 'b')
    inst.put()
    inst = A.get_by_id(inst.key.id())

    # The old data is gone :)
    self.assertIsNone(inst.b)

  def testSameSchema_DoesntDeleteProperty(self):

    # Initial schema
    class A(ndb.Model):
      a = ndb.StringProperty()
      b = ndb.StringProperty()

    # Create an entity using the initial schema
    inst = A(a='abc', b='def')
    inst.put()

    # Delete the property and save the entity
    datastore_utils.DeleteProperty(inst, 'b')
    inst.put()

    # Create a new instance and verify that the 'b' hasn't disappeared
    new = A(a='abc', b='def')
    new.put()
    self.assertTrue(datastore_utils.HasProperty(new, 'b'))

  def testSameSchema_RepeatedProperty(self):

    # Initial schema
    class A(ndb.Model):
      a = ndb.StringProperty()
      b = ndb.StringProperty(repeated=True)

    # Create an entity using the initial schema
    inst = A(a='abc', b=['def'])
    inst.put()

    self.assertIsNotNone(inst.b)

    # Delete the property and save the entity
    datastore_utils.DeleteProperty(inst, 'b')
    inst.put()
    inst = A.get_by_id(inst.key.id())

    # The old data is...kinda gone :|
    self.assertEqual([], inst.b)

  def testChangeSchema(self):

    # Initial schema
    class A(ndb.Model):
      a = ndb.StringProperty()
      b = ndb.StringProperty()

    # Create an entity using the initial schema
    inst = A(a='abc', b='def')
    inst.put()

    # Revised schema
    class A(ndb.Model):  # pylint: disable=function-redefined
      a = ndb.StringProperty()

    # Retrieve and save the old instance
    inst = A.get_by_id(inst.key.id())
    inst.put()

    # The old data is still there :(
    self.assertIsNotNone(inst.b)

    # Delete the property and save the entity
    datastore_utils.DeleteProperty(inst, 'b')
    inst.put()
    inst = A.get_by_id(inst.key.id())

    # The old data is gone :)
    self.assertIsNone(inst.b)

  def testChangeSchema_RequiredField(self):

    # Initial schema but this time with a required property
    class A(ndb.Model):
      a = ndb.StringProperty()
      b = ndb.StringProperty(required=True)

    # Create an entity using the initial schema
    inst = A(a='abc', b='def')
    inst.put()

    # Revised schema without the required property
    class A(ndb.Model):  # pylint: disable=function-redefined
      a = ndb.StringProperty()

    # Retrieve and save the old instance
    inst = A.get_by_id(inst.key.id())
    inst.put()

    # The old data is still there :(
    self.assertIsNotNone(inst.b)

    # Delete the property and save the entity
    datastore_utils.DeleteProperty(inst, 'b')
    inst.put()
    inst = A.get_by_id(inst.key.id())

    # The old data is gone :)
    self.assertIsNone(inst.b)

  def testUnknownProperty(self):

    class A(ndb.Model):
      a = ndb.StringProperty()

    inst = A(a='abc')
    inst.put()

    datastore_utils.DeleteProperty(inst, 'b')
    inst.put()
    inst = A.get_by_id(inst.key.id())

    self.assertIsNotNone(inst.a)

  def testChangeSchema_PolyModel(self):

    # Initial schema
    class Base(polymodel.PolyModel):
      a = ndb.StringProperty()
      b = ndb.StringProperty(required=True)

    class A(Base):
      pass

    # Create an entity using the initial schema
    inst = A(a='abc', b='def')
    inst.put()

    # Revised schema
    class Base(polymodel.PolyModel):  # pylint: disable=function-redefined
      a = ndb.StringProperty()

    class A(Base):  # pylint: disable=function-redefined
      pass

    # Retrieve and save the old instance
    inst = A.get_by_id(inst.key.id())
    inst.put()

    # The old data is still there :(
    self.assertIsNotNone(inst.b)

    # Delete the property and save the entity
    datastore_utils.DeleteProperty(inst, 'b')
    inst.put()
    inst = A.get_by_id(inst.key.id())

    # The old data is gone :)
    self.assertIsNone(inst.b)


class DeletePropertyValueTest(basetest.UpvoteTestCase):

  def testDeleteValue(self):

    # Initial schema
    class A(ndb.Model):
      a = ndb.StringProperty()
      b = ndb.StringProperty()

    # Create an entity using the initial schema
    inst = A(a='abc', b='def')
    inst.put()

    self.assertIsNotNone(inst.b)

    # Delete the property and save the entity
    datastore_utils.DeletePropertyValue(inst, 'b')
    inst.put()
    inst = A.get_by_id(inst.key.id())

    # The old data is gone :)
    self.assertIsNone(inst.b)

  def testDatetimeAutoNowAdd(self):

    # Initial schema
    class A(ndb.Model):
      a = ndb.StringProperty()
      b = ndb.DateTimeProperty(auto_now_add=True)

    # Create an entity using the initial schema
    inst = A(a='abc')
    inst.put()

    # Delete the property and save the entity
    datastore_utils.DeletePropertyValue(inst, 'b')
    inst.put()

    self.assertTrue(datastore_utils.HasProperty(inst, 'b'))
    self.assertIsNotNone(inst.b)

  def testRepeatedProperty(self):

    # Initial schema
    class A(ndb.Model):
      a = ndb.StringProperty()
      b = ndb.StringProperty(repeated=True)

    # Create an entity using the initial schema
    inst = A(a='abc', b=['def'])
    inst.put()

    self.assertIsNotNone(inst.b)

    # Delete the property and save the entity
    datastore_utils.DeletePropertyValue(inst, 'b')
    inst.put()
    inst = A.get_by_id(inst.key.id())

    # The old data is gone
    self.assertEqual([], inst.b)

  def testRequiredField(self):

    # Initial schema but this time with a required property
    class A(ndb.Model):
      a = ndb.StringProperty()
      b = ndb.StringProperty(required=True)

    # Create an entity using the initial schema
    inst = A(a='abc', b='def')
    inst.put()

    # Delete the property and save the entity
    datastore_utils.DeletePropertyValue(inst, 'b')
    # Property required but no longer has a value.
    with self.assertRaises(Exception):
      inst.put()

  def testUnknownProperty(self):

    class A(ndb.Model):
      a = ndb.StringProperty()

    inst = A(a='abc')
    inst.put()

    datastore_utils.DeletePropertyValue(inst, 'b')
    inst.put()
    inst = A.get_by_id(inst.key.id())

    self.assertIsNotNone(inst.a)


class HasValueTest(basetest.UpvoteTestCase):

  def testHasValue(self):

    class Foo(ndb.Model):
      a = ndb.ComputedProperty(lambda self: 'a')
      b = ndb.StringProperty()

    foo = Foo()
    self.assertFalse(datastore_utils.HasValue(foo, 'a'))
    self.assertFalse(datastore_utils.HasValue(foo, 'b'))

    foo.b = 'b'
    self.assertFalse(datastore_utils.HasValue(foo, 'a'))
    self.assertTrue(datastore_utils.HasValue(foo, 'b'))

    foo.put()
    self.assertTrue(datastore_utils.HasValue(foo, 'a'))
    self.assertTrue(datastore_utils.HasValue(foo, 'b'))


class GetLocalComputedPropertyValueTest(basetest.UpvoteTestCase):

  def setUp(self):
    super(GetLocalComputedPropertyValueTest, self).setUp()

    class A(ndb.Model):
      a = ndb.StringProperty()
      b = ndb.ComputedProperty(lambda self: self.a[0])

    self.inst = A(a='xyz')

  def testNormal(self):
    self.assertIsNone(
        datastore_utils.GetLocalComputedPropertyValue(self.inst, 'b'))
    self.inst.put()
    self.assertEqual(
        'x', datastore_utils.GetLocalComputedPropertyValue(self.inst, 'b'))
    self.inst.a = 'cdg'
    self.assertEqual(
        'x', datastore_utils.GetLocalComputedPropertyValue(self.inst, 'b'))
    self.inst.put()
    self.assertEqual(
        'c', datastore_utils.GetLocalComputedPropertyValue(self.inst, 'b'))

  def testUnknownProperty(self):
    with self.assertRaises(datastore_utils.PropertyError):
      datastore_utils.GetLocalComputedPropertyValue(
          self.inst, 'NotARealProperty')

  def testNotComputedProperty(self):
    with self.assertRaises(datastore_utils.PropertyError):
      datastore_utils.GetLocalComputedPropertyValue(self.inst, 'a')


class KeyHasAncestorTest(basetest.UpvoteTestCase):

  def testKeyHasAncestor(self):
    self.assertFalse(
        datastore_utils.KeyHasAncestor(ndb.Key('A', 1), ndb.Key('A', 1)))
    self.assertTrue(
        datastore_utils.KeyHasAncestor(
            ndb.Key('A', 1, 'B', 2), ndb.Key('A', 1)))
    self.assertFalse(
        datastore_utils.KeyHasAncestor(
            ndb.Key('A', 1, 'B', 2), ndb.Key('A', 2)))
    self.assertFalse(
        datastore_utils.KeyHasAncestor(
            ndb.Key('A', 1, 'B', 2), ndb.Key('A', 1, 'B', 2)))
    self.assertTrue(
        datastore_utils.KeyHasAncestor(
            ndb.Key('A', 1, 'B', 2, 'C', 3), ndb.Key('A', 1, 'B', 2)))


class ConcatenateKeysTest(basetest.UpvoteTestCase):

  def testSuccess(self):
    keys = [ndb.Key('A', 1, 'B', 2), ndb.Key('C', 3)]
    self.assertEqual(
        ndb.Key('A', 1, 'B', 2, 'C', 3), datastore_utils.ConcatenateKeys(*keys))

  def testEmpty(self):
    self.assertIsNone(datastore_utils.ConcatenateKeys())


class GetKeyFromUrlsafeTest(basetest.UpvoteTestCase):

  def testSuccess(self):
    key = ndb.Key('A', 'a', 'B', 'b')
    self.assertEqual(key, datastore_utils.GetKeyFromUrlsafe(key.urlsafe()))

  def testError(self):
    self.assertIsNone(
        datastore_utils.GetKeyFromUrlsafe('not a real ndb key string'))


class FutureFactoryTest(basetest.UpvoteTestCase):

  def testInTxn(self):
    def AssertInTxn():
      self.assertTrue(ndb.in_transaction())

    def RunAssert():
      fut = datastore_utils.GetNoOpFuture()
      fut.add_callback(AssertInTxn)
      fut.add_immediate_callback(AssertInTxn)
      fut.get_result()

    ndb.transaction(RunAssert)


class GetNoOpFutureTest(basetest.UpvoteTestCase):

  def testNone(self):
    future = datastore_utils.GetNoOpFuture()
    self.assertTrue(future.done())
    self.assertIsNone(future.get_result())

  def testResult(self):
    result = 'foobar'
    future = datastore_utils.GetNoOpFuture(result)
    self.assertTrue(future.done())
    self.assertEqual(result, future.get_result())


class GetMultiFutureTest(basetest.UpvoteTestCase):

  def testNoInput(self):
    mf = datastore_utils.GetMultiFuture([])
    self.assertTrue(mf.done())

  def testSingleFuture(self):
    f = ndb.Future()
    mf = datastore_utils.GetMultiFuture([f])

    self.assertFalse(f.done())
    self.assertFalse(mf.done())

    f.set_result(None)

    self.assertTrue(f.done())
    self.assertFalse(mf.done())

    # Event loop must run for the MultiFuture to be marked as done.
    mf.wait()

    self.assertTrue(mf.done())

  def testManyFutures(self):
    futures = [ndb.Future() for _ in range(3)]
    mf = datastore_utils.GetMultiFuture(futures)

    self.assertFalse(any(f.done() for f in futures))
    self.assertFalse(mf.done())

    for f in futures:
      f.set_result(None)

    self.assertTrue(all(f.done() for f in futures))
    self.assertFalse(mf.done())

    # Event loop must run for the MultiFuture to be marked as done.
    mf.wait()

    self.assertTrue(mf.done())

  def testCantModifyResult(self):
    f = ndb.Future()
    mf = datastore_utils.GetMultiFuture([f])
    with self.assertRaises(RuntimeError):
      mf.add_dependent(ndb.Future())


class TestModel(ndb.Model):
  foo = ndb.StringProperty()
  bar = ndb.IntegerProperty()


def CreateEntity(foo='foo', bar=0):
  entity = TestModel(foo=foo, bar=bar)
  entity.put()
  return entity


def CreateEntities(count, **kwargs):
  return [CreateEntity(**kwargs) for _ in range(count)]


_GLOBAL_CBK_MOCK = mock.MagicMock()


def CallMock(*args, **kwargs):
  _GLOBAL_CBK_MOCK(*args, **kwargs)


def GetKey(key):
  return key.get()


def ReturnFoo(entity):
  return entity.foo


def ReturnBar(entity):
  return entity.bar


class PaginateTest(basetest.UpvoteTestCase):

  def testSuccess(self):

    page_size = 10
    for entity_count in range(50):

      # Create some number of entities.
      CreateEntities(entity_count)

      # Verify that we get the expected number of pages.
      pages = list(
          datastore_utils.Paginate(TestModel.query(), page_size=page_size))
      expected_page_count = int(math.ceil(float(entity_count) / page_size))
      self.assertLen(pages, expected_page_count)

      # Verify that we get the expected number of entities.
      entities = list(itertools.chain(*pages))
      self.assertLen(entities, entity_count)

      # Delete everything.
      for entity in entities:
        entity.key.delete()


class QueuedPaginatedBatchApply(basetest.UpvoteTestCase):

  def tearDown(self):
    super(QueuedPaginatedBatchApply, self).tearDown()
    _GLOBAL_CBK_MOCK.reset_mock()

  def testSuccess(self):
    entities = CreateEntities(3)
    datastore_utils.QueuedPaginatedBatchApply(
        TestModel.query(), CallMock, page_size=2)

    for _ in range(3):
      self.assertTaskCount(constants.TASK_QUEUE.DEFAULT, 1)
      self.RunDeferredTasks()

    self.assertTaskCount(constants.TASK_QUEUE.DEFAULT, 0)

    self.assertTrue(_GLOBAL_CBK_MOCK.called_with(entities[:2]))
    self.assertTrue(_GLOBAL_CBK_MOCK.called_with(entities[2:]))
    self.assertEqual(2, _GLOBAL_CBK_MOCK.call_count)

  def testExtraArgs(self):
    entities = CreateEntities(1)
    datastore_utils.QueuedPaginatedBatchApply(
        TestModel.query(), CallMock, extra_args=['a', 'b'],
        extra_kwargs={'c': 'c'})

    for _ in range(2):
      self.assertTaskCount(constants.TASK_QUEUE.DEFAULT, 1)
      self.RunDeferredTasks()

    self.assertTaskCount(constants.TASK_QUEUE.DEFAULT, 0)

    self.assertTrue(_GLOBAL_CBK_MOCK.called_with(entities, 'a', 'b', c='c'))


if __name__ == '__main__':
  basetest.main()
