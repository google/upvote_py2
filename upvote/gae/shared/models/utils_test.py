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

"""Tests for model utils."""

import datetime

from google.appengine.api import datastore_errors
from google.appengine.ext import ndb
from google.appengine.ext.ndb import polymodel

from common.testing import basetest

from upvote.gae.shared.models import utils


class SingletonTest(basetest.AppEngineTestCase):

  def setUp(self):
    super(SingletonTest, self).setUp()

  def testGetAndSet(self):

    class A(utils.Singleton):
      a = ndb.StringProperty()

    self.assertIsNone(A.GetInstance())

    inst = A.SetInstance(a='abcd')
    self.assertEqual('abcd', inst.a)

    inst = A.GetInstance()
    self.assertEqual('abcd', inst.a)
    self.assertEqual('A', A.GetInstance().key.id())

  def testOverrideGetId(self):

    class A(utils.Singleton):
      a = ndb.StringProperty()

      @classmethod
      def _GetId(cls):
        return '1'

    inst = A.SetInstance(a='abcd')
    self.assertEqual('1', inst.key.id())


class CopyEntityTest(basetest.AppEngineTestCase):

  def setUp(self):
    super(CopyEntityTest, self).setUp()

    class A(ndb.Model):
      a = ndb.StringProperty()

    self.default_model = A

  def testUpdateProperties(self):
    inst = self.default_model(a='abc')
    inst.put()

    new = utils.CopyEntity(inst, a='xyz')
    new.put()

    self.assertEqual('abc', inst.a)
    self.assertEqual('xyz', new.a)
    self.assertNotEqual(new.key, inst.key)

  def testFailToSet_AutoNowProperty(self):
    class A(ndb.Model):
      a = ndb.DateTimeProperty(auto_now=True)

    inst = A()
    inst.put()
    with self.assertRaises(utils.PropertyError):
      utils.CopyEntity(
          inst, a=datetime.datetime.utcnow())

  def testFailToSet_ComputedProperty(self):
    class A(ndb.Model):
      a = ndb.StringProperty()
      b = ndb.ComputedProperty(lambda self: self.a[0])

    inst = A(a='xyz')
    inst.put()

    self.assertEqual('x', inst.b)

    with self.assertRaises(utils.PropertyError):
      utils.CopyEntity(inst, b='a')

  def testModelWithComputedProperty(self):
    class A(ndb.Model):
      a = ndb.StringProperty()
      b = ndb.ComputedProperty(lambda self: self.a[0])

    inst = A(a='xyz')
    inst.put()

    self.assertEqual('x', inst.b)

    new = utils.CopyEntity(inst, a='abc')
    new.put()

    self.assertEqual('a', new.b)

  def testPolyModel(self):
    class A(utils.polymodel.PolyModel):
      a = ndb.StringProperty()

    class B(A):
      pass

    inst = B(a='abc')
    inst.put()

    new = utils.CopyEntity(inst, a='xyz')
    new.put()

    self.assertEqual('xyz', new.a)
    self.assertIsInstance(new, B)

  def testPolyModel_NoClass(self):
    class A(utils.polymodel.PolyModel):
      a = ndb.StringProperty()

    class B(A):
      pass

    inst = B(a='abc')
    a_copy = utils.CopyEntity(inst, a='xyz')
    a_copy.put()
    inst.put()

    self.assertEqual('xyz', a_copy.a)
    self.assertEqual('abc', inst.a)

  def testNewId(self):
    inst = self.default_model(a='abc')
    inst.put()

    new = utils.CopyEntity(inst, id='an_id')
    new.put()

    self.assertEqual('abc', new.a)
    self.assertEqual('an_id', new.key.id())

  def testNewIdWithParent(self):
    inst = self.default_model(a='abc')
    inst.put()

    parent = ndb.Key('C', 'c', 'B', 'b')
    expected = ndb.Key('C', 'c', 'B', 'b', 'A', 'an_id')
    new = utils.CopyEntity(
        inst, new_parent=parent, id='an_id')
    new.put()

    self.assertEqual(expected, new.key)

  def testIdWithKey(self):
    inst = self.default_model(a='abc')
    inst.put()

    with self.assertRaises(datastore_errors.BadArgumentError):
      utils.CopyEntity(
          inst, new_key=ndb.Key('A', 'a_key'), id='an_id')

  def testParentWithKey(self):
    inst = self.default_model(a='abc')
    inst.put()

    parent = ndb.Key('C', 'c', 'B', 'b')
    with self.assertRaises(datastore_errors.BadArgumentError):
      utils.CopyEntity(inst, new_key=ndb.Key('A', 'a_key'), new_parent=parent)

  def testUnknownProperty(self):
    inst = self.default_model(a='abc')
    inst.put()

    with self.assertRaises(utils.PropertyError):
      utils.CopyEntity(inst, not_a_property='a')

  def testDeletedProperty(self):
    inst = self.default_model(a='abc')
    inst.put()

    class A(ndb.Model):  # pylint: disable=unused-variable
      b = ndb.StringProperty()

    inst = inst.key.get(use_cache=False)

    copy = utils.CopyEntity(inst)
    self.assertFalse(hasattr(copy, 'a'))


class DeletePropertyTest(basetest.AppEngineTestCase):

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
    utils.DeleteProperty(inst, 'b')
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
    utils.DeleteProperty(inst, 'b')
    inst.put()

    # Create a new instance and verify that the 'b' hasn't disappeared
    new = A(a='abc', b='def')
    new.put()
    self.assertTrue(utils.HasProperty(new, 'b'))

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
    utils.DeleteProperty(inst, 'b')
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
    utils.DeleteProperty(inst, 'b')
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
    utils.DeleteProperty(inst, 'b')
    inst.put()
    inst = A.get_by_id(inst.key.id())

    # The old data is gone :)
    self.assertIsNone(inst.b)

  def testUnknownProperty(self):

    class A(ndb.Model):
      a = ndb.StringProperty()

    inst = A(a='abc')
    inst.put()

    utils.DeleteProperty(inst, 'b')
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
    utils.DeleteProperty(inst, 'b')
    inst.put()
    inst = A.get_by_id(inst.key.id())

    # The old data is gone :)
    self.assertIsNone(inst.b)


class DeletePropertyValueTest(basetest.AppEngineTestCase):

  def setUp(self):
    super(DeletePropertyValueTest, self).setUp()

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
    utils.DeletePropertyValue(inst, 'b')
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
    utils.DeletePropertyValue(inst, 'b')
    inst.put()

    self.assertTrue(utils.HasProperty(inst, 'b'))
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
    utils.DeletePropertyValue(inst, 'b')
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
    utils.DeletePropertyValue(inst, 'b')
    # Property required but no longer has a value.
    with self.assertRaises(Exception):
      inst.put()

  def testUnknownProperty(self):

    class A(ndb.Model):
      a = ndb.StringProperty()

    inst = A(a='abc')
    inst.put()

    utils.DeletePropertyValue(inst, 'b')
    inst.put()
    inst = A.get_by_id(inst.key.id())

    self.assertIsNotNone(inst.a)


class GetLocalComputedPropertyValueTest(basetest.AppEngineTestCase):

  def setUp(self):
    super(GetLocalComputedPropertyValueTest, self).setUp()

    class A(ndb.Model):
      a = ndb.StringProperty()
      b = ndb.ComputedProperty(lambda self: self.a[0])

    self.inst = A(a='xyz')

  def testNormal(self):
    self.assertIsNone(utils.GetLocalComputedPropertyValue(self.inst, 'b'))
    self.inst.put()
    self.assertEqual('x', utils.GetLocalComputedPropertyValue(self.inst, 'b'))
    self.inst.a = 'cdg'
    self.assertEqual('x', utils.GetLocalComputedPropertyValue(self.inst, 'b'))
    self.inst.put()
    self.assertEqual('c', utils.GetLocalComputedPropertyValue(self.inst, 'b'))

  def testUnknownProperty(self):
    with self.assertRaises(utils.PropertyError):
      utils.GetLocalComputedPropertyValue(self.inst, 'NotARealProperty')

  def testNotComputedProperty(self):
    with self.assertRaises(utils.PropertyError):
      utils.GetLocalComputedPropertyValue(self.inst, 'a')


class FutureFactoryTest(basetest.AppEngineTestCase):

  def testInTxn(self):
    def AssertInTxn():
      self.assertTrue(ndb.in_transaction())

    def RunAssert():
      fut = utils.GetNoOpFuture()
      fut.add_callback(AssertInTxn)
      fut.add_immediate_callback(AssertInTxn)
      fut.get_result()

    ndb.transaction(RunAssert)


class GetMultiFutureTest(basetest.AppEngineTestCase):

  def testNoInput(self):
    mf = utils.GetMultiFuture([])
    self.assertTrue(mf.done())

  def testSingleFuture(self):
    f = ndb.Future()
    mf = utils.GetMultiFuture([f])

    self.assertFalse(f.done())
    self.assertFalse(mf.done())

    f.set_result(None)

    self.assertTrue(f.done())
    self.assertFalse(mf.done())

    # Event loop must run for the MultiFuture to be marked as done.
    mf.wait()

    self.assertTrue(mf.done())

  def testManyFutures(self):
    futures = [ndb.Future() for _ in xrange(3)]
    mf = utils.GetMultiFuture(futures)

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
    mf = utils.GetMultiFuture([f])
    with self.assertRaises(RuntimeError):
      mf.add_dependent(ndb.Future())


class GetChainingMultiFutureTest(basetest.AppEngineTestCase):

  def testNoInput(self):
    mf = utils.GetChainingMultiFuture([])
    self.assertTrue(mf.done())

  def testSingleFuture(self):
    f = ndb.Future()
    mf = utils.GetChainingMultiFuture([f])

    self.assertFalse(f.done())
    self.assertFalse(mf.done())

    f.set_result([])

    self.assertTrue(f.done())
    self.assertFalse(mf.done())

    # Event loop must run for the MultiFuture to be marked as done.
    mf.wait()

    self.assertTrue(mf.done())
    self.assertEqual([], mf.get_result())

  def testManyFutures(self):
    futures = [ndb.Future() for _ in xrange(3)]
    mf = utils.GetChainingMultiFuture(futures)

    self.assertFalse(any(f.done() for f in futures))
    self.assertFalse(mf.done())

    for i, f in enumerate(futures):
      f.set_result([i])

    self.assertTrue(all(f.done() for f in futures))
    self.assertFalse(mf.done())

    # Event loop must run for the MultiFuture to be marked as done.
    mf.wait()

    self.assertTrue(mf.done())
    self.assertEqual([0, 1, 2], mf.get_result())

  def testCantModifyResult(self):
    f = ndb.Future()
    mf = utils.GetChainingMultiFuture([f])
    with self.assertRaises(RuntimeError):
      mf.add_dependent(ndb.Future())


class OtherUtilsTest(basetest.AppEngineTestCase):

  def testHasValue(self):

    class Foo(ndb.Model):
      a = ndb.ComputedProperty(lambda self: 'a')
      b = ndb.StringProperty()

    foo = Foo()
    self.assertFalse(utils.HasValue(foo, 'a'))
    self.assertFalse(utils.HasValue(foo, 'b'))

    foo.b = 'b'
    self.assertFalse(utils.HasValue(foo, 'a'))
    self.assertTrue(utils.HasValue(foo, 'b'))

    foo.put()
    self.assertTrue(utils.HasValue(foo, 'a'))
    self.assertTrue(utils.HasValue(foo, 'b'))

  def testKeyHasAncestor(self):
    self.assertFalse(utils.KeyHasAncestor(ndb.Key('A', 1), ndb.Key('A', 1)))
    self.assertTrue(
        utils.KeyHasAncestor(ndb.Key('A', 1, 'B', 2), ndb.Key('A', 1)))
    self.assertFalse(
        utils.KeyHasAncestor(ndb.Key('A', 1, 'B', 2), ndb.Key('A', 2)))
    self.assertFalse(
        utils.KeyHasAncestor(ndb.Key('A', 1, 'B', 2), ndb.Key('A', 1, 'B', 2)))
    self.assertTrue(
        utils.KeyHasAncestor(
            ndb.Key('A', 1, 'B', 2, 'C', 3), ndb.Key('A', 1, 'B', 2)))

  def testConcatenateKeys(self):
    keys = [ndb.Key('A', 1, 'B', 2), ndb.Key('C', 3)]
    self.assertEqual(
        ndb.Key('A', 1, 'B', 2, 'C', 3), utils.ConcatenateKeys(*keys))

  def testConcatenateKeys_Empty(self):
    self.assertIsNone(utils.ConcatenateKeys())

  def testGetKeyFromUrlsafe(self):
    key = ndb.Key('A', 'a', 'B', 'b')
    self.assertEqual(key, utils.GetKeyFromUrlsafe(key.urlsafe()))

  def testGetKeyFromUrlsafe_Error(self):
    self.assertIsNone(utils.GetKeyFromUrlsafe('not a real ndb key string'))

  def testGetNoOpFuture(self):
    future = utils.GetNoOpFuture()
    self.assertTrue(future.done())
    self.assertIsNone(future.get_result())

  def testGetNoOpFuture_Result(self):
    result = 'foobar'
    future = utils.GetNoOpFuture(result)
    self.assertTrue(future.done())
    self.assertEqual(result, future.get_result())


if __name__ == '__main__':
  basetest.main()
