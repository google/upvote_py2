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

"""Tests for API models and properties."""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

import datetime

import mock
import requests

from absl.testing import absltest
from upvote.gae.lib.bit9 import context
from upvote.gae.lib.bit9 import exceptions as excs
from upvote.gae.lib.bit9 import model
from upvote.gae.lib.bit9 import test_utils


class AModel(model.Model):
  ROUTE = '1234'

  foo = model.StringProperty('foo', allow_update=True)


class TestModel(model.Model):
  ROUTE = 'abcd'

  foo = model.StringProperty('foo', allow_update=True, expands_to='AModel')
  bar = model.Int32Property('bar')
  baz = model.StringProperty('baz', allow_update=True, expands_to='AModel')


class OtherTestModel(model.Model):
  ROUTE = 'efgh'

  foo = model.StringProperty(
      'foo', allow_update=True, expands_to='TestModel')
  bar = model.Int32Property('bar')


_TEST_URL = 'https://foo.corn'
_TEST_CTX = context.Context(_TEST_URL, 'abc', 123)
_TEST_API_ADDR = _TEST_URL + '/api/bit9platform/v1/'


class MetaModelTest(absltest.TestCase):

  def testSetPropModelCls(self):
    self.assertEqual('TestModel', TestModel.foo.model_cls_name)
    self.assertEqual('TestModel', TestModel.bar.model_cls_name)

  def testNoRouteProvided(self):
    with self.assertRaises(excs.Error):

      class OtherModel(model.Model):  # pylint: disable=unused-variable
        pass

  def testKindMap(self):
    self.assertEqual(TestModel, OtherTestModel._KIND_MAP['TestModel'])


@mock.patch.object(
    requests, 'request', return_value=test_utils.GetTestResponse())
class ModelTest(absltest.TestCase):

  def testPut(self, mock_req):
    obj = {'foo': 'abc', 'bar': 123}
    test_model = TestModel.from_dict(obj)
    mock_req.return_value = test_utils.GetTestResponse(data=obj)

    test_model.put(_TEST_CTX)

    mock_req.assert_called_once_with(
        'POST', _TEST_API_ADDR + 'abcd', headers=mock.ANY, json=obj,
        verify=mock.ANY, timeout=mock.ANY)

  def testPut_ExtraQueryArgs(self, mock_req):
    obj = {'foo': 'abc', 'bar': 123}
    test_model = TestModel.from_dict(obj)
    mock_req.return_value = test_utils.GetTestResponse(data=obj)

    test_model.put(_TEST_CTX, {'resetCLIPassword': True})

    mock_req.assert_called_once_with(
        'POST', _TEST_API_ADDR + 'abcd?resetCLIPassword=True', headers=mock.ANY,
        json=obj, verify=mock.ANY, timeout=mock.ANY)

  def testPut_ExpandedModel(self, mock_req):
    obj = {'foo': 'abc', 'foo_foo': 'def', 'bar': 123}
    test_model = TestModel.from_dict(obj)
    amodel = test_model.get_expand(TestModel.foo)

    # Update the expanded model.
    amodel.foo = 'ghi'

    mock_req.return_value = test_utils.GetTestResponse(data={'foo': 'ghi'})

    new_model = amodel.put(_TEST_CTX)
    self.assertEqual(new_model, amodel)

    mock_req.assert_called_once_with(
        'POST', _TEST_API_ADDR + '1234', headers=mock.ANY, json={'foo': 'ghi'},
        verify=mock.ANY, timeout=mock.ANY)

  def testPut_ModelWithExpand(self, mock_req):
    obj = {'foo': 'abc', 'foo_foo': 'def', 'bar': 123}
    test_model = TestModel.from_dict(obj)
    test_model.foo = 'def'

    mock_req.return_value = test_utils.GetTestResponse(
        data={'foo': 'def', 'bar': 123})

    new_model = test_model.put(_TEST_CTX)
    self.assertEqual(new_model, test_model)

    mock_req.assert_called_once_with(
        'POST', _TEST_API_ADDR + 'abcd', headers=mock.ANY,
        json={'foo': 'def', 'bar': 123}, verify=mock.ANY, timeout=mock.ANY)

  def testGet(self, mock_req):
    mock_req.return_value = test_utils.GetTestResponse(data={})

    TestModel.get('123', _TEST_CTX)

    mock_req.assert_called_once_with(
        'GET', _TEST_API_ADDR + 'abcd/123', headers=mock.ANY, json=None,
        verify=mock.ANY, timeout=mock.ANY)

  def testDelete(self, mock_req):
    obj = {'foo': 'abc', 'bar': 123}
    test_model = TestModel.from_dict(obj)
    mock_req.return_value = test_utils.GetTestResponse(data=obj)

    test_model.delete(123, _TEST_CTX)

    mock_req.assert_called_once_with(
        'DELETE', _TEST_API_ADDR + 'abcd/123', headers=mock.ANY, json=None,
        verify=mock.ANY, timeout=mock.ANY)

  def testUpdateFields(self, mock_req):
    obj = {'foo': 'def'}
    mock_req.side_effect = [
        test_utils.GetTestResponse(data={'foo': 'abc', 'bar': 123}),
        test_utils.GetTestResponse(data={'foo': 'def', 'bar': 123})]

    TestModel.update('12345', obj, _TEST_CTX)

    expected_calls = [
        mock.call(
            'GET', _TEST_API_ADDR + 'abcd/12345', headers=mock.ANY, json=None,
            verify=mock.ANY, timeout=mock.ANY),
        mock.call(
            'POST', _TEST_API_ADDR + 'abcd', headers=mock.ANY,
            json={'foo': 'def', 'bar': 123}, verify=mock.ANY,
            timeout=mock.ANY)]
    mock_req.assert_has_calls(expected_calls)

  def testUpdateFields_WrongModelProp(self, _):
    obj = {OtherTestModel.foo: 'def'}
    with self.assertRaises(excs.PropertyError):
      TestModel.update('12345', obj, _TEST_CTX)

  def testUpdateFields_BadProp(self, _):
    obj = {'notAProperty': 'def'}
    with self.assertRaises(excs.PropertyError):
      TestModel.update('12345', obj, _TEST_CTX)

  def testUpdateFields_NotUpdateable(self, _):
    obj = {'bar': 123}
    with self.assertRaises(excs.PropertyError):
      TestModel.update('12345', obj, _TEST_CTX)

  def testBuildQuery(self, mock_req):
    mock_req.return_value = test_utils.GetTestResponse(data={})

    TestModel.query().execute(_TEST_CTX)

    mock_req.assert_called_once_with(
        'GET', _TEST_API_ADDR + 'abcd', headers=mock.ANY, json=None,
        verify=mock.ANY, timeout=mock.ANY)

  def testGetExpand(self, _):
    test_model = TestModel.from_dict(
        {'foo': 'a', 'bar': 1, 'baz': 'b', 'foo_foo': 'c'})

    a_model = test_model.get_expand(TestModel.foo)

    self.assertIsInstance(a_model, AModel)
    self.assertEqual('foo', a_model._prefix)

  def testGetExpand_NoExpandedFields(self, _):
    test_model = TestModel(foo='a', bar=1, baz='b')

    a_model = test_model.get_expand(TestModel.foo)

    self.assertIsNone(a_model)

  def testGetExpand_NonExpandableProperty(self, _):
    test_model = TestModel()
    with self.assertRaises(excs.PropertyError):
      test_model.get_expand(TestModel.bar)

  def testGetExpand_UnknownModel(self, _):

    class FooModel(model.Model):
      ROUTE = 'foo'

      foo = model.StringProperty('foo', expands_to='NotARealModel')

    foo_model = FooModel(foo='a')
    with self.assertRaises(excs.PropertyError):
      foo_model.get_expand(FooModel.foo)

  def testGetAttr(self, _):
    test_model = TestModel(foo='a', bar=1, baz='b')
    self.assertEqual('a', test_model.foo)

  def testGetAttr_WithPrefix(self, _):
    test_model = TestModel.from_dict(
        {'foo': 'a', 'bar': 1, 'baz': 'b', 'foo_foo': 'c'})
    self.assertEqual('c', test_model.get_expand(TestModel.foo).foo)

  def testGetAttr_NonProperty(self, _):
    test_model = TestModel.from_dict(
        {'foo': 'a', 'bar': 1, 'baz': 'b', 'foo_foo': 'c'})
    self.assertEqual('abcd', test_model.ROUTE)

  def testGetAttr_AbsentDatetimeProperty(self, _):

    class FooModel(model.Model):
      ROUTE = 'foo'

      foo = model.DateTimeProperty('foo')

    foo_model = FooModel.from_dict({})
    self.assertIsNone(foo_model.foo)

  def testGetAttr_RawDatetimePropertyInConstructor(self, _):

    class FooModel(model.Model):
      ROUTE = 'foo'

      foo = model.DateTimeProperty('foo')

    foo_model = FooModel(foo=datetime.datetime.now())
    with self.assertRaises(TypeError):
      unused_dt = foo_model.foo

  def testSetAttr(self, _):
    test_model = TestModel(foo='a', bar=1, baz='b')

    test_model.foo = 'c'

    self.assertEqual('c', test_model.foo)
    self.assertEqual('c', test_model._obj_dict['foo'])

  def testSetAttr_WithPrefix(self, _):
    test_model = TestModel.from_dict(
        {'foo': 'a', 'bar': 1, 'baz': 'b', 'foo_foo': 'c'})
    a_model = test_model.get_expand(TestModel.foo)

    a_model.foo = 'd'

    self.assertEqual('d', a_model.foo)
    self.assertEqual('d', a_model._obj_dict['foo_foo'])

  def testSetAttr_NonProperty(self, _):
    test_model = TestModel(foo='a', bar=1, baz='b')
    test_model.ROUTE = 'a'  # pylint: disable=invalid-name
    self.assertEqual('a', test_model.ROUTE)

  def testFormatting(self, _):

    class RealModel(model.Model):
      ROUTE = '1234'

      id = model.Int32Property('id')
      foo = model.StringProperty('foo')

    a_model = RealModel(id=123, foo=u'a')
    self.assertEqual('RealModel(id=123, ...)', str(a_model))
    self.assertEqual("RealModel(\n    foo=u'a',\n    id=123)", repr(a_model))


# pylint: disable=pointless-statement,g-equals-none,g-explicit-bool-comparison
class PropertyTest(absltest.TestCase):

  @classmethod
  def setUpClass(cls):

    class Foo(model.Model):
      ROUTE = 'foo'

      bar = model.StringProperty('bar')
      baz = model.Int32Property('baz')
      bot = model.DecimalProperty('bot')
      qux = model.BooleanProperty('qux')
      zut = model.DateTimeProperty('zut')

    cls.model = Foo

  def testString(self):
    self.assertEqual('foo', (self.model.bar == 'foo').value)
    self.assertEqual('foo', (self.model.bar != 'foo').value)
    self.assertEqual('foo', (self.model.bar > 'foo').value)
    self.assertEqual('foo', (self.model.bar < 'foo').value)

    self.assertEqual(u'foo', (self.model.bar == u'foo').value)

    with self.assertRaises(ValueError):
      self.model.bar == 1

    self.assertEqual('', (self.model.bar == None).value)

  def testInteger(self):
    self.assertEqual('1', (self.model.baz == 1).value)
    self.assertEqual('1', (self.model.baz != 1).value)
    self.assertEqual('1', (self.model.baz > 1).value)
    self.assertEqual('1', (self.model.baz < 1).value)

    with self.assertRaises(ValueError):
      self.model.baz == '1'

    self.assertEqual('', (self.model.baz == None).value)

  def testInteger_BoundsCheck(self):
    at_limit = 2 ** 32 - 1
    self.assertEqual(str(at_limit), (self.model.baz < at_limit).value)

    over_limit = 2 ** 32
    with self.assertRaises(ValueError):
      self.model.baz == over_limit

  def testDecimal(self):
    self.assertEqual('1.1', (self.model.bot == 1.1).value)
    self.assertEqual('0.0', (self.model.bot != 0.).value)

    with self.assertRaises(ValueError):
      self.model.bot == 1

    self.assertEqual('', (self.model.bot == None).value)

  def testBoolean(self):
    self.assertEqual('true', (self.model.qux == True).value)
    self.assertEqual('false', (self.model.qux != False).value)

    with self.assertRaises(excs.QueryError):
      self.model.qux < True

    with self.assertRaises(excs.QueryError):
      self.model.qux > True

    with self.assertRaises(ValueError):
      self.model.qux == 'True'

    self.assertEqual('', (self.model.qux == None).value)

  def testDateTime(self):
    expected = '2012-12-12T08:08:08.990000Z'
    a_dt = datetime.datetime(
        year=2012, month=12, day=12, hour=8, minute=8, second=8,
        microsecond=990000)
    self.assertEqual(expected, (self.model.zut == a_dt).value)
    self.assertEqual(expected, (self.model.zut != a_dt).value)
    self.assertEqual(expected, (self.model.zut > a_dt).value)
    self.assertEqual(expected, (self.model.zut < a_dt).value)

    with self.assertRaises(ValueError):
      self.model.zut == '1'

    with self.assertRaises(ValueError):
      self.model.zut == 1

    self.assertEqual('', (self.model.zut == None).value)

    # Secondary datetime format (without usecs) should add a usec field.
    expected = '2012-12-12T08:08:08.000000Z'
    a_dt = datetime.datetime(
        year=2012, month=12, day=12, hour=8, minute=8, second=8)
    self.assertEqual(expected, (self.model.zut == a_dt).value)

# pylint: enable=pointless-statement,g-equals-none,g-explicit-bool-comparison

if __name__ == '__main__':
  absltest.main()
