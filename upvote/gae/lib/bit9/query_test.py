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

"""Tests for API queries."""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

import mock
import requests
from upvote.gae.lib.bit9 import context
from upvote.gae.lib.bit9 import exceptions as excs
from upvote.gae.lib.bit9 import model
from upvote.gae.lib.bit9 import query
from upvote.gae.lib.bit9 import test_utils
from absl.testing import absltest


class AModel(model.Model):
  ROUTE = '1234'


class TestModel(model.Model):
  ROUTE = 'abcd'

  foo = model.StringProperty('foo', allow_update=True, expands_to=AModel)
  bar = model.Int32Property('bar')
  baz = model.StringProperty('baz', allow_update=True, expands_to=AModel)


class OtherTestModel(model.Model):
  ROUTE = 'efgh'

  foo = model.StringProperty(
      'foo', allow_update=True, expands_to=TestModel)
  bar = model.Int32Property('bar')


_TEST_URL = 'https://foo.corn'
_TEST_CTX = context.Context(_TEST_URL, 'abc', 123)
_TEST_API_ADDR = _TEST_URL + '/api/bit9platform/v1/'


@mock.patch.object(
    requests, 'request', return_value=test_utils.GetTestResponse(data={}))
class QueryTest(absltest.TestCase):

  def testEmpty(self, mock_req):
    query.Query(TestModel).execute(_TEST_CTX)
    mock_req.assert_called_once_with(
        'GET', _TEST_API_ADDR + 'abcd', headers=mock.ANY, json=None,
        verify=mock.ANY, timeout=mock.ANY)

  def testLimit(self, mock_req):
    query.Query(TestModel).limit(10).execute(_TEST_CTX)
    mock_req.assert_called_once_with(
        'GET', _TEST_API_ADDR + 'abcd?limit=10', headers=mock.ANY, json=None,
        verify=mock.ANY, timeout=mock.ANY)

  def testBadLimit(self, _):
    with self.assertRaises(excs.QueryError):
      query.Query(TestModel).limit(-1).execute(_TEST_CTX)

  def testBadExpand(self, _):
    with self.assertRaises(excs.QueryError):
      query.Query(TestModel).expand(TestModel.bar).execute(_TEST_CTX)

  def testWrongModelClassExpand(self, _):
    with self.assertRaises(excs.QueryError):
      query.Query(TestModel).expand(TestModel.bar).execute(_TEST_CTX)

  def testExpands(self, mock_req):
    query.Query(TestModel).expand(TestModel.foo).execute(_TEST_CTX)
    mock_req.assert_called_once_with(
        'GET', _TEST_API_ADDR + 'abcd?expand=foo', headers=mock.ANY, json=None,
        verify=mock.ANY, timeout=mock.ANY)

  def testMultipleExpands(self, mock_req):
    (query.Query(TestModel)
     .expand(TestModel.foo)
     .expand(TestModel.baz)
     .execute(_TEST_CTX))
    mock_req.assert_called_once_with(
        'GET', _TEST_API_ADDR + 'abcd?expand=baz&expand=foo', headers=mock.ANY,
        json=None, verify=mock.ANY, timeout=mock.ANY)

  def testSort_RawProperty(self, mock_req):
    query.Query(TestModel).order(TestModel.foo).execute(_TEST_CTX)
    mock_req.assert_called_once_with(
        'GET', _TEST_API_ADDR + 'abcd?sort=foo ASC', headers=mock.ANY,
        json=None, verify=mock.ANY, timeout=mock.ANY)

  def testSort_WithNode(self, mock_req):
    query.Query(TestModel).order(-TestModel.baz).execute(_TEST_CTX)
    mock_req.assert_called_once_with(
        'GET', _TEST_API_ADDR + 'abcd?sort=baz DESC', headers=mock.ANY,
        json=None, verify=mock.ANY, timeout=mock.ANY)

  def testSort_BadObj(self, _):
    with self.assertRaises(excs.QueryError):
      query.Query(TestModel).order('garbage').execute(_TEST_CTX)

  def testCount(self, mock_req):
    mock_req.return_value = test_utils.GetTestResponse(data={'count': 1})

    response = query.Query(TestModel).count(_TEST_CTX)

    self.assertEqual(1, response)
    mock_req.assert_called_once_with(
        'GET', _TEST_API_ADDR + 'abcd?limit=-1', headers=mock.ANY, json=None,
        verify=mock.ANY, timeout=mock.ANY)

  def testBadFilter(self, _):
    with self.assertRaises(excs.QueryError):
      (query.Query(TestModel)
       .filter(OtherTestModel.foo == 'a')
       .execute(_TEST_CTX))

  def testManyFilters(self, mock_req):
    query.Query(TestModel).filter(
        TestModel.foo == 'a',
        TestModel.baz == 'b').execute(_TEST_CTX)
    mock_req.assert_called_once_with(
        'GET', _TEST_API_ADDR + 'abcd?q=baz:b&q=foo:a', headers=mock.ANY,
        json=None, verify=mock.ANY, timeout=mock.ANY)

  def testOrFilter(self, mock_req):
    query.Query(TestModel).filter(
        (TestModel.foo == 'a') |
        (TestModel.foo == 'b')).execute(_TEST_CTX)
    mock_req.assert_called_once_with(
        'GET', _TEST_API_ADDR + 'abcd?q=foo:a|b', headers=mock.ANY,
        json=None, verify=mock.ANY, timeout=mock.ANY)

  def testOrFilter_MismatchedProperties(self, _):
    with self.assertRaises(excs.QueryError):
      query.Query(TestModel).filter(
          (TestModel.foo == 'a') |
          (TestModel.baz == 'b')).execute(_TEST_CTX)

  def testOrFilter_MismatchedOperators(self, _):
    with self.assertRaises(excs.QueryError):
      query.Query(TestModel).filter(
          (TestModel.foo == 'a') |
          (TestModel.baz != 'b')).execute(_TEST_CTX)

  def testEverything(self, mock_req):
    (query.Query(TestModel)
     .filter(TestModel.foo == 'a', TestModel.baz == 'b')
     .order(TestModel.foo)
     .expand(TestModel.foo)
     .limit(3)
     .execute(_TEST_CTX))
    mock_req.assert_called_once_with(
        'GET',
        _TEST_API_ADDR + 'abcd?q=baz:b&q=foo:a&sort=foo ASC&limit=3&expand=foo',
        headers=mock.ANY, json=None, verify=mock.ANY, timeout=mock.ANY)


if __name__ == '__main__':
  absltest.main()
