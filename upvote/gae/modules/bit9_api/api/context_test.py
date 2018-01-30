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

"""Tests for API Context."""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

import httplib

import mock
import requests

from absl.testing import absltest
from upvote.gae.modules.bit9_api.api import context
from upvote.gae.modules.bit9_api.api import exceptions as excs
from upvote.gae.modules.bit9_api.api import test_utils


@mock.patch.object(
    requests, 'request', return_value=test_utils.GetTestResponse())
class ContextTest(absltest.TestCase):

  def testBadVersion(self, _):
    with self.assertRaises(ValueError):
      context.Context('foo.corn', 'foo', 1, version='v2')

  def testBadTimeout(self, _):
    with self.assertRaises(ValueError):
      context.Context('foo.corn', 'foo', -1, version='v2')

    with self.assertRaises(ValueError):
      context.Context('foo.corn', 'foo', 'foo', version='v2')

  def testNoSchema(self, mock_req):
    ctx = context.Context('foo.corn', 'foo', 1)
    ctx.ExecuteRequest('GET', api_route='abc')

    mock_req.assert_called_once_with(
        'GET', 'https://foo.corn/api/bit9platform/v1/abc', headers=mock.ANY,
        json=None, verify=mock.ANY, timeout=mock.ANY)

  def testHeaders(self, mock_req):
    ctx = context.Context('foo.corn', 'foo', 1)
    ctx.ExecuteRequest('GET')

    expected_headers = {
        'X-Auth-Token': 'foo',
        'Content-Type': 'application/json'}
    mock_req.assert_called_once_with(
        'GET', mock.ANY, headers=expected_headers, json=None, verify=True,
        timeout=1)

  def testWithPath(self, mock_req):
    ctx = context.Context('foo.corn/other/path', 'foo', 1)
    ctx.ExecuteRequest('GET', api_route='abc')

    mock_req.assert_called_once_with(
        'GET', 'https://foo.corn/other/path/api/bit9platform/v1/abc',
        headers=mock.ANY, json=None, verify=mock.ANY, timeout=mock.ANY)

  def testNoRoute(self, mock_req):
    ctx = context.Context('foo.corn', 'foo', 1)
    ctx.ExecuteRequest('GET')

    mock_req.assert_called_once_with(
        'GET', 'https://foo.corn/api/bit9platform/v1', headers=mock.ANY,
        json=None, verify=mock.ANY, timeout=mock.ANY)

  def testRequestError(self, mock_req):
    mock_req.side_effect = requests.RequestException

    ctx = context.Context('foo.corn', 'foo', 1)
    with self.assertRaises(excs.RequestError):
      ctx.ExecuteRequest('GET')

  def testClientError(self, mock_req):
    mock_req.return_value = test_utils.GetTestResponse(
        status_code=httplib.BAD_REQUEST)

    ctx = context.Context('foo.corn', 'foo', 1)
    with self.assertRaises(excs.RequestError):
      ctx.ExecuteRequest('GET')

  def testServerError(self, mock_req):
    mock_req.return_value = test_utils.GetTestResponse(
        status_code=httplib.INTERNAL_SERVER_ERROR)

    ctx = context.Context('foo.corn', 'foo', 1)
    with self.assertRaises(excs.RequestError):
      ctx.ExecuteRequest('GET')

  def testNotFound(self, mock_req):
    mock_req.return_value = test_utils.GetTestResponse(
        status_code=httplib.NOT_FOUND)

    ctx = context.Context('foo.corn', 'foo', 1)
    with self.assertRaises(excs.NotFoundError):
      ctx.ExecuteRequest('GET')

  def testEmptyResponse(self, mock_req):
    mock_req.return_value = test_utils.GetTestResponse(status_code=httplib.OK)
    mock_req.return_value.text = None

    ctx = context.Context('foo.corn', 'foo', 1)
    with self.assertRaises(excs.RequestError):
      ctx.ExecuteRequest('GET')

  def testFailedJsonParse(self, mock_req):
    mock_req.return_value = test_utils.GetTestResponse()
    mock_req.return_value.text = '{"Invalid": "JSON}'

    ctx = context.Context('foo.corn', 'foo', 1)
    with self.assertRaises(excs.RequestError):
      ctx.ExecuteRequest('GET')


if __name__ == '__main__':
  absltest.main()
