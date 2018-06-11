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

"""Unit tests for intermodule.py."""

import httplib

import mock
import webapp2

from google.appengine.api import modules
from google.appengine.api import urlfetch

from upvote.gae.shared.common import basetest
from upvote.gae.shared.common import settings
from upvote.gae.shared.common import settings_utils
from upvote.gae.utils import intermodule_utils

_TEST_DOMAIN = 'somemodule.appspot.com'


@mock.patch.object(
    modules, 'get_hostname', return_value=_TEST_DOMAIN)
class SubmitIntermoduleRequestTest(basetest.UpvoteTestCase):

  @mock.patch.object(
      urlfetch, 'fetch',
      return_value=mock.Mock(status_code=httplib.OK, content='{}'))
  def testSuccess_WithoutData(self, mock_fetch, _):
    response = intermodule_utils.SubmitIntermoduleRequest(
        'some-module', '/api/path/whatever')

    self.assertEqual(httplib.OK, response.status_code)
    self.assertEqual('{}', response.content)

    mock_fetch.assert_called_once_with(
        'https://%s/api/path/whatever' % _TEST_DOMAIN,
        method=urlfetch.GET,
        payload=None,
        headers=mock.ANY,
        deadline=mock.ANY,
        follow_redirects=False)

  @mock.patch.object(
      urlfetch, 'fetch',
      return_value=mock.Mock(status_code=httplib.OK, content='{}'))
  def testSuccess_WithData(self, mock_fetch, _):
    response = intermodule_utils.SubmitIntermoduleRequest(
        'some-module', '/api/path/whatever', data={'foo': 'bar'})

    self.assertEqual(httplib.OK, response.status_code)
    self.assertEqual('{}', response.content)

    mock_fetch.assert_called_once_with(
        'https://%s/api/path/whatever' % _TEST_DOMAIN,
        method=urlfetch.POST,
        payload='foo=bar',
        headers=mock.ANY,
        deadline=mock.ANY,
        follow_redirects=False)

  @mock.patch.object(
      urlfetch, 'fetch',
      return_value=mock.Mock(status_code=httplib.OK, content=''))
  def testSuccess_NoReturnedData(self, mock_fetch, _):
    response = intermodule_utils.SubmitIntermoduleRequest(
        'some-module', '/api/path/whatever', data={'foo': 'bar'})

    self.assertEqual(httplib.OK, response.status_code)
    self.assertEqual('', response.content)

  @mock.patch.object(urlfetch, 'fetch')
  def testSuccess_Redirects(self, mock_fetch, _):
    def GenRedirect(url):
      return mock.Mock(status_code=httplib.FOUND, headers={'Location': url})

    # Rediret 4 times and succeed on the fifth.
    success = mock.Mock(status_code=httplib.OK, content='{}')
    redirect_urls = ['https://foo%d.com' % i for i in xrange(4)]
    mock_fetch.side_effect = [
        GenRedirect(url) for url in redirect_urls] + [success]

    response = intermodule_utils.SubmitIntermoduleRequest(
        'some-module', '/api/path/whatever')

    self.assertEqual(httplib.OK, response.status_code)
    self.assertEqual('{}', response.content)

    self.assertEqual(5, mock_fetch.call_count)

    for expected, call in zip(redirect_urls, mock_fetch.call_args_list[1:]):
      observed = call[0][0]
      self.assertEqual(expected, observed)

  @mock.patch.object(urlfetch, 'fetch')
  def testError_Redirects(self, mock_fetch, _):
    redirect = mock.Mock(
        status_code=httplib.FOUND, headers={'Location': 'https://foo.com'})
    mock_fetch.side_effect = (redirect,) * 5
    with self.assertRaises(urlfetch.Error):
      intermodule_utils.SubmitIntermoduleRequest(
          'some-module', '/api/path/whatever')

    self.assertEqual(5, mock_fetch.call_count)

  @mock.patch.object(urlfetch, 'fetch', side_effect=urlfetch.Error)
  def testError(self, *_):
    with self.assertRaises(urlfetch.Error):
      intermodule_utils.SubmitIntermoduleRequest(
          'some-module', '/api/path/whatever')


if __name__ == '__main__':
  basetest.main()
