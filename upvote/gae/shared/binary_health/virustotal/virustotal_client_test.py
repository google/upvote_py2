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

"""Unit tests for virustotal_client.py."""

import mock

from google.appengine.api import urlfetch

from common.testing import basetest
from upvote.gae.datastore.models import virustotal
from upvote.gae.shared.binary_health.virustotal import virustotal_client


@mock.patch.object(urlfetch, 'fetch')
@mock.patch.object(virustotal.VirusTotalApiAuth, 'GetInstance')
class ClientTest(basetest.AppEngineTestCase):

  def testLookup(self, mock_get_inst, mock_fetch):
    mock_get_inst.return_value.api_key = 'fake_api_key'
    mock_fetch_response = mock.Mock()
    mock_fetch_response.content = '{"response_code": 1}'
    mock_fetch.return_value = mock_fetch_response

    response_dict = virustotal_client.Lookup('some_hash')
    self.assertIsInstance(response_dict, dict)
    self.assertEqual(1, response_dict['response_code'])

  def testLookup_StripUntrustedScans(self, mock_get_inst, mock_fetch):
    mock_get_inst.return_value.api_key = 'fake_api_key'
    mock_fetch_response = mock.Mock()
    mock_fetch_response.content = (
        '{"response_code": 1, "scans": {"Microsoft": {"detected": false}, '
        '"Not-Microsoft": {"detected": true}}}')
    mock_fetch.return_value = mock_fetch_response

    response_dict = virustotal_client.Lookup('some_hash')
    self.assertIsInstance(response_dict, dict)
    self.assertEqual(0, response_dict['positives'])
    self.assertEqual(1, response_dict['total'])
    self.assertEqual(1, len(response_dict['scans']))
    self.assertEqual('Microsoft', response_dict['scans'].keys()[0])

  def testLookup_BadResponse(self, mock_get_inst, mock_fetch):
    mock_get_inst.return_value.api_key = 'fake_api_key'
    # Create a malformed JSON response.
    mock_fetch_response = mock.Mock()
    mock_fetch_response.content = '{"response_c'
    mock_fetch.return_value = mock_fetch_response

    with self.assertRaises(virustotal_client.ResponseError):
      virustotal_client.Lookup('some_hash')

  def testLookup_Cached(self, mock_get_inst, mock_fetch):
    mock_get_inst.return_value.api_key = 'fake_api_key'
    mock_fetch_response = mock.Mock()
    mock_fetch_response.content = '{"response_code": 1}'
    mock_fetch.return_value = mock_fetch_response

    virustotal_client.Lookup('some_hash')
    virustotal_client.Lookup('some_hash')
    virustotal_client.Lookup('other_hash')
    virustotal_client.Lookup('other_hash')

    # Only the two unique hashes should have caused API queries.
    self.assertEqual(2, mock_fetch.call_count)

  def testLookup_OnlyCacheAnalyzed(self, mock_get_inst, mock_fetch):
    mock_get_inst.return_value.api_key = 'fake_api_key'
    mock_fetch_response = mock.Mock()
    mock_fetch_response.content = '{"response_code": 0}'
    mock_fetch.return_value = mock_fetch_response

    virustotal_client.Lookup('some_hash')
    virustotal_client.Lookup('some_hash')
    virustotal_client.Lookup('other_hash')
    virustotal_client.Lookup('other_hash')

    # No cache entries are written so all calls should result in an API query.
    self.assertEqual(4, mock_fetch.call_count)


if __name__ == '__main__':
  basetest.main()
