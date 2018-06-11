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

"""Tests for lookups.py."""

import httplib

import mock
import webapp2

from upvote.gae.datastore import test_utils
from upvote.gae.lib.analysis import api as analysis_api
from upvote.gae.modules.upvote_app.api.handlers import lookups
from upvote.gae.shared.common import basetest
from upvote.gae.shared.common import settings
from upvote.gae.shared.common import settings_utils
from upvote.shared import constants


class LookupsTest(basetest.UpvoteTestCase):

  VIRUSTOTAL_ROUTE = '/check/virustotal/%s'

  def setUp(self):
    app = webapp2.WSGIApplication(routes=[lookups.ROUTES])
    super(LookupsTest, self).setUp(wsgi_app=app)

    self.santa_blockable1 = test_utils.CreateSantaBlockable(
        id='eeeeffffgggghhhh',
        id_type=constants.ID_TYPE.SHA256,
        blockable_hash='eeeeffffgggghhhh',
        file_name='Mac.app',
        publisher='Arple',
        product_name='New Shiny',
        version='2.0',
        flagged=True)

    self.santa_blockable2 = test_utils.CreateSantaBlockable()

    self.santa_bundle = test_utils.CreateSantaBundle(
        id='yyyyyyyyyyyyyyyyyyyyyyyyyyyy',
        bundle_binaries=[self.santa_blockable1, self.santa_blockable2])

    self.bit9_blockable1 = test_utils.CreateBit9Binary(
        id='zzzzzzzzzzzzzzzzzzzzzzzzzzzz',
        id_type=constants.ID_TYPE.SHA256,
        file_name='spyware.exe',
        publisher='TrustUs',
        product_name='Free PC Check!',
        version='1.0')

    self.bit9_blockable2 = test_utils.CreateBit9Binary(
        id='aaaaaaaaaaaaaaaaaaaaaaaaaaaa',
        id_type=constants.ID_TYPE.SHA256,
        file_name='legit.exe',
        publisher='A Really Trustworthy Company',
        product_name='Safe To Run',
        version='1.0')


  @mock.patch.object(
      analysis_api, 'VirusTotalLookup', return_value={'response_code': 1})
  def testCheckVirusTotal_SuccessFound(self, mock_vt_lookup):
    with self.LoggedInUser():
      response = self.testapp.get(
          self.VIRUSTOTAL_ROUTE % self.bit9_blockable1.key.id())

    self.assertIn('application/json', response.headers['Content-type'])
    self.assertEqual(1, response.json['responseCode'])

  @mock.patch.object(
      analysis_api, 'VirusTotalLookup', return_value={'response_code': 1})
  def testCheckVirusTotal_NotBit9Binary(self, mock_vt_lookup):
    with self.LoggedInUser():
      response = self.testapp.get(
          self.VIRUSTOTAL_ROUTE % self.santa_blockable1.key.id())

    self.assertIn('application/json', response.headers['Content-type'])
    self.assertEqual(1, response.json['responseCode'])

  @mock.patch.object(analysis_api, 'VirusTotalLookup')
  def testCheckVirusTotal_SantaBundle_AllKnown(self, mock_vt_lookup):
    mock_vt_lookup.side_effect = [
        {'response_code': 1, 'positives': 5, 'total': 40, 'scans': []},
        {'response_code': 1, 'positives': 0, 'total': 40, 'scans': []},
    ]
    with self.LoggedInUser():
      response = self.testapp.get(
          self.VIRUSTOTAL_ROUTE % self.santa_bundle.key.id())

    self.assertIn('application/json', response.headers['Content-type'])
    self.assertEqual(1, response.json['responseCode'])
    self.assertEqual(1, response.json['positives'])

    blockable_report = response.json['reports'][self.santa_blockable1.key.id()]
    self.assertEqual(1, blockable_report['responseCode'])
    self.assertNotIn('scans', blockable_report)

  @mock.patch.object(analysis_api, 'VirusTotalLookup')
  def testCheckVirusTotal_SantaBundle_PartialKnown(self, mock_vt_lookup):
    mock_vt_lookup.side_effect = [
        {'response_code': 1, 'positives': 0, 'total': 40, 'scans': []},
        {'response_code': 0},
    ]
    with self.LoggedInUser():
      response = self.testapp.get(
          self.VIRUSTOTAL_ROUTE % self.santa_bundle.key.id())

    self.assertIn('application/json', response.headers['Content-type'])
    self.assertEqual(0, response.json['responseCode'])
    self.assertEqual(0, response.json['positives'])

  @mock.patch.object(analysis_api, 'VirusTotalLookup')
  def testCheckVirusTotal_SantaBundle_PartialError(self, mock_vt_lookup):
    mock_vt_lookup.side_effect = [
        analysis_api.LookupFailure,
        {
            'response_code': 1,
            'positives': 0,
            'total': 40,
            'scans': []
        },
    ]
    with self.LoggedInUser():
      response = self.testapp.get(
          self.VIRUSTOTAL_ROUTE % self.santa_bundle.key.id())

    self.assertIn('application/json', response.headers['Content-type'])
    self.assertEqual(0, response.json['responseCode'])
    self.assertEqual(0, response.json['positives'])

  def testCheckVirusTotal_BlockableDoesntExist(self):
    with self.LoggedInUser():
      self.testapp.get(
          self.VIRUSTOTAL_ROUTE % self.santa_blockable1.key.id(),
          status=httplib.NOT_FOUND)


if __name__ == '__main__':
  basetest.main()
