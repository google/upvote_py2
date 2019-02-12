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

"""Unit tests for settings.py."""

import httplib

import mock
import webapp2

from upvote.gae.lib.testing import basetest
from upvote.gae.modules.upvote_app.api.web import settings


class SettingsTest(basetest.UpvoteTestCase):
  """Test Settings Handler Class."""

  ROUTE = '/settings/%s'

  def setUp(self):
    app = webapp2.WSGIApplication(routes=[settings.ROUTES])
    super(SettingsTest, self).setUp(wsgi_app=app)

    settings.settings.READY_TO_MOVE_OUT = 'Ready'

    self.PatchValidateXSRFToken()

  def testGet(self):
    """Admin getting a value."""

    with self.LoggedInUser():
      response = self.testapp.get(self.ROUTE % 'ready_to_move_out')

    output = response.json

    self.assertIn('application/json', response.headers['Content-type'])
    self.assertEqual('Ready', output)

  def testGet_DoesntExist(self):
    """Admin querying for a setting value that does not exist."""

    with self.LoggedInUser():
      self.testapp.get(
          self.ROUTE % 'spidey_sense_tingling', status=httplib.NOT_FOUND)


class ApiKeysTest(basetest.UpvoteTestCase):
  """Test Settings Handler Class."""

  ROUTE = '/settings/api-keys/%s'

  def setUp(self):
    app = webapp2.WSGIApplication(routes=[settings.ROUTES])
    super(ApiKeysTest, self).setUp(wsgi_app=app)

    self.PatchValidateXSRFToken()

  def testUpdateVirusTotalKey(self):
    with mock.patch.object(
        settings.singleton.VirusTotalApiAuth, 'SetInstance') as mock_set:
      with self.LoggedInUser(admin=True):
        self.testapp.post(self.ROUTE % 'virustotal', {'value': 'abc'})
      mock_set.assert_called_once_with(api_key='abc')

  def testUpdateBit9Key(self):
    with mock.patch.object(
        settings.singleton.Bit9ApiAuth, 'SetInstance') as mock_set:
      with self.LoggedInUser(admin=True):
        self.testapp.post(self.ROUTE % 'bit9', {'value': 'abc'})
      mock_set.assert_called_once_with(api_key='abc')

  def testBadValue(self):
    with self.LoggedInUser(admin=True):
      self.testapp.post(
          self.ROUTE % 'virustotal', {}, status=httplib.BAD_REQUEST)

  def testBadKeyName(self):
    with self.LoggedInUser(admin=True):
      self.testapp.post(
          self.ROUTE % 'not-a-key', {'value': 'good-value'},
          status=httplib.BAD_REQUEST)

  def testInsufficientPermissions(self):
    with self.LoggedInUser():
      self.testapp.post(
          self.ROUTE % 'bit9', {'value': 'abc'}, status=httplib.FORBIDDEN)


if __name__ == '__main__':
  basetest.main()
