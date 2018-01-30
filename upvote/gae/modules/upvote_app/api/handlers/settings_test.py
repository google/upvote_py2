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

from upvote.gae.modules.upvote_app.api.handlers import settings
from upvote.gae.shared.common import basetest


class SettingsTest(basetest.UpvoteTestCase):
  """Test Settings Handler Class."""

  def setUp(self):
    app = webapp2.WSGIApplication(
        [webapp2.Route(r'/<setting>', handler=settings.Settings)])
    super(SettingsTest, self).setUp(wsgi_app=app)

    settings.settings.READY_TO_MOVE_OUT = 'Ready'

    self.PatchValidateXSRFToken()

  def testGet(self):
    """Admin getting a value."""

    with self.LoggedInUser():
      response = self.testapp.get('/ready_to_move_out')

    output = response.json

    self.assertIn('application/json', response.headers['Content-type'])
    self.assertEqual('Ready', output)

  def testGet_DoesntExist(self):
    """Admin querying for a setting value that does not exist."""

    with self.LoggedInUser():
      self.testapp.get(
          '/spidey_sense_tingling', status=httplib.NOT_FOUND)


class ApiKeysTest(basetest.UpvoteTestCase):
  """Test Settings Handler Class."""

  def setUp(self):
    app = webapp2.WSGIApplication(
        [webapp2.Route(r'/<key_name>', handler=settings.ApiKeys)])
    super(ApiKeysTest, self).setUp(wsgi_app=app)

    self.PatchValidateXSRFToken()

  def testUpdateVirusTotalKey(self):
    with mock.patch.object(
        settings.virustotal.VirusTotalApiAuth, 'SetInstance') as mock_set:
      with self.LoggedInUser(admin=True):
        self.testapp.post('/virustotal', {'value': 'abc'})
      mock_set.assert_called_once_with(api_key='abc')

  def testUpdateBit9Key(self):
    with mock.patch.object(
        settings.bit9.Bit9ApiAuth, 'SetInstance') as mock_set:
      with self.LoggedInUser(admin=True):
        self.testapp.post('/bit9', {'value': 'abc'})
      mock_set.assert_called_once_with(api_key='abc')

  def testBadValue(self):
    with self.LoggedInUser(admin=True):
      self.testapp.post('/virustotal', {}, status=httplib.BAD_REQUEST)

  def testBadKeyName(self):
    with self.LoggedInUser(admin=True):
      self.testapp.post(
          '/not-a-key', {'value': 'good-value'}, status=httplib.BAD_REQUEST)

  def testInsufficientPermissions(self):
    with self.LoggedInUser():
      self.testapp.post('/bit9', {'value': 'abc'}, status=httplib.FORBIDDEN)


if __name__ == '__main__':
  basetest.main()
