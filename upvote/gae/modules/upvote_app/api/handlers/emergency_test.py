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

"""Unit tests for emergency.py."""

import mock

import webapp2

from upvote.gae.modules.upvote_app.api.handlers import emergency
from upvote.gae.shared.common import basetest


class EmergencyTest(basetest.UpvoteTestCase):
  """This is a test of the emergency handler system."""

  def setUp(self):
    app = webapp2.WSGIApplication([
        webapp2.Route(r'', handler=emergency.Emergency)])
    super(EmergencyTest, self).setUp(wsgi_app=app)

    self.PatchValidateXSRFToken()

  def testGet(self):
    mock_brb = mock.MagicMock()
    with self.LoggedInUser(admin=True):
      with mock.patch.object(emergency.big_red, 'BigRedButton',
                             return_value=mock_brb):
        mock_brb.get_button_status.return_value = {'it_worked': True}
        response = self.testapp.get('')

    self.assertIn('application/json', response.headers['Content-type'])
    self.assertIsInstance(response.json, dict)
    self.assertEqual(response.json['itWorked'], True)

  def master_button_tester(self, button_name, button_value, test_call):
    mock_brb = mock.MagicMock()
    with self.LoggedInUser(admin=True):
      with mock.patch.object(emergency.big_red, 'BigRedButton',
                             return_value=mock_brb):
        mock_brb.get_button_status.return_value = {'it_worked': True}
        response = self.testapp.post('', params={button_name: button_value})

    mock_brb.assert_has_calls([test_call])
    self.assertIn('application/json', response.headers['Content-type'])
    self.assertIsInstance(response.json, dict)
    self.assertEqual(response.json['itWorked'], True)

  def testPressBigRedButton(self):
    self.master_button_tester(
        'bigRedButton', 'true', mock.call.turn_on_big_red_button())

  def testUnPressBigRedButton(self):
    self.master_button_tester(
        'bigRedButton', 'false', mock.call.turn_everything_off())

  def testSetStop1(self):
    self.master_button_tester(
        'bigRedButtonStop1', 'true', mock.call.turn_on_stop1())

  def testSetStop2(self):
    self.master_button_tester(
        'bigRedButtonStop2', 'true', mock.call.turn_on_stop2())

  def testSetGo1(self):
    self.master_button_tester(
        'bigRedButtonGo1', 'true', mock.call.turn_on_go1())

  def testSetGo2(self):
    self.master_button_tester(
        'bigRedButtonGo2', 'true', mock.call.turn_on_go2())


if __name__ == '__main__':
  basetest.main()
