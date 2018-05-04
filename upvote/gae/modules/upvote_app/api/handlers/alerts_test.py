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

"""Unit tests for alert handlers."""

import datetime
import httplib
import json
import webapp2

from google.appengine.api import memcache
from google.appengine.ext import ndb

from upvote.gae.datastore import test_utils
from upvote.gae.datastore.models import alert
from upvote.gae.modules.upvote_app.api.handlers import alerts
from upvote.gae.shared.common import basetest
from upvote.gae.shared.common import json_utils
from upvote.shared import constants


def _CreateAlert(
    start_hours, end_hours=None, scope=constants.SITE_ALERT_SCOPE.APPDETAIL,
    platform=constants.SITE_ALERT_PLATFORM.WINDOWS, **kwargs):

  now = datetime.datetime.utcnow()
  start_date = now + datetime.timedelta(hours=start_hours)
  end_date = now + datetime.timedelta(hours=end_hours) if end_hours else None

  return test_utils.CreateAlert(
      start_date=start_date, end_date=end_date, scope=scope, platform=platform,
      **kwargs)


class CreateMemcacheKeyTest(basetest.UpvoteTestCase):

  def testSuccess(self):
    expected_key = 'alert_appdetail_windows'
    actual_key = alerts._CreateMemcacheKey(
        constants.SITE_ALERT_SCOPE.APPDETAIL,
        platform=constants.SITE_ALERT_PLATFORM.WINDOWS)
    self.assertEqual(expected_key, actual_key)


class AlertHandlerTest(basetest.UpvoteTestCase):

  ROUTE = '/alert/appdetail/windows'

  def assertResponseContains(self, response, alert_dict):
    encoder = json_utils.JSONEncoderJavaScript()
    expected_content = json.loads(encoder.encode(alert_dict))
    actual_content = json.loads(response.body)
    self.assertEqual(expected_content, actual_content)

  def setUp(self):
    app = webapp2.WSGIApplication(routes=[alerts.ROUTES])
    super(AlertHandlerTest, self).setUp(wsgi_app=app)

  def testGet_InvalidScope(self):
    with self.LoggedInUser():
      response = self.testapp.get(
          '/alert/blah/macos', expect_errors=True)

    self.assertEqual(httplib.BAD_REQUEST, response.status_int)
    self.assertMemcacheLacks(alerts._CreateMemcacheKey('blah', 'macos'))

  def testGet_InvalidPlatform(self):
    with self.LoggedInUser():
      response = self.testapp.get('/alert/appdetail/xbox', expect_errors=True)

    self.assertEqual(httplib.BAD_REQUEST, response.status_int)
    self.assertMemcacheLacks(alerts._CreateMemcacheKey('appdetail', 'xbox'))

  def testGet_InMemcache(self):

    # Create an active Alert and stuff it in Memcache.
    alert_dict = _CreateAlert(-5, end_hours=5).to_dict()
    memcache.set(alerts._CreateMemcacheKey('appdetail', 'windows'), alert_dict)

    with self.LoggedInUser():
      response = self.testapp.get(self.ROUTE)

    self.assertEqual(httplib.OK, response.status_int)
    self.assertResponseContains(response, alert_dict)

  def testGet_InPast(self):

    # Create a limited-duration Alert which has already expired.
    _CreateAlert(-20, end_hours=-10).put()
    self.assertEntityCount(alert.Alert, 1)

    with self.LoggedInUser():
      response = self.testapp.get(self.ROUTE)

    self.assertEntityCount(alert.Alert, 0)
    self.assertMemcacheContains(
        alerts._CreateMemcacheKey('appdetail', 'windows'), {})
    self.assertEqual(httplib.OK, response.status_int)
    self.assertResponseContains(response, {})

  def testGet_InFuture(self):

    # Create a limited-duration Alert which is upcoming.
    _CreateAlert(10, end_hours=20).put()
    self.assertEntityCount(alert.Alert, 1)

    with self.LoggedInUser():
      response = self.testapp.get(self.ROUTE)

    self.assertEntityCount(alert.Alert, 1)
    self.assertMemcacheContains(
        alerts._CreateMemcacheKey('appdetail', 'windows'), {})
    self.assertEqual(httplib.OK, response.status_int)
    self.assertResponseContains(response, {})

  def testGet_Active_LimitedDuration(self):

    # Create a limited-duration Alert which is active.
    alert_entity = _CreateAlert(-5, end_hours=5)
    alert_entity.put()
    self.assertEntityCount(alert.Alert, 1)

    with self.LoggedInUser():
      response = self.testapp.get(self.ROUTE)

    alert_dict = alert_entity.to_dict()

    self.assertEntityCount(alert.Alert, 1)
    self.assertMemcacheContains(
        alerts._CreateMemcacheKey('appdetail', 'windows'), alert_dict)
    self.assertEqual(httplib.OK, response.status_int)
    self.assertResponseContains(response, alert_dict)

  def testGet_Active_IndefiniteDuration(self):

    # Create an indefinite-duration Alert which is active.
    alert_entity = _CreateAlert(-5)
    alert_entity.put()
    self.assertEntityCount(alert.Alert, 1)

    with self.LoggedInUser():
      response = self.testapp.get(self.ROUTE)

    alert_dict = alert_entity.to_dict()

    self.assertEntityCount(alert.Alert, 1)
    self.assertMemcacheContains(
        alerts._CreateMemcacheKey('appdetail', 'windows'), alert_dict)
    self.assertEqual(httplib.OK, response.status_int)
    self.assertResponseContains(response, alert_dict)

  def testGet_Active_MultipleOverlapping(self):

    # Create two active Alerts which overlap at the current time.
    alert_entity_1 = _CreateAlert(-10)
    alert_entity_2 = _CreateAlert(-5, end_hours=5)
    ndb.put_multi([alert_entity_1, alert_entity_2])
    self.assertEntityCount(alert.Alert, 2)

    with self.LoggedInUser():
      response = self.testapp.get(self.ROUTE)

    alert_dict = alert_entity_2.to_dict()

    self.assertEntityCount(alert.Alert, 2)
    self.assertMemcacheContains(
        alerts._CreateMemcacheKey('appdetail', 'windows'), alert_dict)
    self.assertEqual(httplib.OK, response.status_int)
    self.assertResponseContains(response, alert_dict)

  def testGet_Active_AllScopes(self):

    # Create an active Alert for all scopes.
    alert_entity = _CreateAlert(
        -5, end_hours=5, scope=constants.SITE_ALERT_SCOPE.EVERYWHERE)
    alert_entity.put()
    alert_dict = alert_entity.to_dict()

    for scope in constants.SITE_ALERT_SCOPE.SET_ALL:
      route = '/alert/%s/windows' % scope
      with self.LoggedInUser():
        response = self.testapp.get(route)

      self.assertMemcacheContains(
          alerts._CreateMemcacheKey(scope, 'windows'), alert_dict)
      self.assertEqual(httplib.OK, response.status_int)
      self.assertResponseContains(response, alert_dict)

  def testGet_Active_AllPlatforms(self):

    # Create an active Alert for all platforms.
    alert_entity = _CreateAlert(
        -5, end_hours=5, platform=constants.SITE_ALERT_PLATFORM.ALL)
    alert_entity.put()
    alert_dict = alert_entity.to_dict()

    for platform in constants.SITE_ALERT_PLATFORM.SET_ALL:
      route = '/alert/appdetail/%s' % platform
      with self.LoggedInUser():
        response = self.testapp.get(route)

      self.assertMemcacheContains(
          alerts._CreateMemcacheKey('appdetail', platform), alert_dict)
      self.assertEqual(httplib.OK, response.status_int)
      self.assertResponseContains(response, alert_dict)


if __name__ == '__main__':
  basetest.main()
