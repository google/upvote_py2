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

"""Unit tests for Audit Logs handlers."""

import httplib

import webapp2

from upvote.gae.modules.upvote_app.api.handlers import auditlogs
from upvote.gae.shared.common import basetest
from upvote.gae.shared.models import base as base_db
from upvote.gae.shared.models import test_utils


class AuditLogsTest(basetest.UpvoteTestCase):
  """Base class for Audit Logs handler tests."""

  def setUp(self, app):
    super(AuditLogsTest, self).setUp(wsgi_app=app)

    self.user = test_utils.CreateUser()

    self.auditlog_1 = base_db.AuditLog(
        id=123456,
        log_event='Something happened.',
        user=self.user.email,
        target_object_key=self.user.key)

    self.auditlog_2 = base_db.AuditLog(
        id=123457,
        log_event='Another thing happened.',
        user=self.user.email,
        target_object_key=self.user.key)

    self.auditlog_3 = base_db.AuditLog(
        id=123458,
        log_event='And this happened.',
        user=self.user.email,
        target_object_key=self.user.key)

    self.auditlog_1.put()
    self.auditlog_2.put()
    self.auditlog_3.put()


class AuditLogQueryHandlerTest(AuditLogsTest):
  """Test AuditLogQueryHandler class."""

  def setUp(self):
    app = webapp2.WSGIApplication(
        [webapp2.Route(r'', handler=auditlogs.AuditLogQueryHandler)])
    super(AuditLogQueryHandlerTest, self).setUp(app)

  def testAdminGetList(self):
    """Admin gets a list of all audit logs."""
    with self.LoggedInUser(admin=True):
      response = self.testapp.get('')

    output = response.json

    self.assertIn('application/json', response.headers['Content-type'])
    self.assertIsInstance(output, dict)
    self.assertIsInstance(output['content'], list)
    self.assertEqual(len(output['content']), 3)

  def testUserGetListNoPermissions(self):
    """Unprivileged user attempts to get a list of all audit logs."""
    with self.LoggedInUser():
      self.testapp.get('', status=httplib.FORBIDDEN)

  def testAdminGetQuery(self):
    """Admin queries for an audit log."""
    params = {
        'search': self.auditlog_1.log_event,
        'searchBase': 'logEvent'}
    with self.LoggedInUser(admin=True):
      response = self.testapp.get('', params)

    output = response.json

    self.assertIn('application/json', response.headers['Content-type'])
    self.assertIsInstance(output, dict)
    self.assertIsInstance(output['content'], list)
    self.assertEqual(len(output['content']), 1)

  def testAdminGetQueryBadField(self):
    """Admin queries for a auditlogs with an invalid field."""
    params = {
        'search': 'DoesntMatter',
        'searchBase': 'NotAField'}

    with self.LoggedInUser(admin=True):
      self.testapp.get('', params=params, status=httplib.BAD_REQUEST)


class AuditLogHandlerTest(AuditLogsTest):
  """Test AuditLogHandler class."""

  def setUp(self):
    app = webapp2.WSGIApplication(
        [webapp2.Route(r'/<log_id>', handler=auditlogs.AuditLogHandler)])
    super(AuditLogHandlerTest, self).setUp(app)

  def testAdminGetID(self):
    """Admin gets a single audit log by ID."""
    with self.LoggedInUser(admin=True):
      response = self.testapp.get('/%s' % self.auditlog_1.key.id())

    output = response.json

    self.assertIn('application/json', response.headers['Content-type'])
    self.assertIsInstance(output, dict)
    # NOTE: The keys are the object properies converted to camelCase
    self.assertEqual(output['logEvent'], self.auditlog_1.log_event)

  def testAdminGetUnknownID(self):
    """Admin gets unknown audit log by ID."""
    with self.LoggedInUser(admin=True):
      self.testapp.get('/999999', status=httplib.NOT_FOUND)

  def testAdminGetBadID(self):
    """Admin gets audit log by non-numeric ID."""
    with self.LoggedInUser(admin=True):
      self.testapp.get('/ThisIsNotANumber', status=httplib.BAD_REQUEST)


if __name__ == '__main__':
  basetest.main()
