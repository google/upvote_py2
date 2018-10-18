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

"""Unit tests for datastore_backup.py."""

import datetime
import httplib

import upvote.gae.shared.common.google_cloud_lib_fixer  # pylint: disable=unused-import
# pylint: disable=g-bad-import-order,g-import-not-at-top

import mock
import webapp2

from google.appengine.api import taskqueue
from google.appengine.ext import db
from upvote.gae.cron import datastore_backup
from upvote.gae.lib.testing import basetest
from upvote.gae.shared.common import settings
from upvote.gae.shared.common import settings_utils
from upvote.gae.utils import env_utils


class FakeBackup(db.Model):
  name = db.ByteStringProperty()
  complete_time = db.DateTimeProperty()

  @classmethod
  def kind(cls):
    return '_AE_Backup_Information'


class DatastoreBackupTest(basetest.UpvoteTestCase):

  ROUTE = '/datastore/backup'

  def setUp(self):
    app = webapp2.WSGIApplication(routes=[datastore_backup.ROUTES])
    super(DatastoreBackupTest, self).setUp(wsgi_app=app)
    self.date1 = datetime.datetime.utcnow()
    self.date2 = datetime.datetime(2012, 12, 12, 8, 45)
    todaystr1 = self.date1.strftime('%Y_%m_%d')
    todaystr2 = self.date2.strftime('%Y_%m_%d')
    self.expected_name1 = '%s_%s' % (datastore_backup._BACKUP_PREFIX, todaystr1)
    self.expected_name2 = '%s_%s' % (datastore_backup._BACKUP_PREFIX, todaystr2)

  def testInProd_Cron(self):
    self.Patch(datastore_backup.env_utils, 'RunningInProd', return_value=True)
    self.Logout()  # Ensures that get_current_user() returns None.
    self.testapp.get(self.ROUTE, status=httplib.OK)

  def testInProd_AuthorizedUser(self):
    self.Patch(datastore_backup.env_utils, 'RunningInProd', return_value=True)
    with self.LoggedInUser(admin=True):
      self.testapp.get(self.ROUTE, status=httplib.OK)

  def testInProd_UnauthorizedUser(self):
    self.Patch(datastore_backup.env_utils, 'RunningInProd', return_value=True)
    with self.LoggedInUser():
      self.testapp.get(self.ROUTE, expect_errors=True, status=httplib.FORBIDDEN)

  def testNotInProd_Cron(self):
    self.Patch(datastore_backup.env_utils, 'RunningInProd', return_value=False)
    self.Logout()  # Ensures that get_current_user() returns None.
    self.testapp.get(self.ROUTE, expect_errors=True, status=httplib.FORBIDDEN)

  def testNotInProd_Authorized(self):
    self.Patch(datastore_backup.env_utils, 'RunningInProd', return_value=False)
    with self.LoggedInUser(admin=True):
      self.testapp.get(self.ROUTE, status=httplib.OK)

  def testNotInProd_Unauthorized(self):
    self.Patch(datastore_backup.env_utils, 'RunningInProd', return_value=False)
    with self.LoggedInUser():
      self.testapp.get(self.ROUTE, expect_errors=True, status=httplib.FORBIDDEN)

  def testNoDailyBackupExists(self):
    self.assertFalse(datastore_backup._DailyBackupExists())

  def testDailyBackupExists(self):
    FakeBackup(name=self.expected_name1, complete_time=self.date1).put()
    self.assertTrue(datastore_backup._DailyBackupExists())

  @mock.patch.object(taskqueue, 'add')
  @mock.patch.object(datastore_backup, '_DailyBackupExists', return_value=True)
  @mock.patch.object(
      datastore_backup.users, 'get_current_user', return_value=None)
  @mock.patch.object(env_utils, 'RunningInProd', return_value=True)
  def testBackupExists(self, mock_prod, mock_user, mock_exists, mock_add):
    self.testapp.get(self.ROUTE, status=httplib.OK)
    self.assertEqual(0, mock_add.call_count)

  @mock.patch.object(taskqueue, 'add')
  @mock.patch.object(
      settings_utils, 'CurrentEnvironment', return_value=settings.ProdEnv)
  @mock.patch.object(datastore_backup, '_DailyBackupExists', return_value=False)
  @mock.patch.object(
      datastore_backup.users, 'get_current_user', return_value=None)
  @mock.patch.object(env_utils, 'RunningInProd', return_value=True)
  def testSuccessfulBackup(
      self, mock_prod, mock_user, mock_exists, mock_env, mock_add):
    self.testapp.get(self.ROUTE, status=httplib.OK)
    self.assertEqual(1, mock_add.call_count)


if __name__ == '__main__':
  basetest.main()
