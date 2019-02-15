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

import httplib

import upvote.gae.lib.cloud.google_cloud_lib_fixer  # pylint: disable=unused-import
# pylint: disable=g-bad-import-order,g-import-not-at-top

import mock
import webapp2

from google.appengine.api import urlfetch
from upvote.gae.cron import datastore_backup
from upvote.gae.lib.testing import basetest
from upvote.gae import settings
from upvote.gae.utils import env_utils


class DatastoreBackupTest(basetest.UpvoteTestCase):

  ROUTE = '/datastore/backup'

  def setUp(self):

    app = webapp2.WSGIApplication(routes=[datastore_backup.ROUTES])
    super(DatastoreBackupTest, self).setUp(wsgi_app=app)

    self.mock_metric = mock.Mock(spec=datastore_backup.monitoring_utils.Counter)
    patcher = mock.patch.dict(
        datastore_backup.__dict__,
        _DATASTORE_BACKUPS=self.mock_metric)
    self.addCleanup(patcher.stop)
    patcher.start()

  def testNotInProd(self):
    self.Patch(datastore_backup.env_utils, 'RunningInProd', return_value=False)
    self.testapp.get(
        self.ROUTE, headers={'X-AppEngine-Cron': 'true'}, expect_errors=True,
        status=httplib.FORBIDDEN)
    self.mock_metric.Increment.assert_not_called()

  @mock.patch.object(datastore_backup.urlfetch, 'fetch')
  @mock.patch.object(
      env_utils, 'CurrentEnvironment', return_value=settings.ProdEnv)
  @mock.patch.object(env_utils, 'RunningInProd', return_value=True)
  def testSuccessfulBackup(self, mock_prod, mock_env, mock_fetch):

    mock_result = mock.Mock(status_code=httplib.OK)
    mock_fetch.return_value = mock_result

    self.testapp.get(
        self.ROUTE, headers={'X-AppEngine-Cron': 'true'}, status=httplib.OK)

    self.mock_metric.Increment.assert_called_once()

  @mock.patch.object(datastore_backup.urlfetch, 'fetch')
  @mock.patch.object(
      env_utils, 'CurrentEnvironment', return_value=settings.ProdEnv)
  @mock.patch.object(env_utils, 'RunningInProd', return_value=True)
  def testUnsuccessfulBackup(self, mock_prod, mock_env, mock_fetch):

    mock_result = mock.Mock(status_code=httplib.BAD_REQUEST)
    mock_fetch.return_value = mock_result

    self.testapp.get(
        self.ROUTE, headers={'X-AppEngine-Cron': 'true'},
        status=httplib.BAD_REQUEST)

    self.mock_metric.Increment.assert_not_called()

  @mock.patch.object(datastore_backup.urlfetch, 'fetch')
  @mock.patch.object(
      env_utils, 'CurrentEnvironment', return_value=settings.ProdEnv)
  @mock.patch.object(env_utils, 'RunningInProd', return_value=True)
  def testException(self, mock_prod, mock_env, mock_fetch):

    mock_fetch.side_effect = urlfetch.Error

    self.testapp.get(
        self.ROUTE, headers={'X-AppEngine-Cron': 'true'},
        status=httplib.INTERNAL_SERVER_ERROR)

    self.mock_metric.Increment.assert_not_called()


if __name__ == '__main__':
  basetest.main()
