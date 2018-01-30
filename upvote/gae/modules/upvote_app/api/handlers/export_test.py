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

"""Unit tests for export.py."""

import httplib

import upvote.gae.shared.common.google_cloud_lib_fixer  # pylint: disable=unused-import
# pylint: disable=g-bad-import-order,g-import-not-at-top
from google.cloud import bigquery
import mock
import webapp2

from upvote.gae.shared.common import basetest
from upvote.gae.modules.upvote_app.api.handlers import export
from upvote.gae.modules.upvote_app.lib import bigquery_schema


class InitializeBigqueryStreamingTest(basetest.UpvoteTestCase):

  def setUp(self):
    app = webapp2.WSGIApplication([('/', export.InitializeBigqueryStreaming)])
    super(InitializeBigqueryStreamingTest, self).setUp(wsgi_app=app)

  @mock.patch.object(
      bigquery.dataset.Dataset, 'exists', autospec=True,
      return_value=False)
  @mock.patch.object(
      bigquery.dataset.Dataset, 'create', autospec=True)
  @mock.patch.object(
      bigquery.table.Table, 'exists', autospec=True,
      return_value=False)
  @mock.patch.object(
      bigquery.table.Table, 'create', autospec=True)
  def testSuccess(
      self, mock_table_create, mock_table_exists, mock_dataset_create,
      mock_dataset_exists):

    with self.LoggedInUser(admin=True):
      response = self.testapp.get('/')

    self.assertEqual(httplib.OK, response.status_int)
    self.assertEqual(
        len(bigquery_schema.TABLE_SCHEMAS.keys()), mock_table_create.call_count)
    self.assertEqual(1, mock_dataset_create.call_count)

  @mock.patch.object(
      bigquery.dataset.Dataset, 'exists', autospec=True,
      return_value=False)
  @mock.patch.object(
      bigquery.dataset.Dataset, 'create', autospec=True)
  @mock.patch.object(
      bigquery.table.Table, 'exists', autospec=True,
      return_value=False)
  @mock.patch.object(
      bigquery.table.Table, 'create', autospec=True)
  def testFail_NotAdmin(self, *_):

    with self.LoggedInUser():
      self.testapp.get('/', status=httplib.FORBIDDEN)


if __name__ == '__main__':
  basetest.main()
