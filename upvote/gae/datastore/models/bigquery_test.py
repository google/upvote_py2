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

"""Tests for bigquery models."""

import datetime
import mock

from upvote.gae.datastore.models import bigquery
from upvote.gae.shared.common import basetest
from upvote.gae.shared.common import settings
from upvote.shared import constants


class BigQueryRowTest(basetest.UpvoteTestCase):

  def setUp(self):
    super(BigQueryRowTest, self).setUp()
    self.vote_args = {
        'sha256': 'abcdef',
        'timestamp': datetime.datetime.utcnow(),
        'upvote': True,
        'weight': 123,
        'platform': constants.PLATFORM.MACOS,
        'target_type': constants.RULE_TYPE.BINARY,
        'voter': 'foouser'}

    self.PatchEnv(settings.ProdEnv, ENABLE_BIGQUERY_STREAMING=True)

  @mock.patch.object(bigquery, '_PERSISTED_METRIC')
  def testCreate(self, mock_metric):

    self.assertEntityCount(bigquery.VoteRow, 0)

    key = bigquery.VoteRow.Create(**self.vote_args)

    self.assertIsNotNone(key)
    self.assertEntityCount(bigquery.VoteRow, 1)
    self.assertEqual(1, mock_metric.Increment.call_count)

  @mock.patch.object(bigquery, '_PERSISTED_METRIC')
  def testCreateAsync_Enabled(self, mock_metric):

    self.assertEntityCount(bigquery.VoteRow, 0)

    result = bigquery.VoteRow.CreateAsync(**self.vote_args)
    key = result.get_result()

    self.assertIsNotNone(key)
    self.assertEntityCount(bigquery.VoteRow, 1)
    self.assertEqual(1, mock_metric.Increment.call_count)

  @mock.patch.object(bigquery, '_PERSISTED_METRIC')
  def testCreateAsync_Disabled(self, mock_metric):

    self.PatchEnv(ENABLE_BIGQUERY_STREAMING=False)

    self.assertEntityCount(bigquery.VoteRow, 0)

    result = bigquery.VoteRow.CreateAsync(**self.vote_args)
    key = result.get_result()

    self.assertIsNone(key)
    self.assertEntityCount(bigquery.VoteRow, 0)
    self.assertEqual(0, mock_metric.Increment.call_count)

  @mock.patch.object(bigquery, '_PERSISTED_METRIC')
  def testDeferCreate(self, mock_metric):

    self.assertEntityCount(bigquery.VoteRow, 0)

    bigquery.VoteRow.DeferCreate(**self.vote_args)

    self.assertTaskCount(constants.TASK_QUEUE.BQ_PERSISTENCE, 1)
    self.RunDeferredTasks(constants.TASK_QUEUE.BQ_PERSISTENCE)
    self.assertEntityCount(bigquery.VoteRow, 1)
    self.assertEqual(1, mock_metric.Increment.call_count)


if __name__ == '__main__':
  basetest.main()
