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

from upvote.gae.shared.common import basetest
from upvote.gae.shared.models import bigquery
from upvote.shared import constants


class BigQueryTest(basetest.UpvoteTestCase):

  def setUp(self):
    super(BigQueryTest, self).setUp()
    self.sha256 = 'chachacha'
    self.timestamp = datetime.datetime.utcnow()
    self.upvote = True
    self.weight = 123
    self.platform = constants.PLATFORM.MACOS
    self.target_type = constants.RULE_TYPE.BINARY
    self.voter = 'Farren'

  def verifyRow(self):
    rows = bigquery.VoteRow.query().fetch()
    self.assertEqual(1, len(rows))
    row = rows[0]
    self.assertEqual(self.sha256, row.sha256)
    self.assertEqual(self.timestamp, row.timestamp)
    self.assertEqual(self.upvote, row.upvote)
    self.assertEqual(self.weight, row.weight)
    self.assertEqual(self.platform, row.platform)
    self.assertEqual(self.target_type, row.target_type)
    self.assertEqual(self.voter, row.voter)

  @mock.patch.object(bigquery, '_PERSISTED_METRIC')
  def testCreate(self, mock_metric):
    bigquery.VoteRow.Create(
        sha256=self.sha256,
        timestamp=self.timestamp,
        upvote=self.upvote,
        weight=self.weight,
        platform=self.platform,
        target_type=self.target_type,
        voter=self.voter)
    self.verifyRow()
    self.assertEqual(1, mock_metric.Increment.call_count)

  @mock.patch.object(bigquery, '_PERSISTED_METRIC')
  def testCreateAsync(self, mock_metric):
    result = bigquery.VoteRow.CreateAsync(
        sha256=self.sha256,
        timestamp=self.timestamp,
        upvote=self.upvote,
        weight=self.weight,
        platform=self.platform,
        target_type=self.target_type,
        voter=self.voter)
    result.get_result()
    self.verifyRow()
    self.assertEqual(1, mock_metric.Increment.call_count)

  @mock.patch.object(bigquery, '_PERSISTED_METRIC')
  def testDeferCreate(self, mock_metric):
    bigquery.VoteRow.DeferCreate(
        sha256=self.sha256,
        timestamp=self.timestamp,
        upvote=self.upvote,
        weight=self.weight,
        platform=self.platform,
        target_type=self.target_type,
        voter=self.voter)
    self.assertTaskCount(constants.TASK_QUEUE.BQ_PERSISTENCE, 1)
    self.RunDeferredTasks(constants.TASK_QUEUE.BQ_PERSISTENCE)
    self.assertEntityCount(bigquery.VoteRow, 1)
    self.assertEqual(1, mock_metric.Increment.call_count)


if __name__ == '__main__':
  basetest.main()
