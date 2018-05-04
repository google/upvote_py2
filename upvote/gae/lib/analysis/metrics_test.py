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

"""Unit tests for metrics.py."""

import mock

from upvote.gae.datastore import test_utils
from upvote.gae.datastore.models import metrics as metrics_db
from upvote.gae.lib.analysis import metrics
from upvote.gae.lib.analysis.virustotal import constants as vt_constants
from upvote.gae.shared.common import basetest
from upvote.shared import constants


@mock.patch.object(metrics.monitoring, 'virustotal_new_lookups')
@mock.patch.object(
    metrics.analysis, 'VirusTotalLookup',
    return_value={'response_code': 0})
class MetricsTest(basetest.UpvoteTestCase):

  def setUp(self):
    super(MetricsTest, self).setUp()

    self.PatchSetting('ENABLE_BINARY_ANALYSIS_PRECACHING', True)

  def testCollectLookup(self, mock_vt_lookup, mock_metric):
    expected_state = vt_constants.ANALYSIS_STATE.MAP_FROM_RESPONSE_CODE[0]
    test_utils.CreateSantaBlockable(id='foo')

    metrics.CollectLookup('foo', constants.ANALYSIS_REASON.NEW_BLOCKABLE)

    metric = metrics_db.VirusTotalAnalysisMetric.query().get()
    self.assertEqual('foo', metric.blockable_id)
    self.assertEqual(constants.PLATFORM.MACOS, metric.platform)
    self.assertEqual(expected_state, metric.analysis_state)
    self.assertEqual(
        constants.ANALYSIS_REASON.NEW_BLOCKABLE, metric.analysis_reason)
    self.assertEqual(-1, metric.positives)

    mock_metric.Increment.assert_called_once_with(expected_state)

  def testCollectLookup_Bit9Blockable(self, *_):
    test_utils.CreateBit9Binary(id='foo')

    metrics.CollectLookup('foo', constants.ANALYSIS_REASON.NEW_BLOCKABLE)

    metric = metrics_db.VirusTotalAnalysisMetric.query().get()
    self.assertEqual(constants.PLATFORM.WINDOWS, metric.platform)

  def testCollectLookup_BadBlockable(self, *_):
    with self.assertRaises(ValueError):
      metrics.CollectLookup(
          'foo', constants.ANALYSIS_REASON.NEW_BLOCKABLE)

  def testDeferLookupMetric(self, mock_vt_lookup, _):
    test_utils.CreateSantaBlockable(id='foo')

    metrics.DeferLookupMetric('foo', constants.ANALYSIS_REASON.NEW_BLOCKABLE)

    self.assertTaskCount(constants.TASK_QUEUE.METRICS, 1)
    self.RunDeferredTasks(constants.TASK_QUEUE.METRICS)

    mock_vt_lookup.assert_called_once_with('foo')


if __name__ == '__main__':
  basetest.main()
