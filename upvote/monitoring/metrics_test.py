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

from absl.testing import absltest
from upvote.monitoring import metrics


class MetricTest(absltest.TestCase):

  def testStr(self):
    metric_name = '/some/test/metric'
    metric = metrics.Metric(metric_name, 'Display Name')
    self.assertEqual(metric_name, str(metric))


class MetricNamespaceTest(absltest.TestCase):

  def testSantaApi(self):
    self.assertEqual(6, len(metrics.SANTA_API.ALL))

  def testBit9Api(self):
    self.assertEqual(12, len(metrics.BIT9_API.ALL))

  def testBit9RestApi(self):
    self.assertEqual(3, len(metrics.BIT9_REST_API.ALL))

  def testUpvoteApp(self):
    self.assertEqual(10, len(metrics.UPVOTE_APP.ALL))

  def testBinaryHealth(self):
    self.assertEqual(2, len(metrics.ANALYSIS.ALL))

  def testBigQuery(self):
    self.assertEqual(1, len(metrics.BIGQUERY.ALL))

  def testRpcServer(self):
    self.assertEqual(3, len(metrics.RPC_SERVER.ALL))

  def testPresence(self):
    self.assertEqual(1, len(metrics.PRESENCE.ALL))


if __name__ == '__main__':
  absltest.main()
