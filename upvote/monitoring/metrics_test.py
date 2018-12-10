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

from upvote.monitoring import metrics
from absl.testing import absltest


class MetricTest(absltest.TestCase):

  def testStr(self):
    metric_name = '/some/test/metric'
    metric = metrics.Metric(metric_name, 'Display Name')
    self.assertEqual(metric_name, str(metric))


class MetricNamespaceTest(absltest.TestCase):

  def testDatastore(self):
    self.assertLen(metrics.DATASTORE.ALL, 1)

  def testSantaApi(self):
    self.assertLen(metrics.SANTA_API.ALL, 6)

  def testBit9Api(self):
    self.assertLen(metrics.BIT9_API.ALL, 11)

  def testBit9RestApi(self):
    self.assertLen(metrics.BIT9_REST_API.ALL, 3)

  def testUpvoteApp(self):
    self.assertLen(metrics.UPVOTE_APP.ALL, 9)

  def testBinaryHealth(self):
    self.assertLen(metrics.ANALYSIS.ALL, 2)

  def testBigQuery(self):
    self.assertLen(metrics.BIGQUERY.ALL, 1)

  def testExemption(self):
    self.assertLen(metrics.EXEMPTION.ALL, 1)

  def testRpcServer(self):
    self.assertLen(metrics.RPC_SERVER.ALL, 3)

  def testPresence(self):
    self.assertLen(metrics.PRESENCE.ALL, 1)


if __name__ == '__main__':
  absltest.main()
