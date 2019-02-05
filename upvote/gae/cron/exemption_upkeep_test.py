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

"""Unit tests for exemptions.py."""

import datetime
import httplib

import mock
import webapp2

from google.appengine.api import memcache

from upvote.gae.cron import exemption_upkeep
from upvote.gae.datastore import test_utils
from upvote.gae.lib.testing import basetest
from upvote.gae.utils import env_utils
from upvote.gae.utils import user_utils
from upvote.shared import constants


class ProcessExemptionsTest(basetest.UpvoteTestCase):

  ROUTE = '/exemptions/process'

  def setUp(self):
    app = webapp2.WSGIApplication(routes=[exemption_upkeep.ROUTES])
    super(ProcessExemptionsTest, self).setUp(wsgi_app=app)

  @mock.patch.object(exemption_upkeep.monitoring, 'requested_exemptions')
  def testSuccess(self, mock_metric):

    deactivation_dt = datetime.datetime.utcnow() + datetime.timedelta(days=1)
    exm_count = 5
    expected_exm_keys = []
    for host_id in test_utils.RandomStrings(exm_count):
      exm_key = test_utils.CreateExemption(
          host_id, deactivation_dt=deactivation_dt)
      expected_exm_keys.append(exm_key)

    self.testapp.get(
        self.ROUTE, headers={'X-AppEngine-Cron': 'true'}, status=httplib.OK)
    tasks = self.UnpackTaskQueue(queue_name=constants.TASK_QUEUE.EXEMPTIONS)
    actual_exm_keys = {args[0] for func, args, kwargs in tasks}
    self.assertSameElements(expected_exm_keys, actual_exm_keys)

    self.assertNoBigQueryInsertions()
    mock_metric.Set.assert_called_once_with(exm_count)


class NotifyExpirationsInRangeTest(basetest.UpvoteTestCase):

  @mock.patch.object(exemption_upkeep.notify, 'SendExpirationEmail')
  def testSuccess(self, mock_send):

    # Create a number of APPROVED Exemptions that expire at different times.
    deactivation_dts = [datetime.datetime(2018, 12, 19, h) for h in xrange(10)]
    for deactivation_dt in deactivation_dts:
      host = test_utils.CreateSantaHost()
      test_utils.CreateExemption(
          host.key.id(), initial_state=constants.EXEMPTION_STATE.APPROVED,
          deactivation_dt=deactivation_dt)

    start_dt = datetime.datetime(2018, 12, 19, 3)
    end_dt = datetime.datetime(2018, 12, 19, 7)
    exemption_upkeep._NotifyExpirationsInRange(start_dt, end_dt)

    self.assertEqual(4, mock_send.call_count)


class NotifyUpcomingExpirationsTest(basetest.UpvoteTestCase):

  ROUTE = '/exemptions/notify-upcoming-expirations'

  def setUp(self):
    app = webapp2.WSGIApplication(routes=[exemption_upkeep.ROUTES])
    super(NotifyUpcomingExpirationsTest, self).setUp(wsgi_app=app)

  def testSuccess(self):
    self.assertTaskCount(constants.TASK_QUEUE.EXEMPTIONS, 0)
    self.testapp.get(
        self.ROUTE, headers={'X-AppEngine-Cron': 'true'}, status=httplib.OK)
    self.assertTaskCount(constants.TASK_QUEUE.EXEMPTIONS, 2)


class ExpireExemptionsTest(basetest.UpvoteTestCase):

  ROUTE = '/exemptions/expire'

  def setUp(self):
    app = webapp2.WSGIApplication(routes=[exemption_upkeep.ROUTES])
    super(ExpireExemptionsTest, self).setUp(wsgi_app=app)

  @mock.patch.object(exemption_upkeep.monitoring, 'expired_exemptions')
  def testSuccess(self, mock_metric):

    non_expired_dt = datetime.datetime.utcnow() + datetime.timedelta(days=1)
    test_utils.CreateExemption(
        'non_expired_host_id',
        deactivation_dt=non_expired_dt,
        initial_state=constants.EXEMPTION_STATE.APPROVED)

    expired_dt = datetime.datetime.utcnow() - datetime.timedelta(days=1)
    exm_count = 7
    expired_exm_keys = []
    for host_id in test_utils.RandomStrings(exm_count):
      exm_key = test_utils.CreateExemption(
          host_id, deactivation_dt=expired_dt,
          initial_state=constants.EXEMPTION_STATE.APPROVED)
      expired_exm_keys.append(exm_key)

    self.testapp.get(
        self.ROUTE, headers={'X-AppEngine-Cron': 'true'}, status=httplib.OK)
    tasks = self.UnpackTaskQueue(queue_name=constants.TASK_QUEUE.EXEMPTIONS)
    # keys = {args[0] for func, args, kwargs in tasks}
    actual_exm_keys = {args[0] for func, args, kwargs in tasks}
    self.assertSameElements(expired_exm_keys, actual_exm_keys)

    self.assertNoBigQueryInsertions()
    mock_metric.Set.assert_called_once_with(exm_count)


if __name__ == '__main__':
  basetest.main()
