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

"""Tests for bit9_api cron jobs."""

import datetime
import httplib

import mock
import webapp2

from google.appengine.ext import ndb

from absl.testing import absltest
from upvote.gae.datastore import test_utils
from upvote.gae.datastore.models import base as base_db
from upvote.gae.datastore.models import bit9 as bit9_db
from upvote.gae.modules.bit9_api import change_set
from upvote.gae.modules.bit9_api import cron
from upvote.gae.modules.bit9_api import sync
from upvote.gae.modules.bit9_api import utils
from upvote.gae.modules.bit9_api.api import api
from upvote.gae.shared.common import basetest
from upvote.gae.shared.common import user_map
from upvote.shared import constants


class CronTest(basetest.UpvoteTestCase):

  def setUp(self, **kwargs):
    super(CronTest, self).setUp(**kwargs)
    self.Patch(utils, 'CONTEXT')

  def _PatchApiRequests(self, *results):
    requests = []
    for batch in results:
      if isinstance(batch, list):
        requests.append([obj.to_raw_dict() for obj in batch])
      else:
        requests.append(batch.to_raw_dict())
    utils.CONTEXT.ExecuteRequest.side_effect = requests


class CommitAllChangeSetsTest(CronTest):

  def setUp(self):
    app = webapp2.WSGIApplication([
        webapp2.Route(
            '/', handler=cron.CommitAllChangeSets)])
    super(CommitAllChangeSetsTest, self).setUp(wsgi_app=app)

    self.binary = test_utils.CreateBit9Binary()
    self.change = test_utils.CreateRuleChangeSet(self.binary.key)

  @mock.patch.object(cron.monitoring, 'pending_changes')
  def testAll(self, mock_metric):
    other_binary = test_utils.CreateBit9Binary()
    # Create two changeset so we're sure we're doing only 1 task per blockable.
    real_change = test_utils.CreateRuleChangeSet(other_binary.key)
    unused_change = test_utils.CreateRuleChangeSet(other_binary.key)
    self.assertTrue(real_change.recorded_dt < unused_change.recorded_dt)

    self.testapp.get('/')

    self.assertEqual(2, mock_metric.Set.call_args_list[0][0][0])
    self.assertTaskCount(constants.TASK_QUEUE.BIT9_COMMIT_CHANGE, 2)
    with mock.patch.object(change_set, 'CommitChangeSet') as mock_commit:
      self.RunDeferredTasks(constants.TASK_QUEUE.BIT9_COMMIT_CHANGE)

      expected_calls = [mock.call(self.change.key), mock.call(real_change.key)]
      self.assertSameElements(expected_calls, mock_commit.mock_calls)


class UpdateBit9PoliciesTest(CronTest):

  def setUp(self):
    app = webapp2.WSGIApplication([('/', cron.UpdateBit9Policies)])
    super(UpdateBit9PoliciesTest, self).setUp(wsgi_app=app)

  def _PatchApiRequests(self, *results):
    requests = []
    for batch in results:
      if isinstance(batch, list):
        requests.append([obj.to_raw_dict() for obj in batch])
      else:
        requests.append(obj.to_raw_dict())
    utils.CONTEXT.ExecuteRequest.side_effect = requests

  def testGet_CreateNewPolicy(self):
    policy = api.Policy(id=1, name='foo', enforcement_level=20)
    self._PatchApiRequests([policy])

    self.testapp.get('/')

    policies = bit9_db.Bit9Policy.query().fetch()
    self.assertEqual(1, len(policies))

    policy = policies[0]
    self.assertEqual('1', policy.key.id())
    self.assertEqual('foo', policy.name)
    self.assertEqual(
        constants.BIT9_ENFORCEMENT_LEVEL.LOCKDOWN, policy.enforcement_level)

  def testGet_UpdateChangedPolicy(self):
    policy_obj_1 = bit9_db.Bit9Policy(
        id='1', name='bar',
        enforcement_level=constants.BIT9_ENFORCEMENT_LEVEL.LOCKDOWN)
    policy_obj_1.put()
    old_policy_dt = policy_obj_1.updated_dt

    policy_obj_2 = bit9_db.Bit9Policy(
        id='2', name='baz',
        enforcement_level=constants.BIT9_ENFORCEMENT_LEVEL.LOCKDOWN)
    policy_obj_2.put()
    old_other_policy_dt = policy_obj_2.updated_dt

    policy1 = api.Policy(id=1, name='foo', enforcement_level=30)
    policy2 = api.Policy(id=2, name='baz', enforcement_level=20)
    self._PatchApiRequests([policy1, policy2])

    self.testapp.get('/')

    self.assertEqual(2, bit9_db.Bit9Policy.query().count())

    # First policy should have has its name updated from 'bar' to 'foo'.
    updated_policy = bit9_db.Bit9Policy.get_by_id('1')
    self.assertEqual('foo', updated_policy.name)
    self.assertEqual(
        constants.BIT9_ENFORCEMENT_LEVEL.BLOCK_AND_ASK,
        updated_policy.enforcement_level)
    self.assertNotEqual(old_policy_dt, updated_policy.updated_dt)

    # Second policy should be unchanged.
    other_updated_policy = bit9_db.Bit9Policy.get_by_id('2')
    self.assertEqual(old_other_policy_dt, other_updated_policy.updated_dt)

  def testGet_IgnoreBadEnforcementLevel(self):
    policy_obj = bit9_db.Bit9Policy(
        id='1', name='foo',
        enforcement_level=constants.BIT9_ENFORCEMENT_LEVEL.LOCKDOWN)
    policy_obj.put()

    # Updated to an unknown enforcement level.
    policy = api.Policy(id=1, name='bar', enforcement_level=25)
    self._PatchApiRequests([policy])

    self.testapp.get('/')

    # Policy name should _not_ be updated.
    updated_policy = bit9_db.Bit9Policy.get_by_id('1')
    self.assertEqual('foo', updated_policy.name)


class CountEventsToPullTest(CronTest):

  def setUp(self):
    app = webapp2.WSGIApplication([('/', cron.CountEventsToPull)])
    super(CountEventsToPullTest, self).setUp(wsgi_app=app)

  @mock.patch.object(cron.monitoring, 'events_to_pull')
  def testSuccess(self, mock_metric):
    utils.CONTEXT.ExecuteRequest.return_value = {'count': 20}

    self.testapp.get('/')

    actual_length = mock_metric.Set.call_args_list[0][0][0]
    self.assertEqual(20, actual_length)


class PullEventsTest(CronTest):

  def setUp(self):
    app = webapp2.WSGIApplication([('/', cron.PullEvents)])
    super(PullEventsTest, self).setUp(wsgi_app=app)

  def testQueueFills(self):
    for i in xrange(1, cron._PULL_MAX_QUEUE_SIZE + 20):
      response = self.testapp.get('/')
      self.assertEqual(httplib.OK, response.status_int)
      expected_queue_size = min(i, cron._PULL_MAX_QUEUE_SIZE)
      self.assertTaskCount(constants.TASK_QUEUE.BIT9_PULL, expected_queue_size)


class CountEventsToProcessTest(CronTest):

  def setUp(self):
    app = webapp2.WSGIApplication([('/', cron.CountEventsToProcess)])
    super(CountEventsToProcessTest, self).setUp(wsgi_app=app)

  @mock.patch.object(cron.monitoring, 'events_to_process')
  def testSuccess(self, mock_metric):
    expected_length = 5
    for _ in xrange(expected_length):
      sync._UnsyncedEvent().put()

    response = self.testapp.get('/')

    self.assertEqual(httplib.OK, response.status_int)
    actual_length = mock_metric.Set.call_args_list[0][0][0]
    self.assertEqual(expected_length, actual_length)


class ProcessEventsTest(CronTest):

  def setUp(self):
    app = webapp2.WSGIApplication([('/', cron.ProcessEvents)])
    super(ProcessEventsTest, self).setUp(wsgi_app=app)

  def testQueueFills(self):
    for i in xrange(1, cron._DISPATCH_MAX_QUEUE_SIZE + 20):
      response = self.testapp.get('/')
      self.assertEqual(httplib.OK, response.status_int)
      expected_queue_size = min(i, cron._DISPATCH_MAX_QUEUE_SIZE)
      self.assertTaskCount(
          constants.TASK_QUEUE.BIT9_DISPATCH, expected_queue_size)


if __name__ == '__main__':
  absltest.main()
