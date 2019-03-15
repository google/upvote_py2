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

"""Unit tests for host.py."""

from google.appengine.ext import ndb

from upvote.gae.datastore import test_utils
from upvote.gae.datastore.models import host as host_models
from upvote.gae.datastore.models import policy as policy_models
from upvote.gae.lib.testing import basetest
from upvote.shared import constants


class Bit9HostTest(basetest.UpvoteTestCase):

  def setUp(self):
    super(Bit9HostTest, self).setUp()

    self.user = test_utils.CreateUser()
    self.admin = test_utils.CreateUser(admin=True)

    self.bit9_policy = test_utils.CreateBit9Policy()
    self.bit9_host = test_utils.CreateBit9Host(
        policy_key=self.bit9_policy.key, users=[self.user.nickname])

  def testChangePolicyKey(self):

    monitor_policy_key = ndb.Key(
        policy_models.Bit9Policy, constants.BIT9_ENFORCEMENT_LEVEL.MONITOR)
    lockdown_policy_key = ndb.Key(
        policy_models.Bit9Policy, constants.BIT9_ENFORCEMENT_LEVEL.LOCKDOWN)
    host_key = test_utils.CreateBit9Host(policy_key=monitor_policy_key).key

    self.assertEqual(monitor_policy_key, host_key.get().policy_key)
    host_models.Bit9Host.ChangePolicyKey(host_key.id(), lockdown_policy_key)
    self.assertEqual(lockdown_policy_key, host_key.get().policy_key)

  def testToDict(self):
    dict_ = self.bit9_host.to_dict()
    self.assertEqual(
        self.bit9_policy.enforcement_level, dict_['policy_enforcement_level'])

    self.bit9_host.policy_key = None
    self.bit9_host.put()

    dict_ = self.bit9_host.to_dict()
    self.assertNotIn('policy_enforcement_level', dict_)


class SantaHostTest(basetest.UpvoteTestCase):

  def testChangeClientMode(self):

    host_key = test_utils.CreateSantaHost(
        client_mode=constants.CLIENT_MODE.MONITOR,
        client_mode_lock=False).key

    self.assertEqual(
        constants.CLIENT_MODE.MONITOR, host_key.get().client_mode)
    self.assertFalse(host_key.get().client_mode_lock)
    host_models.SantaHost.ChangeClientMode(
        host_key.id(), constants.CLIENT_MODE.LOCKDOWN)
    self.assertEqual(
        constants.CLIENT_MODE.LOCKDOWN, host_key.get().client_mode)
    self.assertTrue(host_key.get().client_mode_lock)


if __name__ == '__main__':
  basetest.main()
