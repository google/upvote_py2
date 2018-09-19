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

"""Unit tests for bit9.py."""

import datetime

from google.appengine.ext import ndb

from upvote.gae.datastore import test_utils
from upvote.gae.datastore import utils
from upvote.gae.datastore.models import bit9
from upvote.gae.lib.testing import basetest
from upvote.gae.shared.common import settings
from upvote.shared import constants


class Bit9HostTest(basetest.UpvoteTestCase):

  def setUp(self):
    super(Bit9HostTest, self).setUp()

    self.user = test_utils.CreateUser()
    self.admin = test_utils.CreateUser(admin=True)

    self.bit9_policy = test_utils.CreateBit9Policy()
    self.bit9_host = test_utils.CreateBit9Host(
        policy_key=self.bit9_policy.key, users=[self.user.nickname])

  def testGetAssociatedHostIds(self):
    # Create a diversion...
    test_utils.CreateBit9Host(users=[self.admin.nickname])

    associated_hosts = bit9.Bit9Host.GetAssociatedHostIds(self.user)
    self.assertListEqual([self.bit9_host.key.id()], associated_hosts)

  def testChangePolicyKey_InvalidEnforcementLevel(self):

    host_key = test_utils.CreateBit9Host().key

    with self.assertRaises(bit9.InvalidEnforcementLevel):
      bit9.Bit9Host.ChangePolicyKey(host_key.id(), 'OMGWTF')

  def testChangePolicyKey_Success(self):

    monitor_policy_key = ndb.Key(
        bit9.Bit9Policy, constants.BIT9_ENFORCEMENT_LEVEL.MONITOR)
    lockdown_policy_key = ndb.Key(
        bit9.Bit9Policy, constants.BIT9_ENFORCEMENT_LEVEL.LOCKDOWN)
    host_key = test_utils.CreateBit9Host(policy_key=monitor_policy_key).key

    self.assertEqual(monitor_policy_key, host_key.get().policy_key)
    bit9.Bit9Host.ChangePolicyKey(
        host_key.id(), constants.BIT9_ENFORCEMENT_LEVEL.LOCKDOWN)
    self.assertEqual(lockdown_policy_key, host_key.get().policy_key)

  def testIsAssociatedWithUser(self):
    self.assertTrue(self.bit9_host.IsAssociatedWithUser(self.user))
    self.assertFalse(self.bit9_host.IsAssociatedWithUser(self.admin))

  def testToDict(self):
    dict_ = self.bit9_host.to_dict()
    self.assertEqual(
        self.bit9_policy.enforcement_level, dict_['policy_enforcement_level'])

    self.bit9_host.policy_key = None
    self.bit9_host.put()

    dict_ = self.bit9_host.to_dict()
    self.assertNotIn('policy_enforcement_level', dict_)


class Bit9EventTest(basetest.UpvoteTestCase):

  def setUp(self):
    super(Bit9EventTest, self).setUp()

    self.user = test_utils.CreateUser()

    self.bit9_host = test_utils.CreateBit9Host()

    self.bit9_binary = test_utils.CreateBit9Binary()
    now = test_utils.Now()
    self.bit9_event = test_utils.CreateBit9Event(
        self.bit9_binary,
        host_id=self.bit9_host.key.id(),
        executing_user=self.user.nickname,
        first_blocked_dt=now,
        last_blocked_dt=now,
        id='1',
        parent=utils.ConcatenateKeys(
            self.user.key, self.bit9_host.key,
            self.bit9_binary.key))

  def testGetKeysToInsert_Superuser(self):
    self.bit9_event.executing_user = constants.LOCAL_ADMIN.WINDOWS
    self.bit9_event.put()

    users = [self.user.nickname]
    self.assertEquals(
        [self.bit9_event.key],
        self.bit9_event.GetKeysToInsert(users, users))

  def testDedupe(self):
    earlier_dt = self.bit9_event.last_blocked_dt - datetime.timedelta(hours=1)
    earlier_bit9_event = utils.CopyEntity(
        self.bit9_event,
        first_blocked_dt=earlier_dt,
        last_blocked_dt=earlier_dt,
        bit9_id=self.bit9_event.bit9_id - 1,
    )

    # Always choose the larger ID.

    more_recent_deduped = utils.CopyEntity(earlier_bit9_event)
    more_recent_deduped.Dedupe(self.bit9_event)
    self.assertEquals(self.bit9_event.bit9_id, more_recent_deduped.bit9_id)

    earlier_deduped = utils.CopyEntity(self.bit9_event)
    earlier_deduped.Dedupe(earlier_bit9_event)
    self.assertEquals(self.bit9_event.bit9_id, earlier_deduped.bit9_id)

  def testDedupe_OutOfOrder(self):
    earlier_dt = self.bit9_event.last_blocked_dt - datetime.timedelta(hours=1)
    earlier_bit9_event = utils.CopyEntity(
        self.bit9_event,
        first_blocked_dt=earlier_dt,
        last_blocked_dt=earlier_dt,
        bit9_id=self.bit9_event.bit9_id + 1,  # Earlier event has larger ID
    )

    # Always choose the larger ID.

    more_recent_deduped = utils.CopyEntity(earlier_bit9_event)
    more_recent_deduped.Dedupe(self.bit9_event)
    self.assertEquals(self.bit9_event.bit9_id + 1, more_recent_deduped.bit9_id)

    earlier_deduped = utils.CopyEntity(self.bit9_event)
    earlier_deduped.Dedupe(earlier_bit9_event)
    self.assertEquals(self.bit9_event.bit9_id + 1, earlier_deduped.bit9_id)


class Bit9BinaryTest(basetest.UpvoteTestCase):

  def setUp(self):
    super(Bit9BinaryTest, self).setUp()
    self.bit9_binary = test_utils.CreateBit9Binary()

    self.PatchEnv(settings.ProdEnv, ENABLE_BIGQUERY_STREAMING=True)

  def testCalculateInstallerState(self):
    self.bit9_binary.detected_installer = False
    self.bit9_binary.put()
    test_utils.CreateBit9Rule(
        self.bit9_binary.key,
        in_effect=True,
        policy=constants.RULE_POLICY.FORCE_INSTALLER)

    self.assertTrue(self.bit9_binary.CalculateInstallerState())

  def testCalculateInstallerState_ForcedNot(self):
    self.bit9_binary.detected_installer = True
    self.bit9_binary.put()
    test_utils.CreateBit9Rule(
        self.bit9_binary.key,
        in_effect=True,
        policy=constants.RULE_POLICY.FORCE_NOT_INSTALLER)

    self.assertFalse(self.bit9_binary.CalculateInstallerState())

  def testCalculateInstallerState_NoInstallerRule_DefaultToDetected(self):
    unput_binary = bit9.Bit9Binary(
        id='foo', detected_installer=True, is_installer=False)
    self.assertTrue(unput_binary.CalculateInstallerState())

  def testToDict_ContainsOs(self):
    with self.LoggedInUser():
      the_dict = self.bit9_binary.to_dict()
      self.assertEqual(
          constants.PLATFORM.WINDOWS,
          the_dict.get('operating_system_family', None))

  def testToDict_ContainsIsVotingAllowed(self):
    with self.LoggedInUser():
      blockable = test_utils.CreateBlockable()
      self.assertIn('is_voting_allowed', blockable.to_dict())

  def testChangeState(self):

    # Verify the Bit9Binary is in the default state of UNTRUSTED.
    binary = test_utils.CreateBit9Binary()
    blockable_hash = binary.blockable_hash
    binary = bit9.Bit9Binary.get_by_id(blockable_hash)
    self.assertIsNotNone(binary)
    self.assertEqual(constants.STATE.UNTRUSTED, binary.state)

    # Note the state change timestamp.
    old_state_change_dt = binary.state_change_dt

    # Change the state.
    binary.ChangeState(constants.STATE.BANNED)

    # Reload, and verify the state change.
    binary = bit9.Bit9Binary.get_by_id(blockable_hash)
    self.assertIsNotNone(binary)
    self.assertEqual(constants.STATE.BANNED, binary.state)
    self.assertBigQueryInsertion(constants.BIGQUERY_TABLE.BINARY)

    # And the state change timestamp should be increased.
    self.assertTrue(binary.state_change_dt > old_state_change_dt)

  def testResetState(self):
    binary = test_utils.CreateBit9Binary(
        state=constants.STATE.BANNED, flagged=True)
    binary.ResetState()

    reset_binary = binary.key.get()

    self.assertEqual(reset_binary.state, constants.STATE.UNTRUSTED)
    self.assertFalse(reset_binary.flagged)
    self.assertBigQueryInsertion(constants.BIGQUERY_TABLE.BINARY)


class Bit9CertificateTest(basetest.UpvoteTestCase):

  def setUp(self):
    super(Bit9CertificateTest, self).setUp()
    self.PatchEnv(settings.ProdEnv, ENABLE_BIGQUERY_STREAMING=True)

  def testChangeState(self):

    # Verify the Bit9Certificate is in the default state of UNTRUSTED.
    cert = test_utils.CreateBit9Certificate()
    blockable_hash = cert.blockable_hash
    cert = bit9.Bit9Certificate.get_by_id(blockable_hash)
    self.assertIsNotNone(cert)
    self.assertEqual(constants.STATE.UNTRUSTED, cert.state)

    # Note the state change timestamp.
    old_state_change_dt = cert.state_change_dt

    # Change the state.
    cert.ChangeState(constants.STATE.BANNED)

    # Reload, and verify the state change.
    cert = bit9.Bit9Certificate.get_by_id(blockable_hash)
    self.assertIsNotNone(cert)
    self.assertEqual(constants.STATE.BANNED, cert.state)
    self.assertBigQueryInsertion(constants.BIGQUERY_TABLE.CERTIFICATE)

    # And the state change timestamp should be increased.
    self.assertTrue(cert.state_change_dt > old_state_change_dt)

  def testResetState(self):
    cert = test_utils.CreateBit9Certificate(
        state=constants.STATE.BANNED, flagged=True)
    cert.ResetState()

    reset_cert = cert.key.get()

    self.assertEqual(reset_cert.state, constants.STATE.UNTRUSTED)
    self.assertFalse(reset_cert.flagged)
    self.assertBigQueryInsertion(constants.BIGQUERY_TABLE.CERTIFICATE)


class RuleChangeSetTest(basetest.UpvoteTestCase):

  def setUp(self):
    super(RuleChangeSetTest, self).setUp()
    self.bit9_binary = test_utils.CreateBit9Binary()

  def testBlockableKey(self):
    change = bit9.RuleChangeSet(
        rule_keys=[],
        change_type=constants.RULE_POLICY.WHITELIST,
        parent=self.bit9_binary.key)
    change.put()

    self.assertEqual(self.bit9_binary.key, change.blockable_key)

  def testBlockableKey_NoParent(self):
    change = bit9.RuleChangeSet(
        rule_keys=[],
        change_type=constants.RULE_POLICY.WHITELIST,
        parent=None)
    with self.assertRaises(ValueError):
      change.put()

  def testBlockableKey_NotABlockableKey(self):
    host = test_utils.CreateBit9Host()
    change = bit9.RuleChangeSet(
        rule_keys=[],
        change_type=constants.RULE_POLICY.WHITELIST,
        parent=host.key)
    with self.assertRaises(ValueError):
      change.put()


if __name__ == '__main__':
  basetest.main()
