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

"""Unit tests for utils.py."""

import datetime

import mock

from google.appengine.ext import ndb

from upvote.gae import settings
from upvote.gae.datastore import test_utils
from upvote.gae.datastore import utils as datastore_utils
from upvote.gae.datastore.models import base as base_models
from upvote.gae.datastore.models import host as host_models
from upvote.gae.datastore.models import rule as rule_models
from upvote.gae.datastore.models import santa as santa_models
from upvote.gae.datastore.models import utils as model_utils
from upvote.gae.lib.testing import basetest
from upvote.gae.utils import user_utils
from upvote.shared import constants


# Done for brevity.
_STATE = constants.EXEMPTION_STATE
_TABLE = constants.BIGQUERY_TABLE


class GetBit9HostKeysForUserTest(basetest.UpvoteTestCase):

  def testSuccess(self):

    user = test_utils.CreateUser()
    expected_host_key = test_utils.CreateBit9Host(users=[user.nickname]).key
    test_utils.CreateBit9Host(users=['someone_else'])
    test_utils.CreateSantaHost(primary_user=user.nickname)

    actual_host_keys = model_utils.GetBit9HostKeysForUser(user)

    self.assertListEqual([expected_host_key], actual_host_keys)


class GetBit9HostIdsForUserTest(basetest.UpvoteTestCase):

  def testSuccess(self):

    user = test_utils.CreateUser()
    expected_host_id = test_utils.CreateBit9Host(users=[user.nickname]).key.id()
    test_utils.CreateBit9Host(users=['someone_else'])
    test_utils.CreateSantaHost(primary_user=user.nickname)

    actual_host_ids = model_utils.GetBit9HostIdsForUser(user)

    self.assertListEqual([expected_host_id], actual_host_ids)


class GetSantaHostKeysForUserTest(basetest.UpvoteTestCase):

  def testSuccess(self):

    user = test_utils.CreateUser()
    other_user = test_utils.CreateUser()

    santa_host_key_1 = test_utils.CreateSantaHost(
        primary_user=user.nickname).key
    santa_host_key_2 = test_utils.CreateSantaHost(
        primary_user=other_user.nickname).key
    test_utils.CreateSantaHost(primary_user=other_user.nickname)

    blockable = test_utils.CreateSantaBlockable()
    parent_key = datastore_utils.ConcatenateKeys(
        user.key, santa_host_key_2, blockable.key)
    test_utils.CreateSantaEvent(
        blockable, host_id=santa_host_key_2.id(), parent=parent_key)

    expected_host_keys = sorted([santa_host_key_1, santa_host_key_2])
    actual_host_keys = sorted(model_utils.GetSantaHostKeysForUser(user))
    self.assertListEqual(expected_host_keys, actual_host_keys)


class GetSantaHostIdsForUserTest(basetest.UpvoteTestCase):

  def testSuccess(self):

    user = test_utils.CreateUser()
    other_user = test_utils.CreateUser()

    santa_host_key_1 = test_utils.CreateSantaHost(
        primary_user=user.nickname).key
    santa_host_key_2 = test_utils.CreateSantaHost(
        primary_user=other_user.nickname).key
    test_utils.CreateSantaHost(primary_user=other_user.nickname)

    blockable = test_utils.CreateSantaBlockable()
    parent_key = datastore_utils.ConcatenateKeys(
        user.key, santa_host_key_2, blockable.key)
    test_utils.CreateSantaEvent(
        blockable, host_id=santa_host_key_2.id(), parent=parent_key)

    expected_host_ids = sorted([santa_host_key_1.id(), santa_host_key_2.id()])
    actual_host_ids = sorted(model_utils.GetSantaHostIdsForUser(user))
    self.assertListEqual(expected_host_ids, actual_host_ids)


class GetExemptionsForUserTest(basetest.UpvoteTestCase):

  def testNoExemptions_WithoutStateFilter(self):

    user = test_utils.CreateUser()
    test_utils.CreateSantaHosts(4, primary_user=user.nickname)

    self.assertListEqual([], model_utils.GetExemptionsForUser(user.email))

  def testNoExemptions_WithStateFilter(self):

    user = test_utils.CreateUser()
    test_utils.CreateSantaHosts(4, primary_user=user.nickname)

    actual_exms = model_utils.GetExemptionsForUser(
        user.email, state=constants.EXEMPTION_STATE.APPROVED)
    self.assertListEqual([], actual_exms)

  def testSuccess(self):

    user = test_utils.CreateUser()
    host_id_1 = test_utils.CreateBit9Host(users=[user.nickname]).key.id()
    host_id_2 = test_utils.CreateSantaHost(primary_user=user.nickname).key.id()
    host_id_3 = test_utils.CreateSantaHost(primary_user='someone_else').key.id()
    exm_1 = test_utils.CreateExemption(host_id_1).get()
    exm_2 = test_utils.CreateExemption(host_id_2).get()
    test_utils.CreateExemption(host_id_3)

    expected_exms = sorted([exm_1, exm_2])
    actual_exms = sorted(model_utils.GetExemptionsForUser(user.email))
    self.assertListEqual(expected_exms, actual_exms)

  def testWithStateFilter(self):

    user = test_utils.CreateUser()
    host_id_1 = test_utils.CreateBit9Host(users=[user.nickname]).key.id()
    host_id_2 = test_utils.CreateSantaHost(primary_user=user.nickname).key.id()
    host_id_3 = test_utils.CreateSantaHost(primary_user='someone_else').key.id()
    exm_1 = test_utils.CreateExemption(
        host_id_1, initial_state=_STATE.APPROVED).get()
    test_utils.CreateExemption(host_id_2, initial_state=_STATE.EXPIRED)
    test_utils.CreateExemption(host_id_3, initial_state=_STATE.APPROVED)

    actual_exms = sorted(
        model_utils.GetExemptionsForUser(user.email, state=_STATE.APPROVED))
    self.assertListEqual([exm_1], actual_exms)


class GetExemptionsForHostsTest(basetest.UpvoteTestCase):

  def testSuccess(self):

    # Create a user and some Hosts, some with Exemptions, and some without.
    user = test_utils.CreateUser()
    host_key_1 = test_utils.CreateBit9Host(users=[user.nickname]).key
    exm_1 = test_utils.CreateExemption(host_key_1.id()).get()
    host_key_2 = test_utils.CreateBit9Host(users=[user.nickname]).key
    host_key_3 = test_utils.CreateSantaHost(primary_user=user.nickname).key
    exm_2 = test_utils.CreateExemption(host_key_3.id()).get()
    host_key_4 = test_utils.CreateSantaHost(primary_user=user.nickname).key

    host_keys = [host_key_1, host_key_2, host_key_3, host_key_4]
    results = model_utils.GetExemptionsForHosts(host_keys)

    self.assertLen(results, 4)
    self.assertEqual(exm_1, results.get(host_key_1))
    self.assertIsNone(results.get(host_key_2))
    self.assertEqual(exm_2, results.get(host_key_3))
    self.assertIsNone(results.get(host_key_4))


class GetEventKeysToInsertTest(basetest.UpvoteTestCase):

  def setUp(self):
    super(GetEventKeysToInsertTest, self).setUp()

    now = datetime.datetime.utcnow()
    self.user = test_utils.CreateUser()
    self.event = test_utils.CreateEvent(
        test_utils.CreateBlockable(), first_blocked_dt=now,
        last_blocked_dt=now, executing_user=self.user.nickname)

    self.PatchSetting('EVENT_CREATION', constants.EVENT_CREATION.EXECUTING_USER)

  def testGetEventKeysToInsert(self):
    keys = model_utils.GetEventKeysToInsert(self.event, ['foo', 'bar'], [])

    self.assertLen(keys, 1)
    expected_email = user_utils.UsernameToEmail(self.event.executing_user)
    self.assertEqual(expected_email, keys[0].pairs()[0][1])

  def testGetEventKeysToInsert_Admin(self):
    usernames = ['foo', 'bar']
    with mock.patch.object(
        base_models.Event, 'run_by_local_admin', return_value=True):
      event = datastore_utils.CopyEntity(self.event)
      keys = model_utils.GetEventKeysToInsert(event, usernames, [])

    self.assertLen(keys, 2)
    key_usernames = [user_utils.EmailToUsername(key.flat()[1]) for key in keys]
    self.assertSameElements(usernames, key_usernames)

  def testGetEventKeysToInsert_BlockableKey(self):
    old_key = self.event.blockable_key
    self.event.blockable_key = ndb.Key(
        'bar', 'baz', parent=old_key)
    keys = model_utils.GetEventKeysToInsert(self.event, ['foo', 'bar'], [])

    self.assertLen(keys[0].pairs(), 5)
    self.assertEqual(old_key.pairs()[0], keys[0].pairs()[2])
    self.assertEqual(('bar', 'baz'), keys[0].pairs()[3])

  def testGetEventKeysToInsert_RelatedBinary(self):
    self.event.executing_user = None
    keys = model_utils.GetEventKeysToInsert(self.event, [], [])

    self.assertEqual([], keys)

  def testGetEventKeysToInsert_HostOwner(self):
    self.PatchSetting('EVENT_CREATION', constants.EVENT_CREATION.HOST_OWNER)
    keys = model_utils.GetEventKeysToInsert(self.event, [], ['foo'])

    self.assertLen(keys, 1)
    key_usernames = [user_utils.EmailToUsername(key.flat()[1]) for key in keys]
    self.assertSameElements(['foo'], key_usernames)

  def testGetEventKeysToInsert_Superuser(self):

    bit9_host = test_utils.CreateBit9Host()
    bit9_binary = test_utils.CreateBit9Binary()
    now = test_utils.Now()

    bit9_event = test_utils.CreateBit9Event(
        bit9_binary,
        host_id=bit9_host.key.id(),
        executing_user=constants.LOCAL_ADMIN.WINDOWS,
        first_blocked_dt=now,
        last_blocked_dt=now,
        id='1',
        parent=datastore_utils.ConcatenateKeys(
            self.user.key, bit9_host.key, bit9_binary.key))

    users = [self.user.nickname]
    self.assertEquals(
        [bit9_event.key],
        model_utils.GetEventKeysToInsert(bit9_event, users, users))


class IsBit9HostAssociatedWithUserTest(basetest.UpvoteTestCase):

  def testAssociated(self):
    user = test_utils.CreateUser()
    host = test_utils.CreateBit9Host(users=[user.nickname])
    self.assertTrue(model_utils.IsBit9HostAssociatedWithUser(host, user))

  def testNotAssociated(self):
    user = test_utils.CreateUser()
    host = test_utils.CreateBit9Host(users=['someone_else'])
    self.assertFalse(model_utils.IsBit9HostAssociatedWithUser(host, user))


class IsSantaHostAssociatedWithUserTest(basetest.UpvoteTestCase):

  def testAssociated_PrimaryUser(self):
    user = test_utils.CreateUser()
    host = test_utils.CreateSantaHost(primary_user=user.nickname)
    self.assertTrue(model_utils.IsSantaHostAssociatedWithUser(host, user))

  def testAssociated_HasEvent(self):
    user = test_utils.CreateUser()
    other_user = test_utils.CreateUser()
    # Create a host not owned by `user`.
    host = test_utils.CreateSantaHost(primary_user=other_user.nickname)
    # Create an Event which was generated by `user`.
    blockable = test_utils.CreateSantaBlockable()
    parent_key = datastore_utils.ConcatenateKeys(
        user.key, host.key, blockable.key)
    test_utils.CreateSantaEvent(
        blockable, host_id=host.key.id(), parent=parent_key)

    self.assertTrue(model_utils.IsSantaHostAssociatedWithUser(host, user))

  def testNotAssociated_NoEvent(self):
    user = test_utils.CreateUser()
    # Create a host not owned by `user`.
    host = test_utils.CreateSantaHost(primary_user='someone_else')
    self.assertFalse(model_utils.IsSantaHostAssociatedWithUser(host, user))


class MysteryHost(host_models.Host):
  pass


class IsHostAssociatedWithUserTest(basetest.UpvoteTestCase):

  def testAssociations(self):

    bit9_user = test_utils.CreateUser()
    bit9_host = test_utils.CreateBit9Host(users=[bit9_user.nickname])

    santa_user = test_utils.CreateUser()
    santa_host = test_utils.CreateSantaHost(primary_user=santa_user.nickname)

    self.assertTrue(
        model_utils.IsHostAssociatedWithUser(bit9_host, bit9_user))
    self.assertTrue(
        model_utils.IsHostAssociatedWithUser(santa_host, santa_user))
    self.assertFalse(
        model_utils.IsHostAssociatedWithUser(bit9_host, santa_user))
    self.assertFalse(
        model_utils.IsHostAssociatedWithUser(santa_host, bit9_user))

  def testUnsupported(self):

    user = test_utils.CreateUser()
    host = MysteryHost()

    with self.assertRaises(ValueError):
      model_utils.IsHostAssociatedWithUser(host, user)


class GetUsersAssociatedWithSantaHostTest(basetest.UpvoteTestCase):

  def testSuccess(self):

    host_id = test_utils.CreateSantaHost().key.id()
    other_host_id = test_utils.CreateSantaHost().key.id()
    blockable = test_utils.CreateSantaBlockable()

    # Same Blockable, but wrong Host.
    test_utils.CreateSantaEvent(
        blockable, host_id=other_host_id, executing_user='user1')

    # Correct Host.
    test_utils.CreateSantaEvent(
        blockable, host_id=host_id, executing_user='user2')

    # Multiple Events for one user.
    for _ in xrange(3):
      test_utils.CreateSantaEvent(
          blockable, host_id=host_id, executing_user='user3')

    # Correct Host, but local admin.
    test_utils.CreateSantaEvent(
        blockable, host_id=host_id, executing_user=constants.LOCAL_ADMIN.MACOS)

    expected_users = ['user2', 'user3']
    actual_users = sorted(model_utils.GetUsersAssociatedWithSantaHost(host_id))
    self.assertEqual(expected_users, actual_users)


class GetBundleBinaryIdsForRuleTest(basetest.UpvoteTestCase):

  def testPackage(self):
    blockable = test_utils.CreateSantaBlockable()
    bundle = test_utils.CreateSantaBundle(bundle_binaries=[blockable])
    rule = test_utils.CreateSantaRule(
        bundle.key, rule_type=constants.RULE_TYPE.PACKAGE)

    self.assertSameElements(
        [blockable.key.id()], model_utils.GetBundleBinaryIdsForRule(rule))

  def testNotPackage(self):
    blockable = test_utils.CreateSantaBlockable()
    rule = test_utils.CreateSantaRule(
        blockable.key, rule_type=constants.RULE_TYPE.BINARY)

    self.assertListEqual([], model_utils.GetBundleBinaryIdsForRule(rule))


class EnsureCriticalRulesTest(basetest.UpvoteTestCase):

  def testSuccess(self):

    self.assertEntityCount(santa_models.SantaCertificate, 0)
    self.assertEntityCount(rule_models.SantaRule, 0)

    model_utils.EnsureCriticalRules(settings.CRITICAL_RULES)

    expected_count = len(settings.CRITICAL_RULES)
    self.assertEntityCount(santa_models.SantaCertificate, expected_count)
    self.assertEntityCount(rule_models.SantaRule, expected_count)
    self.assertBigQueryInsertions(
        [_TABLE.CERTIFICATE, _TABLE.RULE] * expected_count)


if __name__ == '__main__':
  basetest.main()
