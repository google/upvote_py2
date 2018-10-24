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

from upvote.gae.datastore import test_utils
from upvote.gae.datastore import utils as datastore_utils
from upvote.gae.datastore.models import base as base_models
from upvote.gae.datastore.models import utils as model_utils
from upvote.gae.lib.testing import basetest
from upvote.gae.shared.common import user_map
from upvote.shared import constants


# Done for brevity.
_STATE = constants.EXEMPTION_STATE


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

  def testSuccess(self):

    user = test_utils.CreateUser()
    host_id_1 = test_utils.CreateBit9Host(users=[user.nickname]).key.id()
    host_id_2 = test_utils.CreateSantaHost(primary_user=user.nickname).key.id()
    host_id_3 = test_utils.CreateSantaHost(primary_user='someone_else').key.id()
    exm_1 = test_utils.CreateExemption(host_id_1).get()
    exm_2 = test_utils.CreateExemption(host_id_2).get()
    test_utils.CreateExemption(host_id_3)

    expected_exms = sorted([exm_1, exm_2])
    actual_exms = sorted(model_utils.GetExemptionsForUser(user))
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
        model_utils.GetExemptionsForUser(user, state=_STATE.APPROVED))
    self.assertListEqual([exm_1], actual_exms)


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

    self.assertEqual(1, len(keys))
    expected_email = user_map.UsernameToEmail(self.event.executing_user)
    self.assertEqual(expected_email, keys[0].pairs()[0][1])

  def testGetEventKeysToInsert_Admin(self):
    usernames = ['foo', 'bar']
    with mock.patch.object(
        base_models.Event, 'run_by_local_admin', return_value=True):
      event = datastore_utils.CopyEntity(self.event)
      keys = model_utils.GetEventKeysToInsert(event, usernames, [])

    self.assertEqual(2, len(keys))
    key_usernames = [user_map.EmailToUsername(key.flat()[1]) for key in keys]
    self.assertSameElements(usernames, key_usernames)

  def testGetEventKeysToInsert_BlockableKey(self):
    old_key = self.event.blockable_key
    self.event.blockable_key = ndb.Key(
        'bar', 'baz', parent=old_key)
    keys = model_utils.GetEventKeysToInsert(self.event, ['foo', 'bar'], [])

    self.assertEqual(5, len(keys[0].pairs()))
    self.assertEqual(old_key.pairs()[0], keys[0].pairs()[2])
    self.assertEqual(('bar', 'baz'), keys[0].pairs()[3])

  def testGetEventKeysToInsert_RelatedBinary(self):
    self.event.executing_user = None
    keys = model_utils.GetEventKeysToInsert(self.event, [], [])

    self.assertEqual([], keys)

  def testGetEventKeysToInsert_HostOwner(self):
    self.PatchSetting('EVENT_CREATION', constants.EVENT_CREATION.HOST_OWNER)
    keys = model_utils.GetEventKeysToInsert(self.event, [], ['foo'])

    self.assertEqual(1, len(keys))
    key_usernames = [user_map.EmailToUsername(key.flat()[1]) for key in keys]
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


if __name__ == '__main__':
  basetest.main()
