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

"""Unit tests for model_utils.py."""

from upvote.gae.datastore import test_utils
from upvote.gae.datastore import utils as datastore_utils
from upvote.gae.datastore.models import utils as model_utils
from upvote.gae.lib.testing import basetest
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


if __name__ == '__main__':
  basetest.main()
