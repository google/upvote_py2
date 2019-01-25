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

"""Unit tests for user.py."""

from upvote.gae import settings
from upvote.gae.datastore import test_utils
from upvote.gae.datastore.models import user as user_models
from upvote.gae.lib.testing import basetest
from upvote.gae.utils import user_utils
from upvote.shared import constants


_TEST_EMAIL = user_utils.UsernameToEmail('testemail')

# Done for the sake of brevity.
USER = constants.USER_ROLE.USER
TRUSTED_USER = constants.USER_ROLE.TRUSTED_USER
ADMINISTRATOR = constants.USER_ROLE.ADMINISTRATOR


class UserTest(basetest.UpvoteTestCase):
  """Test User model."""

  def setUp(self):
    super(UserTest, self).setUp()
    self._voting_weights = settings.VOTING_WEIGHTS

    self.PatchEnv(settings.ProdEnv, ENABLE_BIGQUERY_STREAMING=True)

  def testGetOrInsert_ExistingUser_EmailAddr(self):

    user_models.User.get_or_insert(_TEST_EMAIL)
    self.assertEntityCount(user_models.User, 1)

    user = user_models.User.GetOrInsert(email_addr=_TEST_EMAIL)

    self.assertIsNotNone(user)
    self.assertEntityCount(user_models.User, 1)
    self.assertNoBigQueryInsertions()

  def testGetOrInsert_ExistingUser_AppEngineUser(self):

    user_models.User.get_or_insert(_TEST_EMAIL)
    self.assertEntityCount(user_models.User, 1)

    appengine_user = test_utils.CreateAppEngineUser(email=_TEST_EMAIL)

    user = user_models.User.GetOrInsert(appengine_user=appengine_user)

    self.assertIsNotNone(user)
    self.assertEntityCount(user_models.User, 1)
    self.assertNoBigQueryInsertions()

  def testGetOrInsert_NewUser_EmailAddr(self):

    self.assertEntityCount(user_models.User, 0)

    user = user_models.User.GetOrInsert(email_addr=_TEST_EMAIL)

    self.assertIsNotNone(user)
    self.assertEntityCount(user_models.User, 1)

    self.assertListEqual([constants.USER_ROLE.USER], user.roles)
    self.assertSetEqual(constants.PERMISSIONS.SET_USER, user.permissions)

    self.assertBigQueryInsertion(constants.BIGQUERY_TABLE.USER)

  def testGetOrInsert_NewUser_EmailAddr_Lowercase(self):

    user = user_models.User.GetOrInsert(email_addr='UPPER@case.addr')
    self.assertIsNotNone(user)
    self.assertEqual('upper@case.addr', user.email)
    self.assertEqual('upper', user.nickname)

    self.assertBigQueryInsertion(constants.BIGQUERY_TABLE.USER)

  def testGetOrInsert_NewUser_AppEngineUser(self):

    self.assertEntityCount(user_models.User, 0)

    appengine_user = test_utils.CreateAppEngineUser(email=_TEST_EMAIL)
    user = user_models.User.GetOrInsert(appengine_user=appengine_user)

    self.assertIsNotNone(user)
    self.assertEntityCount(user_models.User, 1)

    self.assertListEqual([constants.USER_ROLE.USER], user.roles)
    self.assertSetEqual(constants.PERMISSIONS.SET_USER, user.permissions)

    self.assertBigQueryInsertion(constants.BIGQUERY_TABLE.USER)

  def testGetOrInsert_UnknownUserError(self):

    self.Patch(user_models.users, 'get_current_user', return_value=None)

    with self.assertRaises(user_models.UnknownUserError):
      user_models.User.GetOrInsert()

  def testPrePutHook(self):
    user = user_models.User.GetOrInsert(email_addr=_TEST_EMAIL)
    user.roles = [USER] * 100
    self.assertLen(user.roles, 100)
    user.put()
    self.assertLen(user.roles, 1)
    self.assertEquals([USER], user.roles)

    self.assertBigQueryInsertion(constants.BIGQUERY_TABLE.USER)

  def testSetRoles_RemoveAll(self):
    with self.LoggedInUser() as user:
      self.assertListEqual([constants.USER_ROLE.USER], user.roles)

      email_addr = user.email
      with self.assertRaises(user_models.NoRolesError):
        user_models.User.SetRoles(email_addr, [])
      user = user_models.User.GetOrInsert(email_addr=email_addr)
      self.assertListEqual([constants.USER_ROLE.USER], user.roles)

    self.assertNoBigQueryInsertions()

  def testSetRoles_InvalidUserRole(self):
    with self.LoggedInUser() as user:
      with self.assertRaises(user_models.InvalidUserRoleError):
        user_models.User.SetRoles(user.email, ['INVALID_ROLE'])

  def testSetRoles_NoChanges(self):

    with self.LoggedInUser() as user:
      self.assertListEqual([constants.USER_ROLE.USER], user.roles)
      old_vote_weight = user.vote_weight

    user_models.User.SetRoles(user.email, [constants.USER_ROLE.USER])
    user = user_models.User.GetOrInsert(email_addr=user.email)

    self.assertListEqual([constants.USER_ROLE.USER], user.roles)
    self.assertEqual(user.vote_weight, old_vote_weight)

    self.assertNoBigQueryInsertions()

  def testSetRoles_AddRole(self):

    with self.LoggedInUser() as user:
      self.assertListEqual([constants.USER_ROLE.USER], user.roles)
      self.assertEqual(
          self._voting_weights[constants.USER_ROLE.USER], user.vote_weight)

    new_roles = [constants.USER_ROLE.SUPERUSER, constants.USER_ROLE.USER]
    user_models.User.SetRoles(user.email, new_roles)
    user = user_models.User.GetOrInsert(email_addr=user.email)

    self.assertListEqual(new_roles, user.roles)
    self.assertEqual(
        self._voting_weights[constants.USER_ROLE.SUPERUSER], user.vote_weight)

    self.assertBigQueryInsertion(constants.BIGQUERY_TABLE.USER)

  def testSetRoles_RemoveRole(self):

    old_roles = [constants.USER_ROLE.SUPERUSER, constants.USER_ROLE.USER]
    user = test_utils.CreateUser(email=_TEST_EMAIL, roles=old_roles)
    self.assertEqual(
        self._voting_weights[constants.USER_ROLE.SUPERUSER], user.vote_weight)

    new_roles = [constants.USER_ROLE.USER]
    user_models.User.SetRoles(_TEST_EMAIL, new_roles)
    user = user_models.User.GetOrInsert(email_addr=_TEST_EMAIL)
    self.assertListEqual(new_roles, user.roles)
    self.assertEqual(
        self._voting_weights[constants.USER_ROLE.USER], user.vote_weight)

    self.assertBigQueryInsertion(constants.BIGQUERY_TABLE.USER)

  def testUpdateRoles_AddRole(self):

    with self.LoggedInUser() as user:
      self.assertListEqual([constants.USER_ROLE.USER], user.roles)
      self.assertEqual(
          self._voting_weights[constants.USER_ROLE.USER], user.vote_weight)

    user_models.User.UpdateRoles(
        user.email, add=[constants.USER_ROLE.SUPERUSER])
    user = user_models.User.GetOrInsert(email_addr=user.email)
    self.assertListEqual(
        [constants.USER_ROLE.SUPERUSER, constants.USER_ROLE.USER], user.roles)
    self.assertEqual(
        self._voting_weights[constants.USER_ROLE.SUPERUSER], user.vote_weight)

    self.assertBigQueryInsertion(constants.BIGQUERY_TABLE.USER)

  def testUpdateRoles_RemoveRole(self):

    old_roles = [constants.USER_ROLE.SUPERUSER, constants.USER_ROLE.USER]
    user = test_utils.CreateUser(email=_TEST_EMAIL, roles=old_roles)
    with self.LoggedInUser(user=user):
      self.assertEqual(
          self._voting_weights[constants.USER_ROLE.SUPERUSER], user.vote_weight)

    user_models.User.UpdateRoles(
        _TEST_EMAIL, remove=[constants.USER_ROLE.SUPERUSER])
    user = user_models.User.GetOrInsert(email_addr=_TEST_EMAIL)
    self.assertListEqual([constants.USER_ROLE.USER], user.roles)
    self.assertEqual(
        self._voting_weights[constants.USER_ROLE.USER], user.vote_weight)

    self.assertBigQueryInsertion(constants.BIGQUERY_TABLE.USER)

  def testHighestRole_Default(self):
    user = test_utils.CreateUser()
    self.assertEqual(constants.USER_ROLE.USER, user.highest_role)

  def testHighestRole_Administrator(self):
    roles = [
        constants.USER_ROLE.USER,
        constants.USER_ROLE.TRUSTED_USER,
        constants.USER_ROLE.ADMINISTRATOR]
    user = test_utils.CreateUser(roles=roles)
    self.assertEqual(constants.USER_ROLE.ADMINISTRATOR, user.highest_role)

  def testHighestRole_NoRolesError(self):
    user = test_utils.CreateUser()
    user.roles = []
    user.put()
    with self.assertRaises(user_models.NoRolesError):
      user.highest_role  # pylint: disable=pointless-statement

  def testIsAdmin_Nope(self):
    lowly_peon = test_utils.CreateUser(roles=[constants.USER_ROLE.USER])
    self.assertFalse(lowly_peon.is_admin)

  def testIsAdmin_HasAdminRole(self):
    fancy_admin = test_utils.CreateUser(
        roles=[constants.USER_ROLE.ADMINISTRATOR])
    self.assertTrue(fancy_admin.is_admin)

  def testIsAdmin_IsFailsafe(self):
    self.PatchSetting('FAILSAFE_ADMINISTRATORS', [_TEST_EMAIL])

    mr_failsafe = test_utils.CreateUser(
        email=_TEST_EMAIL, roles=[constants.USER_ROLE.USER])
    self.assertTrue(mr_failsafe.is_admin)

  def testPermissions_Admin(self):
    admin = test_utils.CreateUser(admin=True)
    self.assertSetEqual(constants.PERMISSIONS.SET_ALL, admin.permissions)

  def testPermissions_User(self):
    user = test_utils.CreateUser()
    self.assertSetEqual(constants.PERMISSIONS.SET_USER, user.permissions)


if __name__ == '__main__':
  basetest.main()
