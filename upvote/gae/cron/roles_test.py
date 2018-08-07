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

"""Unit tests for roles.py."""

import httplib
import mock
import webapp2

from google.appengine.ext import ndb

from upvote.gae.cron import roles
from upvote.gae.datastore import test_utils
from upvote.gae.datastore.models import user as user_models
from upvote.gae.lib.testing import basetest
from upvote.gae.shared.common import settings
from upvote.gae.shared.common import user_map
from upvote.shared import constants


# Done for the sake of brevity.
USER = constants.USER_ROLE.USER
TRUSTED_USER = constants.USER_ROLE.TRUSTED_USER
SUPERUSER = constants.USER_ROLE.SUPERUSER
ADMINISTRATOR = constants.USER_ROLE.ADMINISTRATOR
MONITOR = constants.SANTA_CLIENT_MODE.MONITOR
LOCKDOWN = constants.SANTA_CLIENT_MODE.LOCKDOWN


class SyncRolesTest(basetest.UpvoteTestCase):
  """This is a test of the emergency handler system."""

  ROUTE = '/roles/sync'

  def setUp(self):
    app = webapp2.WSGIApplication(routes=[roles.ROUTES])
    super(SyncRolesTest, self).setUp(wsgi_app=app)

  def VerifyUser(self, email_addr, expected_roles):

    user = user_models.User.GetOrInsert(email_addr=email_addr)
    self.assertIsNotNone(user)
    self.assertSetEqual(set(expected_roles), set(user.roles))

    voting_weights = settings.VOTING_WEIGHTS
    expected_vote_weight = max(voting_weights[r] for r in expected_roles)
    self.assertEqual(expected_vote_weight, user.vote_weight)

  @mock.patch.object(roles.groups, 'GroupManager')
  def testGet_GroupDoesNotExist(self, mock_ctor):
    """Tests a sync with a nonexistent group."""

    self.PatchSetting(
        'GROUP_ROLE_ASSIGNMENTS', {TRUSTED_USER: ['group1', 'group2']})
    user1 = test_utils.CreateUser()
    user2 = test_utils.CreateUser()

    mock_group_client = mock.Mock()
    mock_ctor.return_value = mock_group_client
    mock_group_client.DoesGroupExist.side_effect = [True, False]

    self.VerifyUser(user1.email, [USER])
    self.VerifyUser(user2.email, [USER])

    response = self.testapp.get(self.ROUTE, expect_errors=True)
    self.assertEqual(httplib.NOT_FOUND, response.status_int)

    self.VerifyUser(user1.email, [USER])
    self.VerifyUser(user2.email, [USER])

  @mock.patch.object(roles.groups, 'GroupManager')
  def testGet_AddRole(self, mock_ctor):
    """Tests a new role being added to the syncing dict."""

    self.PatchSetting('GROUP_ROLE_ASSIGNMENTS', {TRUSTED_USER: ['group1']})
    user1 = test_utils.CreateUser()
    user2 = test_utils.CreateUser()
    group1 = [user1.email, user2.email]

    mock_group_client = mock.Mock()
    mock_ctor.return_value = mock_group_client
    mock_group_client.AllMembers.return_value = group1

    self.VerifyUser(user1.email, [USER])
    self.VerifyUser(user2.email, [USER])

    response = self.testapp.get(self.ROUTE)
    self.assertEqual(httplib.OK, response.status_int)

    self.VerifyUser(user1.email, [USER, TRUSTED_USER])
    self.VerifyUser(user2.email, [USER, TRUSTED_USER])

    self.assertBigQueryInsertions([constants.BIGQUERY_TABLE.USER] * 2)

  @mock.patch.object(roles.groups, 'GroupManager')
  def testGet_ExistingRole_AddRole(self, mock_ctor):
    """Tests a new role being added alongside an existing role."""

    self.PatchSetting('GROUP_ROLE_ASSIGNMENTS', {
        TRUSTED_USER: ['group1'], SUPERUSER: ['group1']})
    user1 = test_utils.CreateUser(roles=[USER, TRUSTED_USER])
    user2 = test_utils.CreateUser(roles=[USER, TRUSTED_USER])
    group1 = [user1.email, user2.email]

    mock_group_client = mock.Mock()
    mock_ctor.return_value = mock_group_client
    mock_group_client.AllMembers.side_effect = [group1, group1]

    self.VerifyUser(user1.email, [USER, TRUSTED_USER])
    self.VerifyUser(user2.email, [USER, TRUSTED_USER])

    response = self.testapp.get(self.ROUTE)
    self.assertEqual(httplib.OK, response.status_int)

    self.VerifyUser(user1.email, [USER, TRUSTED_USER, SUPERUSER])
    self.VerifyUser(user2.email, [USER, TRUSTED_USER, SUPERUSER])

    self.assertBigQueryInsertions([constants.BIGQUERY_TABLE.USER] * 2)

  @mock.patch.object(roles.groups, 'GroupManager')
  def testGet_ExistingRole_AddGroup(self, mock_ctor):
    """Tests a new group being added to an existing role."""

    self.PatchSetting(
        'GROUP_ROLE_ASSIGNMENTS', {TRUSTED_USER: ['group1', 'group2']})
    user1 = test_utils.CreateUser(roles=[USER, TRUSTED_USER])
    user2 = test_utils.CreateUser(roles=[USER, TRUSTED_USER])
    user3 = test_utils.CreateUser(roles=[USER])

    mock_group_client = mock.Mock()
    mock_ctor.return_value = mock_group_client
    mock_group_client.AllMembers.side_effect = [
        [user1.email, user2.email], [user3.email]]

    self.VerifyUser(user1.email, [USER, TRUSTED_USER])
    self.VerifyUser(user2.email, [USER, TRUSTED_USER])
    self.VerifyUser(user3.email, [USER])

    response = self.testapp.get(self.ROUTE)
    self.assertEqual(httplib.OK, response.status_int)

    self.VerifyUser(user1.email, [USER, TRUSTED_USER])
    self.VerifyUser(user2.email, [USER, TRUSTED_USER])
    self.VerifyUser(user3.email, [USER, TRUSTED_USER])

    self.assertBigQueryInsertions([constants.BIGQUERY_TABLE.USER])

  @mock.patch.object(roles.groups, 'GroupManager')
  def testGet_RemoveRole(self, mock_ctor):
    """Tests a role being removed entirely."""

    self.PatchSetting('GROUP_ROLE_ASSIGNMENTS', {
        TRUSTED_USER: ['group1'], SUPERUSER: []})
    user1 = test_utils.CreateUser(roles=[USER, TRUSTED_USER, SUPERUSER])
    user2 = test_utils.CreateUser(roles=[USER, TRUSTED_USER, SUPERUSER])

    mock_group_client = mock.Mock()
    mock_ctor.return_value = mock_group_client
    mock_group_client.AllMembers.return_value = [user1.email, user2.email]

    self.VerifyUser(user1.email, [USER, TRUSTED_USER, SUPERUSER])
    self.VerifyUser(user2.email, [USER, TRUSTED_USER, SUPERUSER])

    response = self.testapp.get(self.ROUTE)
    self.assertEqual(httplib.OK, response.status_int)

    self.VerifyUser(user1.email, [USER, TRUSTED_USER])
    self.VerifyUser(user2.email, [USER, TRUSTED_USER])

    self.assertBigQueryInsertions([constants.BIGQUERY_TABLE.USER] * 2)

  @mock.patch.object(roles.groups, 'GroupManager')
  def testGet_ExistingRole_RemoveGroup(self, mock_ctor):
    """Tests a single group being removed from a role which has multiple."""

    self.PatchSetting('GROUP_ROLE_ASSIGNMENTS', {TRUSTED_USER: ['group1']})
    user1 = test_utils.CreateUser(roles=[USER, TRUSTED_USER])
    user2 = test_utils.CreateUser(roles=[USER, TRUSTED_USER])
    user3 = test_utils.CreateUser(roles=[USER, TRUSTED_USER])

    mock_group_client = mock.Mock()
    mock_ctor.return_value = mock_group_client
    mock_group_client.AllMembers.return_value = [
        user1.email, user2.email]

    self.VerifyUser(user1.email, [USER, TRUSTED_USER])
    self.VerifyUser(user2.email, [USER, TRUSTED_USER])
    self.VerifyUser(user3.email, [USER, TRUSTED_USER])

    response = self.testapp.get(self.ROUTE)
    self.assertEqual(httplib.OK, response.status_int)

    self.VerifyUser(user1.email, [USER, TRUSTED_USER])
    self.VerifyUser(user2.email, [USER, TRUSTED_USER])
    self.VerifyUser(user3.email, [USER])

    self.assertBigQueryInsertions([constants.BIGQUERY_TABLE.USER])

  @mock.patch.object(roles.groups, 'GroupManager')
  def testGet_MemberAdded(self, mock_ctor):
    """Tests a member being added to an existing group."""

    self.PatchSetting('GROUP_ROLE_ASSIGNMENTS', {TRUSTED_USER: ['group1']})
    user1 = test_utils.CreateUser(roles=[USER, TRUSTED_USER])
    user2 = test_utils.CreateUser(roles=[USER, TRUSTED_USER])
    user3 = test_utils.CreateUser(roles=[USER])

    mock_group_client = mock.Mock()
    mock_ctor.return_value = mock_group_client
    mock_group_client.AllMembers.return_value = [
        user1.email, user2.email, user3.email]

    self.VerifyUser(user1.email, [USER, TRUSTED_USER])
    self.VerifyUser(user2.email, [USER, TRUSTED_USER])
    self.VerifyUser(user3.email, [USER])

    response = self.testapp.get(self.ROUTE)
    self.assertEqual(httplib.OK, response.status_int)

    self.VerifyUser(user1.email, [USER, TRUSTED_USER])
    self.VerifyUser(user2.email, [USER, TRUSTED_USER])
    self.VerifyUser(user3.email, [USER, TRUSTED_USER])

    self.assertBigQueryInsertions([constants.BIGQUERY_TABLE.USER])

  @mock.patch.object(roles.groups, 'GroupManager')
  def testGet_MemberRemoved(self, mock_ctor):
    """Tests a member being removed from an existing group."""

    self.PatchSetting('GROUP_ROLE_ASSIGNMENTS', {TRUSTED_USER: ['group1']})
    user1 = test_utils.CreateUser(roles=[USER, TRUSTED_USER])
    user2 = test_utils.CreateUser(roles=[USER, TRUSTED_USER])
    user3 = test_utils.CreateUser(roles=[USER, TRUSTED_USER])

    mock_group_client = mock.Mock()
    mock_ctor.return_value = mock_group_client
    mock_group_client.AllMembers.return_value = [
        user1.email, user2.email]

    self.VerifyUser(user1.email, [USER, TRUSTED_USER])
    self.VerifyUser(user2.email, [USER, TRUSTED_USER])
    self.VerifyUser(user3.email, [USER, TRUSTED_USER])

    response = self.testapp.get(self.ROUTE)
    self.assertEqual(httplib.OK, response.status_int)

    self.VerifyUser(user1.email, [USER, TRUSTED_USER])
    self.VerifyUser(user2.email, [USER, TRUSTED_USER])
    # Removing last role will ensure minimum of USER.
    self.VerifyUser(user3.email, [USER])

    self.assertBigQueryInsertions([constants.BIGQUERY_TABLE.USER])

  @mock.patch.object(roles.groups, 'GroupManager')
  def testGet_EnsureFailsafeAdmins(self, mock_ctor):

    self.PatchSetting('GROUP_ROLE_ASSIGNMENTS', {ADMINISTRATOR: ['group1']})
    user1 = test_utils.CreateUser(roles=[USER, ADMINISTRATOR])
    user2 = test_utils.CreateUser(roles=[USER, ADMINISTRATOR])

    mock_group_client = mock.Mock()
    mock_ctor.return_value = mock_group_client
    mock_group_client.AllMembers.return_value = [user1.email, user2.email]

    self.VerifyUser(user1.email, [USER, ADMINISTRATOR])
    self.VerifyUser(user2.email, [USER, ADMINISTRATOR])

    response = self.testapp.get(self.ROUTE)
    self.assertEqual(httplib.OK, response.status_int)

    self.VerifyUser(user1.email, [USER, ADMINISTRATOR])
    self.VerifyUser(user2.email, [USER, ADMINISTRATOR])

    for failsafe in settings.FAILSAFE_ADMINISTRATORS:
      self.VerifyUser(failsafe, [USER, ADMINISTRATOR])

    # 2x the number of failsafe admins: one FIRST_SEEN and one ROLE_CHANGE each.
    expected_insertions = [constants.BIGQUERY_TABLE.USER] * 2 * len(
        settings.FAILSAFE_ADMINISTRATORS)
    self.assertBigQueryInsertions(expected_insertions)


class FakeClientModeChangeHandler(roles.ClientModeChangeHandler):

  def get(self):
    self._ChangeModeForGroup(LOCKDOWN, 'somegroup')


class ClientModeChangeHandlerTest(basetest.UpvoteTestCase):

  def setUp(self):
    app = webapp2.WSGIApplication(
        [webapp2.Route(r'', handler=FakeClientModeChangeHandler)])
    super(ClientModeChangeHandlerTest, self).setUp(wsgi_app=app)

  @mock.patch.object(roles.groups, 'GroupManager')
  @mock.patch.dict(roles.__dict__, values={'BATCH_SIZE': 2})
  def testChangeModeForGroup_SingleBatch(self, mock_ctor):

    users = [
        test_utils.CreateUser() for _ in xrange(roles.BATCH_SIZE - 1)]
    hosts = [
        test_utils.CreateSantaHost(
            primary_user=user_map.EmailToUsername(user.key.id()),
            client_mode=MONITOR)
        for user in users]
    mock_ctor.return_value.AllMembers.return_value = [
        user.key.id() for user in users]

    response = self.testapp.get('')

    self.assertEqual(httplib.OK, response.status_int)

    self.assertTaskCount(constants.TASK_QUEUE.DEFAULT, 1)
    self.DrainTaskQueue(constants.TASK_QUEUE.DEFAULT)

    new_hosts = ndb.get_multi(host.key for host in hosts)
    self.assertTrue(all(host.client_mode == LOCKDOWN for host in new_hosts))

  @mock.patch.object(roles.groups, 'GroupManager')
  @mock.patch.dict(roles.__dict__, values={'BATCH_SIZE': 2})
  def testChangeModeForGroup_MultiBatch(self, mock_ctor):

    users = [
        test_utils.CreateUser() for _ in xrange(roles.BATCH_SIZE + 1)]
    hosts = [
        test_utils.CreateSantaHost(
            primary_user=user_map.EmailToUsername(user.key.id()),
            client_mode=MONITOR)
        for user in users]
    mock_ctor.return_value.AllMembers.return_value = [
        user.key.id() for user in users]

    response = self.testapp.get('')

    self.assertEqual(httplib.OK, response.status_int)

    self.assertTaskCount(constants.TASK_QUEUE.DEFAULT, 2)
    self.DrainTaskQueue(constants.TASK_QUEUE.DEFAULT)

    new_hosts = ndb.get_multi(host.key for host in hosts)
    self.assertTrue(all(host.client_mode == LOCKDOWN for host in new_hosts))

  @mock.patch.object(roles.groups, 'GroupManager')
  def testChangeModeForGroup_NoUsers(self, mock_ctor):

    mock_ctor.return_value.AllMembers.return_value = []

    response = self.testapp.get('')

    self.assertEqual(httplib.OK, response.status_int)

    self.assertTaskCount(constants.TASK_QUEUE.DEFAULT, 0)


class ChangeModeForHostsTest(basetest.UpvoteTestCase):

  def setUp(self):
    super(ChangeModeForHostsTest, self).setUp()

    self.user = test_utils.CreateUser()

  def testNoHosts(self):

    roles._ChangeModeForHosts(LOCKDOWN, [self.user.key])

  def testClientModeLockOnHonored(self):

    host = test_utils.CreateSantaHost(
        primary_user=user_map.EmailToUsername(self.user.key.id()),
        client_mode=MONITOR, client_mode_lock=True)
    roles._ChangeModeForHosts(LOCKDOWN, [self.user.key])

    host = host.key.get()
    self.assertTrue(host.client_mode_lock)
    self.assertEqual(MONITOR, host.client_mode)

  def testClientModeLockOnNotHonored(self):

    host = test_utils.CreateSantaHost(
        primary_user=user_map.EmailToUsername(self.user.key.id()),
        client_mode=MONITOR, client_mode_lock=True)
    roles._ChangeModeForHosts(LOCKDOWN, [self.user.key], honor_lock=False)

    host = host.key.get()
    self.assertFalse(host.client_mode_lock)
    self.assertEqual(LOCKDOWN, host.client_mode)

  def testNoModeChange(self):

    host = test_utils.CreateSantaHost(
        primary_user=user_map.EmailToUsername(self.user.key.id()),
        client_mode=LOCKDOWN)
    roles._ChangeModeForHosts(LOCKDOWN, [self.user.key])

    host = host.key.get()
    self.assertEqual(LOCKDOWN, host.client_mode)

  def testModeChange(self):

    host = test_utils.CreateSantaHost(
        primary_user=user_map.EmailToUsername(self.user.key.id()),
        client_mode=MONITOR)
    roles._ChangeModeForHosts(LOCKDOWN, [self.user.key])

    host = host.key.get()
    self.assertEqual(LOCKDOWN, host.client_mode)


class LockSpiderTest(basetest.UpvoteTestCase):
  """Test LockSpider cron class."""

  ROUTE = '/roles/lock-spider'

  def setUp(self):
    app = webapp2.WSGIApplication(routes=[roles.ROUTES])
    super(LockSpiderTest, self).setUp(wsgi_app=app)

  @mock.patch.object(roles.datastore_utils, 'QueuedPaginatedBatchApply')
  def testLockSpider(self, mock_query_util):
    response = self.testapp.get(self.ROUTE)

    self.assertEqual(httplib.OK, response.status_int)
    self.assertEqual(1, mock_query_util.call_count)


class SpiderBiteTest(basetest.UpvoteTestCase):
  """Test private function for simple lockdown."""

  def testSpiderBite(self):
    key_1 = test_utils.CreateSantaHost(
        client_mode=MONITOR).key
    key_2 = test_utils.CreateSantaHost(
        client_mode=MONITOR).key

    host_keys = [key_1, key_2]

    with mock.patch.object(
        roles.ndb, 'get_multi',
        return_value=[key_1.get(), key_2.get()]) as mock_get:
      with mock.patch.object(roles.ndb, 'put_multi') as mock_put:
        roles._SpiderBite(host_keys)

    self.assertEqual(1, mock_put.call_count)
    self.assertEqual(1, mock_get.call_count)
    self.assertEqual([key_1, key_2], mock_get.call_args[0][0])
    self.assertEqual([key_1.get(), key_2.get()], mock_put.call_args[0][0])
    self.assertEqual(key_1.get().client_mode, LOCKDOWN)
    self.assertEqual(key_2.get().client_mode, LOCKDOWN)


if __name__ == '__main__':
  basetest.main()
