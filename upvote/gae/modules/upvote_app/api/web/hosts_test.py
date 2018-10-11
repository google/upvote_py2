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

"""Unit tests for Hosts handlers."""

import datetime
import httplib

import webapp2

from upvote.gae.datastore import test_utils
from upvote.gae.datastore import utils as datastore_utils
from upvote.gae.datastore.models import bit9
from upvote.gae.datastore.models import exemption
from upvote.gae.datastore.models import santa
from upvote.gae.datastore.models import tickets
from upvote.gae.lib.testing import basetest
from upvote.gae.lib.testing import test_utils as common_test_utils
from upvote.gae.modules.upvote_app.api.web import hosts
from upvote.gae.shared.common import settings
from upvote.shared import constants


class HostsTest(basetest.UpvoteTestCase):
  """Base class for Hosts handler tests."""

  def setUp(self):
    app = webapp2.WSGIApplication(routes=[hosts.ROUTES])
    super(HostsTest, self).setUp(wsgi_app=app)

    self.santa_host_1 = santa.SantaHost(
        id='A-COOL-UUID1',
        hostname='user2.foo.bar.goog.co',
        primary_user='user',
        last_postflight_dt=datetime.datetime.utcnow())
    self.santa_host_2 = santa.SantaHost(
        id='A-COOL-UUID2',
        hostname='user2-blah.foo.bar.goog.co',
        primary_user='llcoolj',
        last_postflight_dt=datetime.datetime.utcnow())
    self.santa_host_3 = santa.SantaHost(
        id='A-COOL-UUID3',
        hostname='deck-the-halls.goog.co',
        client_mode=constants.SANTA_CLIENT_MODE.LOCKDOWN,
        client_mode_lock=False,
        primary_user='bubblebuddy',
        last_postflight_dt=datetime.datetime.utcnow())
    self.bit9_host_1 = bit9.Bit9Host(
        id='uuid3',
        hostname='bit-the-9.goog.co')

    self.santa_host_1.put()
    self.santa_host_2.put()
    self.santa_host_3.put()
    self.bit9_host_1.put()

    self.PatchValidateXSRFToken()


class HostQueryHandlerTest(HostsTest):
  """Test HostQueryHandler classes."""

  ROUTE = '/hosts/query'

  def testAdminGetList(self):
    """Admin gets a list of all hosts."""
    with self.LoggedInUser(admin=True):
      response = self.testapp.get(self.ROUTE)

    output = response.json

    self.assertIn('application/json', response.headers['Content-type'])
    self.assertIsInstance(output, dict)
    self.assertIsInstance(output['content'], list)
    self.assertEqual(len(output['content']), 4)

  def testAdminGetListPlatform(self):
    """Admin gets a list of all hosts specific to a single platform."""

    # Create a dummy host that shouldn't be included in the returned list.
    test_utils.CreateBit9Host()
    with self.LoggedInUser(admin=True):
      response = self.testapp.get(self.ROUTE + '/santa')

    output = response.json

    self.assertIn('application/json', response.headers['Content-type'])
    self.assertIsInstance(output, dict)
    self.assertIsInstance(output['content'], list)
    self.assertEqual(len(output['content']), 3)

  def testUserGetListNoPermissions(self):
    """Unprivileged user attempts to get a list of all hosts."""
    with self.LoggedInUser():
      self.testapp.get(self.ROUTE, status=httplib.FORBIDDEN)

  def testAdminGetQuery(self):
    """Admin queries for a host."""
    params = {
        'search': 'user2-blah.foo.bar.goog.co',
        'searchBase': 'hostname'}

    with self.LoggedInUser(admin=True):
      response = self.testapp.get(self.ROUTE, params)

    output = response.json

    self.assertIn('application/json', response.headers['Content-type'])
    self.assertIsInstance(output, dict)
    self.assertIsInstance(output['content'], list)
    self.assertEqual(len(output['content']), 1)

  def testAdminGetQueryPlatform(self):
    """Admin queries for a host on a specific platform."""
    params = {
        'search': self.santa_host_3.hostname,
        'searchBase': 'hostname'}

    with self.LoggedInUser(admin=True):
      response = self.testapp.get(self.ROUTE + '/santa', params)

    output = response.json

    self.assertIn('application/json', response.headers['Content-type'])
    self.assertIsInstance(output, dict)
    self.assertIsInstance(output['content'], list)
    self.assertEqual(len(output['content']), 1)

  def testAdminGetQueryBadField(self):
    """Admin queries for a host with an invalid field."""
    params = {
        'search': 'DoesntMatter',
        'searchBase': 'NotAField'}

    with self.LoggedInUser(admin=True):
      self.testapp.get(self.ROUTE, params, status=httplib.BAD_REQUEST)


class HostHandlerTest(HostsTest):
  """Test HostHandler class."""

  ROUTE = '/hosts/%s'

  def testAssociatedUserGet(self):
    """Normal user associated with a host gets it by ID."""
    blockable = test_utils.CreateBlockable()
    with self.LoggedInUser() as user:
      test_utils.CreateSantaEvent(
          blockable, host_id=self.santa_host_1.key.id(),
          executing_user=user.nickname,
          parent=datastore_utils.ConcatenateKeys(
              user.key, self.santa_host_1.key, blockable.key))
      self.assertTrue(self.santa_host_1.IsAssociatedWithUser(user))
      response = self.testapp.get(self.ROUTE % self.santa_host_1.key.id())

    output = response.json

    self.assertIn('application/json', response.headers['Content-type'])
    self.assertIsInstance(output, dict)

  def testAssociatedUserGet_PrimaryUser(self):
    """Normal user associated with a host gets it by ID."""
    with self.LoggedInUser() as user:
      self.santa_host_3.primary_user = user.nickname
      self.santa_host_3.put()
      self.assertTrue(self.santa_host_3.IsAssociatedWithUser(user))
      response = self.testapp.get(self.ROUTE % self.santa_host_3.key.id())

    output = response.json

    self.assertIn('application/json', response.headers['Content-type'])
    self.assertIsInstance(output, dict)

  def testUnknownUserGet(self):
    """Normal user not associated with a host attempts to get it by ID."""
    with self.LoggedInUser() as user:
      self.assertFalse(self.santa_host_1.IsAssociatedWithUser(user))
      self.testapp.get(
          self.ROUTE % self.santa_host_1.key.id(), status=httplib.FORBIDDEN)

  def testAdminGet(self):
    """Admin gets a single host by ID."""
    with self.LoggedInUser(admin=True):
      response = self.testapp.get(self.ROUTE % self.santa_host_1.key.id())

    output = response.json

    self.assertIn('application/json', response.headers['Content-type'])
    self.assertIsInstance(output, dict)

  def testAdminGet_UnknownID(self):
    """Admin attempts to get an unknown ID."""
    with self.LoggedInUser(admin=True):
      self.testapp.get(self.ROUTE % 'UnknownID', status=httplib.NOT_FOUND)

  def testAdminPost(self):
    """Admin posts a single host with no update params."""
    with self.LoggedInUser(admin=True):
      response = self.testapp.post(self.ROUTE % self.santa_host_1.key.id())

    output = response.json

    self.assertIn('application/json', response.headers['Content-type'])
    self.assertIsInstance(output, dict)

  def testAdminPost_UnknownID(self):
    """Admin attempts to post an unknown ID."""
    with self.LoggedInUser(admin=True):
      self.testapp.post(self.ROUTE % 'UnknownID', status=httplib.NOT_FOUND)

  def testAdminPost_Update(self):
    """Admin posts a single host with update params."""
    self.santa_host_1.should_upload_logs = False
    self.santa_host_1.client_mode_lock = True
    self.santa_host_1.client_mode = constants.SANTA_CLIENT_MODE.MONITOR
    self.santa_host_1.put()

    params = {
        'shouldUploadLogs': 'true',
        'clientModeLock': 'false',
        'clientMode': constants.SANTA_CLIENT_MODE.LOCKDOWN}

    with self.LoggedInUser(admin=True):
      response = self.testapp.post(
          self.ROUTE % self.santa_host_1.key.id(), params)

    output = response.json

    self.assertIn('application/json', response.headers['Content-type'])
    self.assertIsInstance(output, dict)

    self.assertTrue(self.santa_host_1.should_upload_logs)
    self.assertEqual(self.santa_host_1.client_mode,
                     constants.SANTA_CLIENT_MODE.LOCKDOWN)
    self.assertFalse(self.santa_host_1.client_mode_lock)


class AssociatedHostHandlerTest(HostsTest):

  SELF_ROUTE = '/hosts/associated'
  USER_ID_ROUTE = '/hosts/associated/%s'

  def testGetByUserId_IsAdmin(self):

    user = test_utils.CreateUser()
    bit9_host_id = test_utils.CreateBit9Host(users=[user.nickname]).key.id()

    santa_host_key = test_utils.CreateSantaHost(
        primary_user=user.nickname).key
    santa_host_id = santa_host_key.id()
    blockable = test_utils.CreateSantaBlockable()
    event_parent_key = datastore_utils.ConcatenateKeys(
        user.key, santa_host_key, blockable.key)
    test_utils.CreateSantaEvent(
        blockable, host_id=santa_host_id, parent=event_parent_key)

    with self.LoggedInUser(admin=True):
      response = self.testapp.get(self.USER_ID_ROUTE % user.key.id())

    output = response.json
    self.assertEqual(2, len(output))
    actual_ids = set(host['id'] for host in output)
    self.assertSetEqual(set([santa_host_id, bit9_host_id]), actual_ids)

  def testGetByUserId_NotAuthorized(self):
    other_user_id = test_utils.CreateUser().key.id()
    with self.LoggedInUser():
      self.testapp.get(
          self.USER_ID_ROUTE % other_user_id, status=httplib.FORBIDDEN)

  def testGetByUserId_UnknownUser(self):
    with self.LoggedInUser(admin=True):
      self.testapp.get(
          self.USER_ID_ROUTE % 'NotAUser', status=httplib.NOT_FOUND)

  def testGetSelf(self):

    user = test_utils.CreateUser()
    host_id_1 = test_utils.CreateBit9Host(users=[user.nickname]).key.id()
    host_id_2 = test_utils.CreateBit9Host(users=[user.nickname]).key.id()

    with self.LoggedInUser(user=user):
      response = self.testapp.get(self.SELF_ROUTE)

    output = response.json
    expected_host_ids = [host_id_1, host_id_2]
    actual_host_ids = [host['id'] for host in output]
    self.assertListEqual(sorted(expected_host_ids), sorted(actual_host_ids))

  def testGetSelf_Sorted(self):
    """Hosts are sorted by their rule_sync_dts."""
    early, middle, recent, recenter = common_test_utils.GetSequentialTimes(4)

    user = test_utils.CreateUser()

    santa_host_1 = test_utils.CreateSantaHost(
        primary_user=user.nickname, rule_sync_dt=early)
    santa_host_2 = test_utils.CreateSantaHost(
        primary_user=user.nickname, rule_sync_dt=middle)
    test_utils.CreateSantaHost(rule_sync_dt=recent)
    bit9_host_1 = test_utils.CreateBit9Host(
        users=[user.nickname], last_event_dt=recenter)

    self.assertTrue(santa_host_1.IsAssociatedWithUser(user))
    self.assertTrue(santa_host_2.IsAssociatedWithUser(user))
    self.assertTrue(bit9_host_1.IsAssociatedWithUser(user))

    with self.LoggedInUser(user=user):
      response = self.testapp.get(self.SELF_ROUTE)
    output = response.json

    self.assertIn('application/json', response.headers['Content-type'])

    self.assertEqual(3, len(output))
    expected_host_ids = [
        bit9_host_1.key.id(), santa_host_2.key.id(), santa_host_1.key.id()]
    actual_host_ids = [entry['id'] for entry in output]
    self.assertListEqual(sorted(expected_host_ids), sorted(actual_host_ids))

  def testGetSelf_NeverSyncedRules(self):

    user = test_utils.CreateUser()

    test_utils.CreateSantaHost(
        primary_user=user.nickname, rule_sync_dt=None)
    santa_host_2 = test_utils.CreateSantaHost(
        primary_user=user.nickname, rule_sync_dt=datetime.datetime.utcnow())
    test_utils.CreateBit9Host(
        users=[user.nickname], last_event_dt=None)

    with self.LoggedInUser(user=user):
      response = self.testapp.get(self.SELF_ROUTE)

    output = response.json
    self.assertIn('application/json', response.headers['Content-type'])

    self.assertEqual(santa_host_2.key.id(), output[0]['id'])

  def testGetSelf_NoHosts(self):
    with self.LoggedInUser():
      response = self.testapp.get(self.SELF_ROUTE)
    output = response.json
    self.assertEqual(0, len(output))


class HostExceptionHandlerTest(HostsTest):
  """Test HostExceptionHandler class."""

  ROUTE = '/hosts/%s/request-exception'

  def setUp(self):
    super(HostExceptionHandlerTest, self).setUp()

    self.user = test_utils.CreateUser(admin=True)

    self.santa_blockable = test_utils.CreateSantaBlockable()
    self.santa_event = test_utils.CreateSantaEvent(
        self.santa_blockable,
        host_id=self.santa_host_3.key.id(),
        executing_user=self.user.nickname,
        parent=datastore_utils.ConcatenateKeys(
            self.user.key, self.santa_host_3.key,
            self.santa_blockable.key))

    self.santa_blockable.put()
    self.santa_event.put()

    self.PatchEnv(settings.ProdEnv, ENABLE_BIGQUERY_STREAMING=True)

  def testCreateHostException_Success(self):
    params = {'reason': constants.HOST_EXEMPTION_REASON.DEVELOPER_MACOS}
    with self.LoggedInUser(user=self.user):
      response = self.testapp.post(
          self.ROUTE % self.santa_host_3.key.id(), params)
    self.assertEqual(httplib.OK, response.status_int)
    self.assertEqual(response.json['id'], self.santa_host_3.key.id())

    self.assertBigQueryInsertions([
        constants.BIGQUERY_TABLE.HOST,
    ])

    ticket = tickets.HostExceptionTicket.query().get()
    self.assertEqual(self.santa_host_3.key.id(), ticket.host_id)
    self.assertEqual(self.user.email, ticket.user_id)
    self.assertEqual(
        constants.HOST_EXEMPTION_REASON.DEVELOPER_MACOS, ticket.reason)
    self.assertIsNone(ticket.other_text)

    updated_host = self.santa_host_3.key.get()
    self.assertTrue(updated_host.client_mode_lock)
    self.assertEqual(
        constants.SANTA_CLIENT_MODE.MONITOR, updated_host.client_mode)

  def testCreateHostException_ReRequest(self):

    params = {'reason': constants.HOST_EXEMPTION_REASON.DEVELOPER_MACOS}
    with self.LoggedInUser(user=self.user):
      response = self.testapp.post(
          self.ROUTE % self.santa_host_3.key.id(), params)
    self.assertEqual(httplib.OK, response.status_int)
    self.assertEqual(response.json['id'], self.santa_host_3.key.id())

    self.assertBigQueryInsertions([
        constants.BIGQUERY_TABLE.HOST,
    ])

    host = self.santa_host_3.key.get()
    self.assertTrue(host.client_mode_lock)
    self.assertEqual(
        constants.SANTA_CLIENT_MODE.MONITOR, host.client_mode)

    # Revert the client mode.
    host.client_mode_lock = True
    host.client_mode = constants.SANTA_CLIENT_MODE.LOCKDOWN
    host.put()

    # Request again.
    params = {'reason': constants.HOST_EXEMPTION_REASON.DEVELOPER_MACOS}
    with self.LoggedInUser(user=self.user):
      response = self.testapp.post(
          self.ROUTE % self.santa_host_3.key.id(), params)
    self.assertEqual(httplib.OK, response.status_int)
    self.assertEqual(response.json['id'], self.santa_host_3.key.id())

    self.assertBigQueryInsertion(constants.BIGQUERY_TABLE.HOST)

    host = self.santa_host_3.key.get()
    self.assertTrue(host.client_mode_lock)
    self.assertEqual(
        constants.SANTA_CLIENT_MODE.MONITOR, host.client_mode)

  def testCreateHostException_OtherReason(self):
    params = {'reason': constants.HOST_EXEMPTION_REASON.OTHER,
              'otherText': 'foo'}
    with self.LoggedInUser(user=self.user):
      self.testapp.post(self.ROUTE % self.santa_host_3.key.id(), params)

    self.assertBigQueryInsertions([
        constants.BIGQUERY_TABLE.HOST,
    ])

    ticket = tickets.HostExceptionTicket.query().get()
    self.assertEqual(constants.HOST_EXEMPTION_REASON.OTHER, ticket.reason)
    self.assertEqual('foo', ticket.other_text)

    updated_host = self.santa_host_3.key.get()
    self.assertTrue(updated_host.client_mode_lock)
    self.assertEqual(
        constants.SANTA_CLIENT_MODE.MONITOR, updated_host.client_mode)

  def testCreateHostException_UnknownHost(self):
    params = {'reason': constants.HOST_EXEMPTION_REASON.DEVELOPER_MACOS}
    with self.LoggedInUser(user=self.user):
      self.testapp.post(
          self.ROUTE % 'NotAHost', params, status=httplib.NOT_FOUND)

  def testCreateHostException_AdminCreate(self):
    with self.LoggedInUser(admin=True) as admin:
      self.assertFalse(self.santa_host_3.IsAssociatedWithUser(admin))

      params = {'reason': constants.HOST_EXEMPTION_REASON.DEVELOPER_MACOS}
      response = self.testapp.post(
          self.ROUTE % self.santa_host_3.key.id(), params)

      self.assertBigQueryInsertions([
          constants.BIGQUERY_TABLE.HOST,
      ])

      self.assertTrue(response)
      self.assertTrue(tickets.HostExceptionTicket.query().get())

  def testCreateHostException_UnownedHost(self):
    superuser = test_utils.CreateUser(
        roles=[constants.USER_ROLE.SUPERUSER])
    params = {'reason': constants.HOST_EXEMPTION_REASON.DEVELOPER_MACOS}
    with self.LoggedInUser(user=superuser):
      self.testapp.post(
          self.ROUTE % self.santa_host_2.key.id(), params,
          status=httplib.FORBIDDEN)

  def testCreateHostException_ExistingTicket(self):
    params = {'reason': constants.HOST_EXEMPTION_REASON.DEVELOPER_MACOS}
    with self.LoggedInUser(user=self.user):
      response = self.testapp.post(
          self.ROUTE % self.santa_host_3.key.id(), params)
    self.assertEqual(httplib.OK, response.status_int)

    self.assertBigQueryInsertions([
        constants.BIGQUERY_TABLE.HOST,
    ])


  def testCreateHostException_NoReason(self):
    with self.LoggedInUser(user=self.user):
      self.testapp.post(
          self.ROUTE % self.santa_host_3.key.id(), status=httplib.BAD_REQUEST)

  def testCreateHostException_BadReason(self):
    params = {'reason': 'NotARealReason'}
    with self.LoggedInUser(user=self.user):
      self.testapp.post(
          self.ROUTE % self.santa_host_3.key.id(), params,
          status=httplib.BAD_REQUEST)

  def testCreateHostException_NoOtherReason(self):
    params = {'reason': constants.HOST_EXEMPTION_REASON.OTHER}
    with self.LoggedInUser(user=self.user):
      self.testapp.post(
          self.ROUTE % self.santa_host_3.key.id(), params,
          status=httplib.BAD_REQUEST)

  def testGetHostException(self):
    tickets.HostExceptionTicket.get_open_or_insert_did_insert(
        self.user.key.id(), self.santa_host_3.key.id())

    with self.LoggedInUser(user=self.user):
      response = self.testapp.get(self.ROUTE % self.santa_host_3.key.id())

    output = response.json

    self.assertEqual(self.user.email, output['userId'])
    self.assertEqual(self.santa_host_3.key.id(), output['hostId'])

  def testGetHostException_UnknownHost(self):
    with self.LoggedInUser(user=self.user):
      self.testapp.get(self.ROUTE % 'NotAHost', status=httplib.NOT_FOUND)

  def testGetHostException_UnownedHost(self):
    with self.LoggedInUser():
      self.testapp.get(
          self.ROUTE % self.santa_host_2.key.id(), status=httplib.FORBIDDEN)

  def testGetHostException_NoTicket(self):
    with self.LoggedInUser(user=self.user):
      self.testapp.get(
          self.ROUTE % self.santa_host_3.key.id(), status=httplib.NOT_FOUND)

  def testGetHostException_GetByOtherUsername(self):
    with self.LoggedInUser(admin=True) as admin:
      tickets.HostExceptionTicket.get_open_or_insert_did_insert(
          admin.key.id(), self.santa_host_3.key.id())

      params = {'user_id': admin.email}
      response = self.testapp.get(
          self.ROUTE % self.santa_host_3.key.id(), params)
      self.assertEqual(httplib.OK, response.status_int)

  def testGetHostException_AdminGetByOtherUsername(self):
    tickets.HostExceptionTicket.get_open_or_insert_did_insert(
        self.user.key.id(), self.santa_host_3.key.id())

    params = {'user_id': self.user.email}
    with self.LoggedInUser(admin=True):
      response = self.testapp.get(
          self.ROUTE % self.santa_host_3.key.id(), params)
    self.assertEqual(httplib.OK, response.status_int)


class LockdownHandlerTest(HostsTest):
  """Test LockdownHandler class."""

  ROUTE = '/hosts/%s/request-lockdown'

  def setUp(self):
    super(LockdownHandlerTest, self).setUp()

    self.user = test_utils.CreateUser()

    self.santa_blockable = test_utils.CreateSantaBlockable()
    self.santa_event = test_utils.CreateSantaEvent(
        self.santa_blockable,
        host_id=self.santa_host_3.key.id(),
        parent=datastore_utils.ConcatenateKeys(
            self.user.key, self.santa_host_3.key, self.santa_blockable.key))

    self.santa_blockable.put()
    self.santa_event.put()

    self.santa_host_3.client_mode = constants.SANTA_CLIENT_MODE.MONITOR
    self.santa_host_3.put()

  def testPost(self):
    with self.LoggedInUser(user=self.user):
      response = self.testapp.post(self.ROUTE % self.santa_host_3.key.id())
    self.assertEqual(httplib.OK, response.status_int)
    self.assertEqual(response.json['id'], self.santa_host_3.key.id())

    updated_host = self.santa_host_3.key.get()
    self.assertEqual(
        response.json['clientModeLock'], updated_host.client_mode_lock)
    self.assertTrue(updated_host.client_mode_lock)
    self.assertEqual(
        constants.SANTA_CLIENT_MODE.LOCKDOWN, updated_host.client_mode)

    self.assertBigQueryInsertions([constants.BIGQUERY_TABLE.HOST])

  def testPost_Admin(self):
    with self.LoggedInUser(admin=True):
      response = self.testapp.post(self.ROUTE % self.santa_host_3.key.id())
    self.assertEqual(httplib.OK, response.status_int)

    updated_host = self.santa_host_3.key.get()
    self.assertTrue(updated_host.client_mode_lock)
    self.assertEqual(
        constants.SANTA_CLIENT_MODE.LOCKDOWN, updated_host.client_mode)

    self.assertBigQueryInsertions([constants.BIGQUERY_TABLE.HOST])

  def testPost_UnknownHost(self):
    with self.LoggedInUser(user=self.user):
      self.testapp.post(self.ROUTE % 'NotAHost', status=httplib.NOT_FOUND)

  def testPost_UnownedHost(self):
    with self.LoggedInUser(user=self.user):
      self.testapp.post(
          self.ROUTE % self.santa_host_2.key.id(), status=httplib.FORBIDDEN)


class VisibilityHandlerTest(HostsTest):

  ROUTE = '/hosts/%s/hidden/%s'

  def setUp(self):
    super(VisibilityHandlerTest, self).setUp()

    self.user = test_utils.CreateUser()

    self.santa_host_1.primary_user = self.user.nickname
    self.santa_host_1.hidden = False
    self.santa_host_1.put()

  def testUnhide_Success(self):
    self.santa_host_1.hidden = True
    self.santa_host_1.put()

    with self.LoggedInUser(user=self.user):
      self.testapp.put(
          self.ROUTE % (self.santa_host_1.key.id(), 'false'), status=httplib.OK)
    self.assertFalse(self.santa_host_1.key.get().hidden)

  def testHide_Success(self):
    with self.LoggedInUser(user=self.user):
      self.testapp.put(
          self.ROUTE % (self.santa_host_1.key.id(), 'true'), status=httplib.OK)
    self.assertTrue(self.santa_host_1.key.get().hidden)

  def testHide_Capital(self):
    with self.LoggedInUser(user=self.user):
      self.testapp.put(
          self.ROUTE % (self.santa_host_1.key.id(), 'True'), status=httplib.OK)
    self.assertTrue(self.santa_host_1.key.get().hidden)

  def testHide_Forbidden(self):
    with self.LoggedInUser():
      self.testapp.put(
          self.ROUTE % (self.santa_host_1.key.id(), 'true'),
          status=httplib.FORBIDDEN)
    self.assertFalse(self.santa_host_1.key.get().hidden)

  def testHide_NotFound(self):
    with self.LoggedInUser(user=self.user):
      self.testapp.put(self.ROUTE % ('DNE', 'true'), status=httplib.NOT_FOUND)

  def testHide_BadRequest(self):
    with self.LoggedInUser(user=self.user):
      self.testapp.put(
          self.ROUTE % (self.santa_host_1.key.id(), 'badrequest'),
          status=httplib.BAD_REQUEST)
    self.assertFalse(self.santa_host_1.key.get().hidden)


if __name__ == '__main__':
  basetest.main()
