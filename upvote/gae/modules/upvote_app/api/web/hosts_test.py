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

import mock
import webapp2

from upvote.gae.datastore import test_utils
from upvote.gae.datastore import utils as datastore_utils
from upvote.gae.datastore.models import host as host_models
from upvote.gae.datastore.models import utils as model_utils
from upvote.gae.lib.testing import basetest
from upvote.gae.lib.testing import test_utils as common_test_utils
from upvote.gae.modules.upvote_app.api.web import hosts
from upvote.shared import constants


class HostsTest(basetest.UpvoteTestCase):
  """Base class for Hosts handler tests."""

  def setUp(self):
    app = webapp2.WSGIApplication(routes=[hosts.ROUTES])
    super(HostsTest, self).setUp(wsgi_app=app)

    self.santa_host_1 = host_models.SantaHost(
        id='A-COOL-UUID1',
        hostname='user2.foo.bar.goog.co',
        primary_user='user',
        last_postflight_dt=datetime.datetime.utcnow())
    self.santa_host_2 = host_models.SantaHost(
        id='A-COOL-UUID2',
        hostname='user2-blah.foo.bar.goog.co',
        primary_user='llcoolj',
        last_postflight_dt=datetime.datetime.utcnow())
    self.santa_host_3 = host_models.SantaHost(
        id='A-COOL-UUID3',
        hostname='deck-the-halls.goog.co',
        client_mode=constants.CLIENT_MODE.LOCKDOWN,
        client_mode_lock=False,
        primary_user='bubblebuddy',
        last_postflight_dt=datetime.datetime.utcnow())
    self.bit9_host_1 = host_models.Bit9Host(
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
    self.assertLen(output['content'], 4)

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
    self.assertLen(output['content'], 3)

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
    self.assertLen(output['content'], 1)

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
    self.assertLen(output['content'], 1)

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

  def testGet_AssociatedUser(self):

    user = test_utils.CreateUser()
    host = test_utils.CreateSantaHost(primary_user=user.nickname)
    test_utils.CreateExemption(host.key.id())
    blockable = test_utils.CreateBlockable()
    test_utils.CreateSantaEvent(
        blockable, host_id=host.key.id(), executing_user=user.nickname,
        parent=datastore_utils.ConcatenateKeys(
            user.key, host.key, blockable.key))
    self.assertTrue(model_utils.IsHostAssociatedWithUser(host, user))

    with self.LoggedInUser(user=user):
      response = self.testapp.get(self.ROUTE % host.key.id())

    output = response.json

    self.assertIn('application/json', response.headers['Content-type'])
    self.assertIsInstance(output, dict)
    self.assertIn('exemption', output)

  def testGet_AssociatedUser_PrimaryUser(self):

    user = test_utils.CreateUser()
    host = test_utils.CreateSantaHost(primary_user=user.nickname)
    test_utils.CreateExemption(host.key.id())
    self.assertTrue(model_utils.IsHostAssociatedWithUser(host, user))

    with self.LoggedInUser(user=user):
      response = self.testapp.get(self.ROUTE % host.key.id())

    output = response.json

    self.assertIn('application/json', response.headers['Content-type'])
    self.assertIsInstance(output, dict)
    self.assertIn('exemption', output)

  def testGet_UnknownUser(self):

    user = test_utils.CreateUser()
    host = test_utils.CreateSantaHost(primary_user=user.nickname)

    with self.LoggedInUser() as other_user:
      self.assertFalse(model_utils.IsHostAssociatedWithUser(host, other_user))
      self.testapp.get(self.ROUTE % host.key.id(), status=httplib.FORBIDDEN)

  def testGet_Admin(self):

    user = test_utils.CreateUser()
    host = test_utils.CreateSantaHost(primary_user=user.nickname)
    test_utils.CreateExemption(host.key.id())

    with self.LoggedInUser(admin=True):
      response = self.testapp.get(self.ROUTE % host.key.id())

    output = response.json

    self.assertIn('application/json', response.headers['Content-type'])
    self.assertIsInstance(output, dict)
    self.assertIn('exemption', output)

  def testGet_Admin_UnknownID(self):
    with self.LoggedInUser(admin=True):
      self.testapp.get(self.ROUTE % 'UnknownID', status=httplib.NOT_FOUND)

  def testPost_Admin(self):

    user = test_utils.CreateUser()
    host = test_utils.CreateSantaHost(primary_user=user.nickname)
    test_utils.CreateExemption(host.key.id())

    with self.LoggedInUser(admin=True):
      response = self.testapp.post(self.ROUTE % host.key.id())

    output = response.json

    self.assertIn('application/json', response.headers['Content-type'])
    self.assertIsInstance(output, dict)

  def testPost_Admin_UnknownID(self):
    with self.LoggedInUser(admin=True):
      self.testapp.post(self.ROUTE % 'UnknownID', status=httplib.NOT_FOUND)

  def testPost_Admin_Update(self):

    user = test_utils.CreateUser()
    host = test_utils.CreateSantaHost(
        primary_user=user.nickname, client_mode_lock=True,
        client_mode=constants.CLIENT_MODE.MONITOR)

    params = {
        'clientModeLock': 'false',
        'clientMode': constants.CLIENT_MODE.LOCKDOWN}

    with self.LoggedInUser(admin=True):
      response = self.testapp.post(self.ROUTE % host.key.id(), params)

    output = response.json

    self.assertIn('application/json', response.headers['Content-type'])
    self.assertIsInstance(output, dict)

    self.assertEqual(host.client_mode, constants.CLIENT_MODE.LOCKDOWN)
    self.assertFalse(host.client_mode_lock)


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
    self.assertLen(output, 2)
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

  def testGetByUserId_WithExemption(self):

    user = test_utils.CreateUser()
    bit9_host_id = test_utils.CreateBit9Host(users=[user.nickname]).key.id()
    test_utils.CreateExemption(bit9_host_id).get()

    with self.LoggedInUser(admin=True):
      response = self.testapp.get(self.USER_ID_ROUTE % user.key.id())

    output = response.json
    self.assertLen(output, 1)
    self.assertIn('exemption', output[0])
    self.assertIsNotNone(output[0]['exemption'])

  def testGetByUserId_WithoutExemption(self):

    user = test_utils.CreateUser()
    test_utils.CreateBit9Host(users=[user.nickname]).key.id()

    with self.LoggedInUser(admin=True):
      response = self.testapp.get(self.USER_ID_ROUTE % user.key.id())

    output = response.json
    self.assertLen(output, 1)
    self.assertIn('exemption', output[0])
    self.assertIsNone(output[0]['exemption'])

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

    self.assertTrue(model_utils.IsHostAssociatedWithUser(santa_host_1, user))
    self.assertTrue(model_utils.IsHostAssociatedWithUser(santa_host_2, user))
    self.assertTrue(model_utils.IsHostAssociatedWithUser(bit9_host_1, user))

    with self.LoggedInUser(user=user):
      response = self.testapp.get(self.SELF_ROUTE)
    output = response.json

    self.assertIn('application/json', response.headers['Content-type'])

    self.assertLen(output, 3)
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
    self.assertLen(output, 0)

  def testGetSelf_WithExemption(self):

    user = test_utils.CreateUser()
    bit9_host_id = test_utils.CreateBit9Host(users=[user.nickname]).key.id()
    test_utils.CreateExemption(bit9_host_id)

    with self.LoggedInUser(user=user):
      response = self.testapp.get(self.SELF_ROUTE)

    output = response.json
    self.assertLen(output, 1)
    self.assertIn('exemption', output[0])
    self.assertIsNotNone(output[0]['exemption'])

  def testGetSelf_WithoutExemption(self):

    user = test_utils.CreateUser()
    test_utils.CreateBit9Host(users=[user.nickname]).key.id()

    with self.LoggedInUser(user=user):
      response = self.testapp.get(self.SELF_ROUTE)

    output = response.json
    self.assertLen(output, 1)
    self.assertIn('exemption', output[0])
    self.assertIsNone(output[0]['exemption'])


class BooleanPropertyHandlerTest(basetest.UpvoteTestCase):

  ROUTE = '/hosts/%s/hidden/%s'

  def setUp(self):
    app = webapp2.WSGIApplication(routes=[hosts.ROUTES])
    super(BooleanPropertyHandlerTest, self).setUp(wsgi_app=app)
    self.PatchValidateXSRFToken()

  def testDispatch_HostNotFound(self):
    with self.LoggedInUser():
      url = self.ROUTE % ('missing_host_id', 'false')
      self.testapp.put(url, status=httplib.NOT_FOUND)

  def testDispatch_UserNotAssociated(self):

    user = test_utils.CreateUser()
    host = test_utils.CreateSantaHost(primary_user='someone_else')
    host.put()

    with self.LoggedInUser(user=user):
      url = self.ROUTE % (host.key.id(), 'false')
      self.testapp.put(url, status=httplib.FORBIDDEN)

  def testDispatch_InvalidNewValue(self):

    user = test_utils.CreateUser()
    host = test_utils.CreateSantaHost(primary_user=user.nickname)
    host.put()

    with self.LoggedInUser(user=user):
      url = self.ROUTE % (host.key.id(), 'blah')
      self.testapp.put(url, status=httplib.BAD_REQUEST)


class VisibilityHandlerTest(basetest.UpvoteTestCase):

  ROUTE = '/hosts/%s/hidden/%s'

  def setUp(self):
    app = webapp2.WSGIApplication(routes=[hosts.ROUTES])
    super(VisibilityHandlerTest, self).setUp(wsgi_app=app)
    self.PatchValidateXSRFToken()

  def testHide(self):

    user = test_utils.CreateUser()
    host = test_utils.CreateSantaHost(primary_user=user.nickname, hidden=False)

    with self.LoggedInUser(user=user):
      url = self.ROUTE % (host.key.id(), 'true')
      self.testapp.put(url, status=httplib.OK)
    self.assertTrue(host.key.get().hidden)

  def testReveal(self):

    user = test_utils.CreateUser()
    host = test_utils.CreateSantaHost(primary_user=user.nickname, hidden=True)

    with self.LoggedInUser(user=user):
      url = self.ROUTE % (host.key.id(), 'false')
      self.testapp.put(url, status=httplib.OK)
    self.assertFalse(host.key.get().hidden)


class TransitiveHandlerTest(basetest.UpvoteTestCase):

  ROUTE = '/hosts/%s/transitive/%s'

  def setUp(self):
    app = webapp2.WSGIApplication(routes=[hosts.ROUTES])
    super(TransitiveHandlerTest, self).setUp(wsgi_app=app)
    self.PatchValidateXSRFToken()

  @mock.patch.object(hosts.exemption_api, 'ChangeTransitiveWhitelisting')
  def testPut_WithExemption(self, mock_change):

    user = test_utils.CreateUser()
    host = test_utils.CreateSantaHost(primary_user=user.nickname)
    test_utils.CreateExemption(host.key.id())

    with self.LoggedInUser(user=user):
      url = self.ROUTE % (host.key.id(), 'false')
      response = self.testapp.put(url, status=httplib.OK)

    output = response.json

    self.assertIn('application/json', response.headers['Content-type'])
    self.assertIsInstance(output, dict)
    self.assertIn('transitiveWhitelistingEnabled', output)
    self.assertIn('exemption', output)
    mock_change.assert_called_once()

  @mock.patch.object(hosts.exemption_api, 'ChangeTransitiveWhitelisting')
  def testPut_WithoutExemption(self, mock_change):

    user = test_utils.CreateUser()
    host = test_utils.CreateSantaHost(primary_user=user.nickname)

    with self.LoggedInUser(user=user):
      url = self.ROUTE % (host.key.id(), 'false')
      response = self.testapp.put(url, status=httplib.OK)

    output = response.json

    self.assertIn('application/json', response.headers['Content-type'])
    self.assertIsInstance(output, dict)
    self.assertIn('transitiveWhitelistingEnabled', output)
    self.assertNotIn('exemption', output)
    mock_change.assert_called_once()


if __name__ == '__main__':
  basetest.main()
