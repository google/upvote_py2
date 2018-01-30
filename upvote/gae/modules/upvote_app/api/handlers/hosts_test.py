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

from upvote.gae.modules.upvote_app.api.handlers import hosts
from upvote.gae.shared.common import basetest
from upvote.gae.shared.common import test_utils as common_test_utils
from upvote.gae.shared.models import bigquery
from upvote.gae.shared.models import bit9
from upvote.gae.shared.models import santa
from upvote.gae.shared.models import test_utils
from upvote.gae.shared.models import tickets
from upvote.gae.shared.models import utils
from upvote.shared import constants


class HostsTest(basetest.UpvoteTestCase):
  """Base class for Hosts handler tests."""

  def setUp(self, app):
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

  def setUp(self):
    app = webapp2.WSGIApplication([
        webapp2.Route(r'/santa', handler=hosts.SantaHostQueryHandler),
        webapp2.Route(r'', handler=hosts.HostQueryHandler)])
    super(HostQueryHandlerTest, self).setUp(app)

  def testAdminGetList(self):
    """Admin gets a list of all hosts."""
    with self.LoggedInUser(admin=True):
      response = self.testapp.get('')

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
      response = self.testapp.get('/santa')

    output = response.json

    self.assertIn('application/json', response.headers['Content-type'])
    self.assertIsInstance(output, dict)
    self.assertIsInstance(output['content'], list)
    self.assertEqual(len(output['content']), 3)

  def testUserGetListNoPermissions(self):
    """Unprivileged user attempts to get a list of all hosts."""
    with self.LoggedInUser():
      self.testapp.get('', status=httplib.FORBIDDEN)

  def testAdminGetQuery(self):
    """Admin queries for a host."""
    params = {
        'search': 'user2-blah.foo.bar.goog.co',
        'searchBase': 'hostname'}

    with self.LoggedInUser(admin=True):
      response = self.testapp.get('', params)

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
      response = self.testapp.get('/santa', params)

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
      self.testapp.get('', params, status=httplib.BAD_REQUEST)


class HostHandlerTest(HostsTest):
  """Test HostHandler class."""

  def setUp(self):
    app = webapp2.WSGIApplication(
        [webapp2.Route(r'/<host_id>', handler=hosts.HostHandler)])
    super(HostHandlerTest, self).setUp(app)

  def testAssociatedUserGet(self):
    """Normal user associated with a host gets it by ID."""
    blockable = test_utils.CreateBlockable()
    with self.LoggedInUser() as user:
      test_utils.CreateSantaEvent(
          blockable, host_id=self.santa_host_1.key.id(),
          executing_user=user.nickname,
          parent=utils.ConcatenateKeys(
              user.key, self.santa_host_1.key, blockable.key))
      self.assertTrue(self.santa_host_1.IsAssociatedWithUser(user))
      response = self.testapp.get('/' + self.santa_host_1.key.id())

    output = response.json

    self.assertIn('application/json', response.headers['Content-type'])
    self.assertIsInstance(output, dict)

  def testAssociatedUserGet_PrimaryUser(self):
    """Normal user associated with a host gets it by ID."""
    with self.LoggedInUser() as user:
      self.santa_host_3.primary_user = user.nickname
      self.santa_host_3.put()
      self.assertTrue(self.santa_host_3.IsAssociatedWithUser(user))
      response = self.testapp.get('/' + self.santa_host_3.key.id())

    output = response.json

    self.assertIn('application/json', response.headers['Content-type'])
    self.assertIsInstance(output, dict)

  def testUnknownUserGet(self):
    """Normal user not associated with a host attempts to get it by ID."""
    with self.LoggedInUser() as user:
      self.assertFalse(self.santa_host_1.IsAssociatedWithUser(user))
      self.testapp.get(
          '/' + self.santa_host_1.key.id(), status=httplib.FORBIDDEN)

  def testAdminGet(self):
    """Admin gets a single host by ID."""
    with self.LoggedInUser(admin=True):
      response = self.testapp.get('/' + self.santa_host_1.key.id())

    output = response.json

    self.assertIn('application/json', response.headers['Content-type'])
    self.assertIsInstance(output, dict)

  def testAdminGet_UnknownID(self):
    """Admin attempts to get an unknown ID."""
    with self.LoggedInUser(admin=True):
      self.testapp.get('/UnknownID', status=httplib.NOT_FOUND)

  def testAdminPost(self):
    """Admin posts a single host with no update params."""
    with self.LoggedInUser(admin=True):
      response = self.testapp.post('/' + self.santa_host_1.key.id())

    output = response.json

    self.assertIn('application/json', response.headers['Content-type'])
    self.assertIsInstance(output, dict)

  def testAdminPost_UnknownID(self):
    """Admin attempts to post an unknown ID."""
    with self.LoggedInUser(admin=True):
      self.testapp.post('/UnknownID', status=httplib.NOT_FOUND)

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
      response = self.testapp.post('/' + self.santa_host_1.key.id(), params)

    output = response.json

    self.assertIn('application/json', response.headers['Content-type'])
    self.assertIsInstance(output, dict)

    self.assertTrue(self.santa_host_1.should_upload_logs)
    self.assertEqual(self.santa_host_1.client_mode,
                     constants.SANTA_CLIENT_MODE.LOCKDOWN)
    self.assertFalse(self.santa_host_1.client_mode_lock)


class AssociatedHostHandlerTest(HostsTest):
  """Test HostHandler class."""

  def setUp(self):
    app = webapp2.WSGIApplication([
        webapp2.Route(r'/', handler=hosts.AssociatedHostHandler,
                      handler_method='GetSelf'),
        webapp2.Route(r'/<user_id:.*>', handler=hosts.AssociatedHostHandler,
                      handler_method='GetByUserId')])
    super(AssociatedHostHandlerTest, self).setUp(app)

    self.user = test_utils.CreateUser()
    self.admin = test_utils.CreateUser(admin=True)

    self.santa_blockable = test_utils.CreateSantaBlockable()
    self.santa_event = test_utils.CreateSantaEvent(
        self.santa_blockable,
        host_id=self.santa_host_1.key.id(),
        executing_user=self.user.nickname,
        parent=utils.ConcatenateKeys(
            self.user.key, self.santa_host_1.key, self.santa_blockable.key))

    self.bit9_host_1.users = [self.user.nickname]
    self.bit9_host_1.put()

  def testGetByUserId(self):
    with self.LoggedInUser(user=self.admin):
      response = self.testapp.get('/' + self.user.key.id())
    output = response.json
    self.assertEqual(2, len(output))
    ids = set(host['id'] for host in output)
    self.assertSetEqual(
        set([self.santa_host_1.key.id(), self.bit9_host_1.key.id()]), ids)

  def testGetByUserId_NotAuthorized(self):
    with self.LoggedInUser(user=self.user):
      self.testapp.get('/' + self.admin.key.id(), status=httplib.FORBIDDEN)

  def testGetByUserId_UnknownUser(self):
    with self.LoggedInUser(user=self.admin):
      self.testapp.get('/NotAUser', status=httplib.NOT_FOUND)

  def testGetSelf(self):
    with self.LoggedInUser(user=self.user):
      response = self.testapp.get('/')
    output = response.json
    self.assertEqual(2, len(output))

  def testGetSelf_Sorted(self):
    """Hosts are sorted by their rule_sync_dts."""
    early, middle, recent, recenter = common_test_utils.GetSequentialTimes(4)

    self.santa_host_1.rule_sync_dt = early
    self.santa_host_2.rule_sync_dt = middle
    self.santa_host_2.primary_user = self.user.nickname
    self.santa_host_3.rule_sync_dt = recent
    self.bit9_host_1.last_event_dt = recenter

    self.santa_host_1.put()
    self.santa_host_2.put()
    self.santa_host_3.put()
    self.bit9_host_1.put()

    self.assertTrue(self.santa_host_1.IsAssociatedWithUser(self.user))
    self.assertTrue(self.santa_host_2.IsAssociatedWithUser(self.user))
    self.assertTrue(self.bit9_host_1.IsAssociatedWithUser(self.user))

    with self.LoggedInUser(user=self.user):
      response = self.testapp.get('/')
    output = response.json

    self.assertIn('application/json', response.headers['Content-type'])

    self.assertEqual(3, len(output))
    self.assertListEqual(
        [self.bit9_host_1.key.id(), self.santa_host_2.key.id(),
         self.santa_host_1.key.id()],
        [entry['id'] for entry in output])

  def testGetSelf_NeverSyncedRules(self):
    self.santa_host_1.rule_sync_dt = None
    self.santa_host_2.rule_sync_dt = datetime.datetime.utcnow()
    self.santa_host_2.primary_user = self.user.nickname
    self.bit9_host_1.last_event_dt = None

    self.santa_host_1.put()
    self.santa_host_2.put()
    self.bit9_host_1.put()

    with self.LoggedInUser(user=self.user):
      response = self.testapp.get('/')
    output = response.json
    self.assertIn('application/json', response.headers['Content-type'])

    self.assertEqual(self.santa_host_2.key.id(), output[0]['id'])

  def testGetSelf_NonexistentHostId(self):
    """Host IDs that don't exist are ignored."""
    self.santa_host_1.key.delete()
    self.bit9_host_1.key.delete()
    with self.LoggedInUser(user=self.user):
      response = self.testapp.get('/')
    output = response.json
    self.assertEqual(0, len(output))


class HostExceptionHandlerTest(HostsTest):
  """Test HostExceptionHandler class."""

  def setUp(self):
    app = webapp2.WSGIApplication(
        [webapp2.Route(r'/<host_id>', handler=hosts.HostExceptionHandler)])
    super(HostExceptionHandlerTest, self).setUp(app)

    self.user = test_utils.CreateUser(admin=True)

    self.santa_blockable = test_utils.CreateSantaBlockable()
    self.santa_event = test_utils.CreateSantaEvent(
        self.santa_blockable,
        host_id=self.santa_host_3.key.id(),
        executing_user=self.user.nickname,
        parent=utils.ConcatenateKeys(
            self.user.key, self.santa_host_3.key,
            self.santa_blockable.key))

    self.santa_blockable.put()
    self.santa_event.put()

  def testCreateHostException(self):
    params = {'reason': constants.HOST_EXEMPTION_REASON.OSX_DEVELOPER}
    with self.LoggedInUser(user=self.user):
      response = self.testapp.post('/' + self.santa_host_3.key.id(), params)
    self.assertEqual(httplib.OK, response.status_int)
    self.assertEqual(response.json['id'], self.santa_host_3.key.id())
  # pylint: disable=line-too-long
    self.assertTaskCount(constants.TASK_QUEUE.BQ_PERSISTENCE, 1)
    self.RunDeferredTasks(constants.TASK_QUEUE.BQ_PERSISTENCE)
    self.assertEntityCount(bigquery.HostRow, 1)
    ticket = tickets.HostExceptionTicket.query().get()
    self.assertEqual(self.santa_host_3.key.id(), ticket.host_id)
    self.assertEqual(self.user.email, ticket.user_id)
    self.assertEqual(
        constants.HOST_EXEMPTION_REASON.OSX_DEVELOPER, ticket.reason)
    self.assertIsNone(ticket.other_text)

    updated_host = self.santa_host_3.key.get()
    self.assertTrue(updated_host.client_mode_lock)
    self.assertEqual(
        constants.SANTA_CLIENT_MODE.MONITOR, updated_host.client_mode)

  def testCreateHostException_OtherReason(self):
    params = {'reason': constants.HOST_EXEMPTION_REASON.OTHER,
              'otherText': 'foo'}
    with self.LoggedInUser(user=self.user):
      self.testapp.post('/' + self.santa_host_3.key.id(), params)
  # pylint: disable=line-too-long
    self.assertTaskCount(constants.TASK_QUEUE.BQ_PERSISTENCE, 1)
    self.RunDeferredTasks(constants.TASK_QUEUE.BQ_PERSISTENCE)
    self.assertEntityCount(bigquery.HostRow, 1)
    ticket = tickets.HostExceptionTicket.query().get()
    self.assertEqual(constants.HOST_EXEMPTION_REASON.OTHER, ticket.reason)
    self.assertEqual('foo', ticket.other_text)

    updated_host = self.santa_host_3.key.get()
    self.assertTrue(updated_host.client_mode_lock)
    self.assertEqual(
        constants.SANTA_CLIENT_MODE.MONITOR, updated_host.client_mode)

  def testCreateHostException_UnknownHost(self):
    params = {'reason': constants.HOST_EXEMPTION_REASON.OSX_DEVELOPER}
    with self.LoggedInUser(user=self.user):
      self.testapp.post('/NotAHost', params, status=httplib.NOT_FOUND)

  def testCreateHostException_AdminCreate(self):
    with self.LoggedInUser(admin=True) as admin:
      self.assertFalse(self.santa_host_3.IsAssociatedWithUser(admin))

      params = {'reason': constants.HOST_EXEMPTION_REASON.OSX_DEVELOPER}
      response = self.testapp.post('/' + self.santa_host_3.key.id(), params)  # pylint: disable=line-too-long
      self.assertTaskCount(constants.TASK_QUEUE.BQ_PERSISTENCE, 1)
      self.RunDeferredTasks(constants.TASK_QUEUE.BQ_PERSISTENCE)
      self.assertEntityCount(bigquery.HostRow, 1)
      self.assertTrue(response)
      self.assertTrue(tickets.HostExceptionTicket.query().get())

  def testCreateHostException_UnownedHost(self):
    superuser = test_utils.CreateUser(
        roles=[constants.USER_ROLE.SUPERUSER])
    params = {'reason': constants.HOST_EXEMPTION_REASON.OSX_DEVELOPER}
    with self.LoggedInUser(user=superuser):
      self.testapp.post(
          '/' + self.santa_host_2.key.id(), params, status=httplib.FORBIDDEN)

  def testCreateHostException_ExistingTicket(self):
    params = {'reason': constants.HOST_EXEMPTION_REASON.OSX_DEVELOPER}
    with self.LoggedInUser(user=self.user):
      response = self.testapp.post('/' + self.santa_host_3.key.id(), params)
    self.assertEqual(httplib.OK, response.status_int)  # pylint: disable=line-too-long
    self.assertTaskCount(constants.TASK_QUEUE.BQ_PERSISTENCE, 1)
    self.RunDeferredTasks(constants.TASK_QUEUE.BQ_PERSISTENCE)
    self.assertEntityCount(bigquery.HostRow, 1)

  def testCreateHostException_NoReason(self):
    with self.LoggedInUser(user=self.user):
      self.testapp.post(
          '/' + self.santa_host_3.key.id(), status=httplib.BAD_REQUEST)

  def testCreateHostException_BadReason(self):
    params = {'reason': 'NotARealReason'}
    with self.LoggedInUser(user=self.user):
      self.testapp.post(
          '/' + self.santa_host_3.key.id(), params, status=httplib.BAD_REQUEST)

  def testCreateHostException_NoOtherReason(self):
    params = {'reason': constants.HOST_EXEMPTION_REASON.OTHER}
    with self.LoggedInUser(user=self.user):
      self.testapp.post(
          '/' + self.santa_host_3.key.id(), params, status=httplib.BAD_REQUEST)

  def testGetHostException(self):
    tickets.HostExceptionTicket.get_open_or_insert_did_insert(
        self.user.key.id(), self.santa_host_3.key.id())

    with self.LoggedInUser(user=self.user):
      response = self.testapp.get('/' + self.santa_host_3.key.id())

    output = response.json

    self.assertEqual(self.user.email, output['userId'])
    self.assertEqual(self.santa_host_3.key.id(), output['hostId'])

  def testGetHostException_UnknownHost(self):
    with self.LoggedInUser(user=self.user):
      self.testapp.get('/NotAHost', status=httplib.NOT_FOUND)

  def testGetHostException_UnownedHost(self):
    with self.LoggedInUser():
      self.testapp.get(
          '/' + self.santa_host_2.key.id(), status=httplib.FORBIDDEN)

  def testGetHostException_NoTicket(self):
    with self.LoggedInUser(user=self.user):
      self.testapp.get(
          '/' + self.santa_host_3.key.id(), status=httplib.NOT_FOUND)

  def testGetHostException_GetByOtherUsername(self):
    with self.LoggedInUser(admin=True) as admin:
      tickets.HostExceptionTicket.get_open_or_insert_did_insert(
          admin.key.id(), self.santa_host_3.key.id())

      params = {'user_id': admin.email}
      response = self.testapp.get('/' + self.santa_host_3.key.id(), params)
      self.assertEqual(httplib.OK, response.status_int)

  def testGetHostException_AdminGetByOtherUsername(self):
    tickets.HostExceptionTicket.get_open_or_insert_did_insert(
        self.user.key.id(), self.santa_host_3.key.id())

    params = {'user_id': self.user.email}
    with self.LoggedInUser(admin=True):
      response = self.testapp.get('/' + self.santa_host_3.key.id(), params)
    self.assertEqual(httplib.OK, response.status_int)


class LockdownHandlerTest(HostsTest):
  """Test LockdownHandler class."""

  def setUp(self):
    app = webapp2.WSGIApplication(
        [webapp2.Route(r'/<host_id>', handler=hosts.LockdownHandler)])
    super(LockdownHandlerTest, self).setUp(app)

    self.user = test_utils.CreateUser()

    self.santa_blockable = test_utils.CreateSantaBlockable()
    self.santa_event = test_utils.CreateSantaEvent(
        self.santa_blockable,
        host_id=self.santa_host_3.key.id(),
        parent=utils.ConcatenateKeys(
            self.user.key, self.santa_host_3.key, self.santa_blockable.key))

    self.santa_blockable.put()
    self.santa_event.put()

    self.santa_host_3.client_mode = constants.SANTA_CLIENT_MODE.MONITOR
    self.santa_host_3.put()

  def testLockdown(self):
    with self.LoggedInUser(user=self.user):
      response = self.testapp.post('/' + self.santa_host_3.key.id())
    self.assertEqual(httplib.OK, response.status_int)
    self.assertEqual(response.json['id'], self.santa_host_3.key.id())

    updated_host = self.santa_host_3.key.get()
    self.assertEqual(
        response.json['clientModeLock'], updated_host.client_mode_lock)
    self.assertTrue(updated_host.client_mode_lock)
    self.assertEqual(
        constants.SANTA_CLIENT_MODE.LOCKDOWN, updated_host.client_mode)

  def testLockdown_Admin(self):
    with self.LoggedInUser(admin=True):
      response = self.testapp.post('/' + self.santa_host_3.key.id())
    self.assertEqual(httplib.OK, response.status_int)

    updated_host = self.santa_host_3.key.get()
    self.assertTrue(updated_host.client_mode_lock)
    self.assertEqual(
        constants.SANTA_CLIENT_MODE.LOCKDOWN, updated_host.client_mode)

  def testLockdown_UnknownHost(self):
    with self.LoggedInUser(user=self.user):
      self.testapp.post('/NotAHost', status=httplib.NOT_FOUND)

  def testLockdown_UnownedHost(self):
    with self.LoggedInUser(user=self.user):
      self.testapp.post(
          '/' + self.santa_host_2.key.id(), status=httplib.FORBIDDEN)


class HostEventRateHandlerTest(HostsTest):

  def setUp(self):
    app = webapp2.WSGIApplication([
        webapp2.Route(r'/<host_id>', handler=hosts.HostEventRateHandler)])
    super(HostEventRateHandlerTest, self).setUp(app)

    self.user = test_utils.CreateUser()

    self.santa_blockable = test_utils.CreateSantaBlockable()
    self.santa_event = test_utils.CreateSantaEvent(
        self.santa_blockable,
        host_id=self.santa_host_1.key.id(),
        last_blocked_dt=datetime.datetime.utcnow(),
        parent=utils.ConcatenateKeys(
            self.user.key, self.santa_host_1.key, self.santa_blockable.key))

  def testNonMax(self):
    with self.LoggedInUser(user=self.user):
      response = self.testapp.get('/%s' % self.santa_host_1.key.id())
    output = response.json

    self.assertIn('application/json', response.headers['Content-type'])
    self.assertIsInstance(output, dict)

    self.assertFalse(output['atMax'])
    self.assertTrue(output['avgRate'] > 0)

  def testUnknownHost(self):
    with self.LoggedInUser(user=self.user):
      self.testapp.get('/NotARealHost', status=httplib.NOT_FOUND)

  def testUnassociatedUser(self):
    with self.LoggedInUser():
      self.testapp.get(
          '/%s' % self.santa_host_1.key.id(), status=httplib.FORBIDDEN)


class VisibilityHandlerTest(HostsTest):

  def setUp(self):
    app = webapp2.WSGIApplication(
        [webapp2.Route(
            r'/<host_id>/hidden/<hidden>',
            handler=hosts.VisibilityHandler)])
    super(VisibilityHandlerTest, self).setUp(app)

    self.user = test_utils.CreateUser()

    self.santa_host_1.primary_user = self.user.nickname
    self.santa_host_1.hidden = False
    self.santa_host_1.put()

  def testUnhide_Success(self):
    self.santa_host_1.hidden = True
    self.santa_host_1.put()

    with self.LoggedInUser(user=self.user):
      self.testapp.put(
          '/%s/hidden/false' % self.santa_host_1.key.id(), status=httplib.OK)
    self.assertFalse(self.santa_host_1.key.get().hidden)

  def testHide_Success(self):
    with self.LoggedInUser(user=self.user):
      self.testapp.put(
          '/%s/hidden/true' % self.santa_host_1.key.id(), status=httplib.OK)
    self.assertTrue(self.santa_host_1.key.get().hidden)

  def testHide_Capital(self):
    with self.LoggedInUser(user=self.user):
      self.testapp.put(
          '/%s/hidden/True' % self.santa_host_1.key.id(), status=httplib.OK)
    self.assertTrue(self.santa_host_1.key.get().hidden)

  def testHide_Forbidden(self):
    with self.LoggedInUser():
      self.testapp.put(
          '/%s/hidden/true' % self.santa_host_1.key.id(),
          status=httplib.FORBIDDEN)
    self.assertFalse(self.santa_host_1.key.get().hidden)

  def testHide_NotFound(self):
    with self.LoggedInUser(user=self.user):
      self.testapp.put(
          '/%s/hidden/true' % 'DNE', status=httplib.NOT_FOUND)

  def testHide_BadRequest(self):
    with self.LoggedInUser(user=self.user):
      self.testapp.put(
          '/%s/hidden/badrequest' % self.santa_host_1.key.id(),
          status=httplib.BAD_REQUEST)
    self.assertFalse(self.santa_host_1.key.get().hidden)


if __name__ == '__main__':
  basetest.main()
