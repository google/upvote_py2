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

"""Unit tests for events.py."""

import datetime
import httplib

import webapp2

from google.appengine.ext import ndb

from upvote.gae.datastore import test_utils
from upvote.gae.datastore import utils as datastore_utils
from upvote.gae.lib.testing import basetest
from upvote.gae.modules.upvote_app.api.web import events
from upvote.gae.shared.common import user_map
from upvote.shared import constants


class EventsTest(basetest.UpvoteTestCase):
  """Base class for Event handler tests."""

  def setUp(self):
    app = webapp2.WSGIApplication(routes=[events.ROUTES])
    super(EventsTest, self).setUp(wsgi_app=app)
    self.santa_cert = test_utils.CreateSantaCertificate()
    self.santa_blockable1 = test_utils.CreateSantaBlockable(
        id='aaaabbbbccccddddeeeeffffgggg',
        file_name='Product.app',
        cert_key=self.santa_cert.key,
        cert_sha256=self.santa_cert.key.id())
    self.santa_blockable2 = test_utils.CreateSantaBlockable(
        id='hhhhiiiijjjjkkkkllllmmmmnnnn',
        file_name='Another Product.app')
    self.bit9_blockable1 = test_utils.CreateBit9Binary(
        id='zzzzaaaayyyybbbbxxxxccccwwww',
        file_name='notepad++.exe')

    self.user_1 = test_utils.CreateUser()
    self.user_2 = test_utils.CreateUser()

    self.santa_host1 = test_utils.CreateSantaHost(
        id='AAAAAAAA-1111-BBBB-2222-CCCCCCCCCCCC',
        recorded_dt=datetime.datetime(2015, 2, 1, 1, 0, 0))
    self.santa_host2 = test_utils.CreateSantaHost(
        id='DDDDDDDD-3333-EEEE-33333-FFFFFFFFFFFF',
        recorded_dt=datetime.datetime(2015, 2, 1, 1, 0, 0))
    self.bit9_host1 = test_utils.CreateSantaHost(
        id='CHANGE-ME',
        recorded_dt=datetime.datetime(2015, 2, 1, 1, 0, 0))
    self.bit9_host2 = test_utils.CreateSantaHost(
        id='CHANGE-ME2',
        recorded_dt=datetime.datetime(2015, 2, 1, 1, 0, 0))

    self.santa_event1_from_user1 = test_utils.CreateSantaEvent(
        self.santa_blockable1,
        cert_key=self.santa_cert.key,
        cert_sha256=self.santa_blockable1.cert_sha256,
        executing_user=self.user_1.nickname,
        event_type=constants.EVENT_TYPE.ALLOW_UNKNOWN,
        file_name=self.santa_blockable1.file_name,
        file_path='/Applications/Product.app/Contents/MacOs',
        host_id=self.santa_host1.key.id(),
        last_blocked_dt=datetime.datetime(2015, 3, 1, 1, 0, 0),
        first_blocked_dt=datetime.datetime(2015, 3, 1, 1, 0, 0),
        parent=datastore_utils.ConcatenateKeys(
            self.user_1.key, self.santa_host1.key, self.santa_blockable1.key))

    self.santa_event2_from_user1 = test_utils.CreateSantaEvent(
        self.santa_blockable1,
        cert_key=self.santa_cert.key,
        cert_sha256=self.santa_blockable1.cert_sha256,
        executing_user=self.user_1.nickname,
        event_type=constants.EVENT_TYPE.ALLOW_UNKNOWN,
        file_name=self.santa_blockable1.file_name,
        file_path='/Applications/Product.app/Contents/MacOs',
        host_id=self.santa_host2.key.id(),
        last_blocked_dt=datetime.datetime(2015, 4, 1, 1, 0, 0),
        first_blocked_dt=datetime.datetime(2015, 4, 1, 1, 0, 0),
        parent=datastore_utils.ConcatenateKeys(
            self.user_1.key, self.santa_host2.key, self.santa_blockable1.key))

    self.santa_event3_from_user1 = test_utils.CreateSantaEvent(
        self.santa_blockable2,
        event_type=constants.EVENT_TYPE.ALLOW_UNKNOWN,
        executing_user=self.user_1.nickname,
        file_name=self.santa_blockable2.file_name,
        file_path='/Applications/Another Product.app/Contents/MacOs',
        host_id=self.santa_host1.key.id(),
        last_blocked_dt=datetime.datetime(2015, 5, 1, 1, 0, 0),
        first_blocked_dt=datetime.datetime(2015, 5, 1, 1, 0, 0),
        parent=datastore_utils.ConcatenateKeys(
            self.user_1.key, self.santa_host1.key, self.santa_blockable2.key))

    self.santa_event1_from_user2 = test_utils.CreateSantaEvent(
        self.santa_blockable1,
        event_type=constants.EVENT_TYPE.ALLOW_UNKNOWN,
        executing_user=self.user_2.nickname,
        file_name=self.santa_blockable1.file_name,
        file_path='/Applications/Product.app/Contents/MacOs',
        host_id=self.santa_host2.key.id(),
        last_blocked_dt=datetime.datetime(2015, 3, 1, 1, 0, 0),
        first_blocked_dt=datetime.datetime(2015, 3, 1, 1, 0, 0),
        parent=datastore_utils.ConcatenateKeys(
            self.user_2.key, self.santa_host2.key,
            self.santa_blockable1.key))

    self.bit9_event1_from_user1 = test_utils.CreateBit9Event(
        self.bit9_blockable1,
        executing_user=self.user_1.nickname,
        file_name=self.bit9_blockable1.file_name,
        file_path=r'c:\program files (x86)\notepad++',
        host_id=self.bit9_host1.key.id(),
        last_blocked_dt=datetime.datetime(2015, 6, 1, 1, 0, 0),
        first_blocked_dt=datetime.datetime(2015, 6, 1, 1, 0, 0),
        parent=datastore_utils.ConcatenateKeys(
            self.user_1.key, self.bit9_host1.key, self.bit9_blockable1.key))

    self.bit9_event1_from_user2 = test_utils.CreateBit9Event(
        self.bit9_blockable1,
        executing_user=self.user_2.nickname,
        file_name='notepad++.exe',
        file_path=r'c:\program files (x86)\notepad++',
        host_id=self.bit9_host2.key.id(),
        last_blocked_dt=datetime.datetime(2015, 4, 1, 1, 0, 0),
        first_blocked_dt=datetime.datetime(2015, 4, 1, 1, 0, 0),
        parent=datastore_utils.ConcatenateKeys(
            self.user_2.key, self.bit9_host2.key, self.bit9_blockable1.key))

    self.PatchValidateXSRFToken()


class EventQueryHandlerTest(EventsTest):

  ROUTE = '/events/query'

  def testAdminGetListAllEvents(self):
    """Admin user getting list of all events for a blockable_id."""
    params = {'asAdmin': 'true'}

    with self.LoggedInUser(admin=True):
      response = self.testapp.get(self.ROUTE, params)

    output = response.json

    self.assertIn('application/json', response.headers['Content-type'])
    self.assertIsInstance(output, dict)
    self.assertEqual(6, len(output['content']))

  def testAdminGetListAllEventsWithBlockable(self):
    """Admin user getting list of all events for a blockable_id."""
    params = {'blockableKey': self.santa_blockable1.key.urlsafe(),
              'asAdmin': 'true'}

    with self.LoggedInUser(admin=True):
      response = self.testapp.get(self.ROUTE, params)

    output = response.json

    host_ids = [entry['hostId'] for entry in output['content']]

    self.assertIn('application/json', response.headers['Content-type'])
    self.assertEqual(isinstance(output, dict), True)
    self.assertEqual(len(host_ids), 3)
    self.assertIn(self.santa_host1.key.id(), host_ids)
    self.assertIn(self.santa_host2.key.id(), host_ids)

  def testAdminGetListAllWithBit9Platform(self):
    """Admin user getting list of all bit9 events."""
    params = {'asAdmin': 'true'}

    with self.LoggedInUser(admin=True):
      response = self.testapp.get(self.ROUTE + '/bit9', params)

    output = response.json

    host_ids = [entry['hostId'] for entry in output['content']]

    self.assertIn('application/json', response.headers['Content-type'])
    self.assertEqual(isinstance(output, dict), True)
    self.assertEqual(len(host_ids), 2)
    self.assertIn(self.bit9_host1.key.id(), host_ids)
    self.assertIn(self.bit9_host2.key.id(), host_ids)

  def testAdminGetListAllWithSantaPlatform(self):
    """Admin user getting list of all santa events."""
    params = {'asAdmin': 'true'}

    with self.LoggedInUser(admin=True):
      response = self.testapp.get(self.ROUTE + '/santa', params)

    output = response.json

    host_ids = [entry['hostId'] for entry in output['content']]

    self.assertIn('application/json', response.headers['Content-type'])
    self.assertEqual(isinstance(output, dict), True)
    self.assertEqual(len(host_ids), 4)
    self.assertIn(self.santa_host1.key.id(), host_ids)
    self.assertIn(self.santa_host2.key.id(), host_ids)

  def testUserGetListAllEvents(self):
    """Normal user attempting to get all events."""
    params = {'asAdmin': 'true'}

    with self.LoggedInUser(user=self.user_1):
      self.testapp.get(self.ROUTE, params, status=httplib.FORBIDDEN)

  def testUserGetListOwnEvents(self):
    """Normal user getting list of their events."""
    with self.LoggedInUser(user=self.user_1):
      response = self.testapp.get(self.ROUTE)

    output = response.json

    self.assertIn('application/json', response.headers['Content-type'])
    self.assertIsInstance(output, dict)
    content = output['content']
    self.assertEqual(4, len(content))
    self.assertFalse(output['more'])

  def testUserGetListOwnEventsWithHostId(self):
    """Normal user getting list of their events."""
    params = {'hostId': self.santa_host1.key.id()}
    with self.LoggedInUser(user=self.user_1):
      response = self.testapp.get(self.ROUTE, params)

    output = response.json

    self.assertIn('application/json', response.headers['Content-type'])
    self.assertIsInstance(output, dict)
    self.assertEqual(len(output['content']), 2)
    self.assertFalse(output['more'])

  def testUserGetListOwnEventsWithContext(self):
    """Normal user getting list of their events with context."""
    # Create a vote for event 1.
    test_utils.CreateVote(
        self.santa_event1_from_user2.blockable_key.get(),
        user_email=self.santa_event2_from_user1.user_key.id(),
        was_yes_vote=False)

    params = {'withContext': 'true'}
    with self.LoggedInUser(user=self.user_1):
      response = self.testapp.get(self.ROUTE, params)

    content = response.json['content']
    self.assertEqual(4, len(content))
    self.assertFalse(response.json['more'])

    event1 = [
        dict_ for dict_ in content
        if dict_['blockable']['id'] == self.santa_blockable1.key.id()][0]
    self.assertEqual(len(event1.keys()), 5)
    self.assertEqual(self.santa_event2_from_user1.host_id,
                     event1['host']['id'])
    blockable_key = ndb.Key(urlsafe=event1['event']['blockableKey'])
    self.assertEqual(self.santa_event2_from_user1.blockable_key, blockable_key)
    self.assertEqual(event1['blockable']['id'], blockable_key.id())
    self.assertFalse(event1['vote']['wasYesVote'])

    event2 = [
        dict_ for dict_ in content
        if dict_['blockable']['id'] == self.santa_blockable2.key.id()][0]
    self.assertIsNone(event2['vote'])

  def testUserGetListOwnEventsWithBlockable(self):
    """Normal user getting list of their events with a blockable param."""
    params = {'blockableKey': self.santa_blockable1.key.urlsafe()}

    with self.LoggedInUser(user=self.user_1):
      response = self.testapp.get(self.ROUTE, params)

    self.assertEqual(len(response.json['content']), 2)
    self.assertFalse(response.json['more'])

  def testUserGetListOwnEventsWithBlockableAndContext(self):
    """Normal user getting list of their events with context, by blockable."""
    test_utils.CreateVote(
        self.santa_blockable1, user_email=self.user_1.email)
    test_utils.CreateVote(
        self.santa_blockable1, user_email=self.user_2.email)

    params = {
        'blockableKey': self.santa_blockable1.key.urlsafe(),
        'withContext': 'true'}

    with self.LoggedInUser(user=self.user_1):
      response = self.testapp.get(self.ROUTE, params)

    output = response.json

    self.assertIn('application/json', response.headers['Content-type'])
    self.assertIsInstance(output, dict)
    self.assertEqual(len(output['content']), 2)

    event_with_context = output['content'][0]
    self.assertEqual(len(event_with_context.keys()), 5)
    self.assertEqual(event_with_context['host']['id'],
                     event_with_context['event']['hostId'])
    blockable_key = ndb.Key(urlsafe=event_with_context['event']['blockableKey'])
    self.assertEqual(event_with_context['blockable']['id'], blockable_key.id())
    self.assertEqual(event_with_context['blockable']['fileName'],
                     event_with_context['event']['fileName'])
    self.assertEqual(event_with_context['cert']['id'],
                     event_with_context['blockable']['certId'])
    self.assertEqual(
        user_map.EmailToUsername(event_with_context['vote']['userEmail']),
        event_with_context['event']['executingUser'])

  def testAdminGetQuery(self):
    """Admin searching for something."""
    params = {
        'search': self.santa_host1.key.id(),
        'searchBase': 'hostId',
        'asAdmin': True}

    with self.LoggedInUser(admin=True):
      response = self.testapp.get(self.ROUTE, params)

    output = response.json

    self.assertIn('application/json', response.headers['Content-type'])
    self.assertIsInstance(output, dict)
    self.assertEqual(len(output['content']), 2)

  def testAdminGetQueryWithPlatform(self):
    """Admin searching with a platform param."""
    params = {
        'search': self.user_1.nickname,
        'searchBase': 'executingUser',
        'asAdmin': True}

    with self.LoggedInUser(admin=True):
      response = self.testapp.get(self.ROUTE + '/bit9', params)

    output = response.json

    self.assertIn('application/json', response.headers['Content-type'])
    self.assertIsInstance(output, dict)
    self.assertEqual(len(output['content']), 1)

  def testAdminGetQueryBadPlatform(self):
    """Admin searching with a platform param mismatch with the searchBase."""
    params = {'search': 'DoesntMatter',
              'searchBase': 'bundleId',
              'asAdmin': True}

    with self.LoggedInUser(admin=True):
      self.testapp.get(self.ROUTE + '/bit9', params, status=httplib.BAD_REQUEST)

  def testAdminGetQueryNoSearch(self):
    """Admin searching with no search term."""
    params = {'searchBase': 'hostId',
              'asAdmin': True}

    with self.LoggedInUser(admin=True):
      self.testapp.get(self.ROUTE, params, status=httplib.BAD_REQUEST)

  def testAdminGetQueryNoSearchBase(self):
    """Admin searching with no searchBase param."""
    params = {'search': 'AAAAAAAA-1111-BBBB-2222-CCCCCCCCCCCC',
              'asAdmin': True}

    with self.LoggedInUser(admin=True):
      self.testapp.get(self.ROUTE, params, status=httplib.BAD_REQUEST)

  def testAdminGetQueryInvalidSearchBase(self):
    """Admin searching with invalid searchBase param."""
    params = {'search': 'thisDoesNotMatter',
              'searchBase': 'thisIsNotAField',
              'asAdmin': True}

    with self.LoggedInUser(admin=True):
      self.testapp.get(self.ROUTE, params, status=httplib.BAD_REQUEST)


class EventHandlerTest(EventsTest):

  ROUTE = '/events/%s'

  def testUserGetOwnEvent(self):
    """Getting an event of the requesting user's by id."""
    with self.LoggedInUser(user=self.user_1):
      response = self.testapp.get(
          self.ROUTE % self.santa_event1_from_user1.key.urlsafe())

    output = response.json

    self.assertIn('application/json', response.headers['Content-type'])
    self.assertIsInstance(output, dict)
    self.assertEqual(output['id'], self.santa_event1_from_user1.key.id())
    self.assertEqual(output['fileName'], self.santa_event1_from_user1.file_name)
    self.assertIn('Event', output['class_'])

  def testUserGetOwnEventWithContext(self):
    """Getting an event of the requesting user's by id."""
    params = {'withContext': 'true'}
    with self.LoggedInUser(user=self.user_1):
      response = self.testapp.get(
          self.ROUTE % self.santa_event1_from_user1.key.urlsafe(), params)

    output = response.json

    self.assertIn('application/json', response.headers['Content-type'])
    self.assertIsInstance(output, dict)
    self.assertEqual(output['event']['id'],
                     self.santa_event1_from_user1.key.id())
    self.assertEqual(output['host']['id'], output['event']['hostId'])
    blockable_key = ndb.Key(urlsafe=output['event']['blockableKey'])
    self.assertEqual(output['blockable']['id'], blockable_key.id())
    cert_key = ndb.Key(urlsafe=output['event']['certKey'])
    self.assertEqual(output['cert']['id'], cert_key.id())

  def testUserGetOwnEventWithContext_NoCert(self):

    # Remove all cert identifiers from the Event.
    self.santa_event1_from_user1.cert_key = None
    self.santa_event1_from_user1.cert_sha256 = None
    self.santa_event1_from_user1.put()

    params = {'withContext': 'true'}
    with self.LoggedInUser(user=self.user_1):
      response = self.testapp.get(
          self.ROUTE % self.santa_event1_from_user1.key.urlsafe(), params)

    output = response.json

    self.assertIn('application/json', response.headers['Content-type'])
    self.assertIsInstance(output, dict)
    self.assertIsNone(output['cert'])

  def testUserGetOwnEventWithContext_OldCert(self):

    # Remove the cert_key to simulate an old SantaEvent.
    self.santa_event1_from_user1.cert_key = None
    self.santa_event1_from_user1.put()

    params = {'withContext': 'true'}
    with self.LoggedInUser(user=self.user_1):
      response = self.testapp.get(
          self.ROUTE % self.santa_event1_from_user1.key.urlsafe(), params)

    output = response.json

    self.assertIn('application/json', response.headers['Content-type'])
    self.assertIsInstance(output, dict)
    self.assertEqual(output['cert']['id'], self.santa_cert.key.id())

  def testUserGetOwnEventWithContext_Bundle(self):
    """Getting an event of the requesting user's by id."""
    bundle = test_utils.CreateSantaBundle(
        bundle_binaries=[self.santa_blockable1])
    event = test_utils.CreateSantaEvent(
        self.santa_blockable1,
        bundle_key=bundle.key,
        executing_user=self.user_1.nickname,
        event_type=constants.EVENT_TYPE.ALLOW_UNKNOWN,
        host_id=self.santa_host1.key.id(),
        last_blocked_dt=datetime.datetime(2015, 3, 1, 1, 0, 0),
        first_blocked_dt=datetime.datetime(2015, 3, 1, 1, 0, 0),
        parent=datastore_utils.ConcatenateKeys(
            self.user_1.key, self.santa_host1.key, bundle.key))
    test_utils.CreateVote(bundle, user_email=self.user_1.email)

    params = {'withContext': 'true'}
    with self.LoggedInUser(user=self.user_1):
      response = self.testapp.get(self.ROUTE % event.key.urlsafe(), params)

    output = response.json

    self.assertIn('application/json', response.headers['Content-type'])
    self.assertIsInstance(output, dict)
    self.assertEqual(output['event']['id'], event.key.id())
    self.assertEqual(output['host']['id'], output['event']['hostId'])
    bundle_key = ndb.Key(urlsafe=output['event']['bundleKey'])
    self.assertEqual(output['blockable']['id'], bundle_key.id())
    self.assertIsNotNone(output['vote'])

  def testUserGetBadKey(self):
    """Getting an event of the requesting user's by key."""
    with self.LoggedInUser(user=self.user_1):
      self.testapp.get(self.ROUTE % 'NotARealKey', status=httplib.BAD_REQUEST)

  def testUserGetUnknownKey(self):
    """Getting an event of the requesting user's by key."""
    unknown_key = ndb.Key('Event', 'NotARealId')
    with self.LoggedInUser(user=self.user_1):
      self.testapp.get(
          self.ROUTE % unknown_key.urlsafe(), status=httplib.NOT_FOUND)

  def testUserGetOthersEvent(self):
    """Getting another user's event by id without permission."""
    with self.LoggedInUser(user=self.user_1):
      self.testapp.get(
          self.ROUTE % self.santa_event1_from_user2.key.urlsafe(),
          status=httplib.FORBIDDEN)

  def testAdminGetOthersEvent(self):
    """Getting another user's event by id."""
    with self.LoggedInUser(admin=True):
      response = self.testapp.get(
          self.ROUTE % self.santa_event1_from_user2.key.urlsafe())

    output = response.json

    self.assertIn('application/json', response.headers['Content-type'])
    self.assertIsInstance(output, dict)
    self.assertEqual(output['id'], self.santa_event1_from_user2.key.id())
    self.assertEqual(output['fileName'], self.santa_event1_from_user2.file_name)
    self.assertIn('Event', output['class_'])


class RecentEventHandlerTest(EventsTest):

  ROUTE = '/events/most-recent/%s'

  def testUser_GetOwnEvent(self):
    with self.LoggedInUser(user=self.user_1):
      response = self.testapp.get(self.ROUTE % self.santa_blockable1.key.id())

    output = response.json

    self.assertIn('application/json', response.headers['Content-type'])
    self.assertIsInstance(output, dict)
    # Assert that the more recent event is returned, regardless of the host on
    # which it was run.
    self.assertGreater(
        self.santa_event2_from_user1.last_blocked_dt,
        self.santa_event1_from_user1.last_blocked_dt)
    self.assertEqual(output['id'], self.santa_event2_from_user1.key.id())
    self.assertEqual(output['hostId'], self.santa_event2_from_user1.host_id)
    self.assertIn('Event', output['class_'])

  def testUser_GetOwnEvent_SantaBundle(self):
    bundle = test_utils.CreateSantaBundle(
        bundle_binaries=[self.santa_blockable1])

    event = test_utils.CreateSantaEvent(
        self.santa_blockable1,
        bundle_key=bundle.key,
        executing_user=self.user_1.nickname,
        event_type=constants.EVENT_TYPE.BLOCK_UNKNOWN,
        host_id=self.santa_host1.key.id(),
        last_blocked_dt=datetime.datetime(2015, 3, 1, 1, 0, 0),
        first_blocked_dt=datetime.datetime(2015, 3, 1, 1, 0, 0),
        parent=datastore_utils.ConcatenateKeys(
            self.user_1.key, self.santa_host1.key, bundle.key))

    with self.LoggedInUser(user=self.user_1):
      response = self.testapp.get(self.ROUTE % bundle.key.id())

    output = response.json

    self.assertIn('application/json', response.headers['Content-type'])
    self.assertIsInstance(output, dict)

    self.assertEqual(output['id'], event.key.id())
    self.assertEqual(output['hostId'], event.host_id)

  def testUser_GetOwnEvent_WithContext(self):
    """Getting an event of the requesting user's by id."""
    with self.LoggedInUser(user=self.user_1):
      response = self.testapp.get(
          self.ROUTE % self.santa_blockable1.key.id(),
          params={'withContext': 'true'})

    output = response.json

    self.assertIn('application/json', response.headers['Content-type'])
    self.assertIsInstance(output, dict)
    self.assertEqual(output['event']['id'],
                     self.santa_event2_from_user1.key.id())
    self.assertEqual(output['host']['id'], output['event']['hostId'])
    blockable_key = ndb.Key(urlsafe=output['event']['blockableKey'])
    self.assertEqual(output['blockable']['id'], blockable_key.id())

  def testUser_GetOwnEvent_NoEvent(self):
    new_blockable = test_utils.CreateSantaBlockable()
    with self.LoggedInUser(user=self.user_1):
      response = self.testapp.get(self.ROUTE % new_blockable.key.id())

    output = response.json

    self.assertIsNone(output)

  def testUser_GetUnknownBlockable(self):
    with self.LoggedInUser(user=self.user_1):
      self.testapp.get(self.ROUTE % 'NotARealId', status=httplib.NOT_FOUND)

  def testUser_GetOthersEvent(self):
    with self.LoggedInUser(user=self.user_1):
      self.testapp.get(
          self.ROUTE % self.santa_blockable1.key.id(),
          params={'asUser': self.user_2.nickname},
          status=httplib.FORBIDDEN)

  def testAdmin_GetOthersEvent(self):
    """Getting another user's event by id."""
    with self.LoggedInUser(admin=True):
      response = self.testapp.get(
          self.ROUTE % self.santa_blockable1.key.id(),
          params={'asUser': self.user_2.nickname})

    output = response.json

    self.assertIn('application/json', response.headers['Content-type'])
    self.assertIsInstance(output, dict)
    self.assertEqual(output['hostId'], self.santa_event1_from_user2.host_id)
    self.assertEqual(
        output['executingUser'], self.santa_event1_from_user2.executing_user)


if __name__ == '__main__':
  basetest.main()
