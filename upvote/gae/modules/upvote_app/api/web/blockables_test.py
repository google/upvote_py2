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

"""Unit tests for blockable handlers."""
import datetime
import httplib

import mock
import webapp2

from google.appengine.ext import ndb

from upvote.gae.datastore import test_utils
from upvote.gae.datastore import utils as datastore_utils
from upvote.gae.datastore.models import base
from upvote.gae.datastore.models import note as note_models
from upvote.gae.datastore.models import package as package_models
from upvote.gae.datastore.models import rule as rule_models
from upvote.gae.datastore.models import santa
from upvote.gae.lib.testing import basetest
from upvote.gae.lib.voting import api as voting_api
from upvote.gae.modules.upvote_app.api.web import blockables
from upvote.shared import constants


class BlockablesTest(basetest.UpvoteTestCase):
  """Base class for Blockable handler tests."""

  def setUp(self):
    app = webapp2.WSGIApplication(routes=[blockables.ROUTES])
    super(BlockablesTest, self).setUp(wsgi_app=app)

    self.bit9_blockable = test_utils.CreateBit9Binary(
        id='zzzzzzzzzaaa',
        id_type=constants.ID_TYPE.SHA256,
        file_name='Mac.app.exe')
    self.bit9_blockable2 = test_utils.CreateBit9Binary(
        id='zzzzzzzzzbbb',
        id_type=constants.ID_TYPE.SHA256,
        file_name='app.exe')

    self.generic_blockable = test_utils.CreateBlockable(
        file_name='Not4Mac.exe', state=constants.STATE.SUSPECT)
    self.santa_blockable = test_utils.CreateSantaBlockable(
        publisher='Arple', product_name='New Shiny', flagged=True)
    self.santa_certificate = test_utils.CreateSantaCertificate(
        id_type=constants.ID_TYPE.SHA256,
        common_name='Best Cert Ever',
        organization='Totally Legit CA')

    self.PatchValidateXSRFToken()


class BlockableQueryHandlerTest(BlockablesTest):

  def testAdminGetList(self):
    """Admin getting list of all blockables."""
    with self.LoggedInUser(admin=True):
      response = self.testapp.get('/blockables/all/all')

    output = response.json

    self.assertIn('application/json', response.headers['Content-type'])
    self.assertIsInstance(output['content'], list)
    self.assertLen(output['content'], 5)

  def testAdminGetListWithPlatform(self):
    """Admin getting list of all blockables on a specific platform."""
    with self.LoggedInUser(admin=True):
      response = self.testapp.get('/blockables/santa/certificates')

    output = response.json

    self.assertIn('application/json', response.headers['Content-type'])
    self.assertIsInstance(output['content'], list)
    self.assertLen(output['content'], 1)

  def testUserGetBlockableList(self):
    """Normal user getting a list of all blockables."""

    with self.LoggedInUser():
      self.testapp.get('/blockables/all/all', status=httplib.FORBIDDEN)

  def testUserGetFlaggedBlockables(self):
    """Normal user getting a list of flagged blockables."""
    params = {'filter': 'flagged'}
    with self.LoggedInUser():
      self.testapp.get('/blockables/all/all', params, status=httplib.FORBIDDEN)

  def testUserGetSuspectBlockables(self):
    """Normal user getting a list of suspect blockables."""
    params = {'filter': 'suspect'}
    with self.LoggedInUser():
      self.testapp.get('/blockables/all/all', params, status=httplib.FORBIDDEN)

  def testUserGetOwnBlockables(self):

    user_1 = test_utils.CreateUser()
    user_2 = test_utils.CreateUser()

    # Create two events for this user.
    test_utils.CreateBit9Event(
        self.bit9_blockable,
        executing_user=user_2.nickname,
        host_id='a_host_id',
        parent=datastore_utils.ConcatenateKeys(
            user_2.key, ndb.Key('Host', 'a_host_id'), self.santa_blockable.key))
    host_id = 'AAAAAAAA-1111-BBBB-2222-CCCCCCCCCCCC'
    test_utils.CreateSantaEvent(
        self.santa_blockable,
        executing_user=user_2.nickname,
        event_type=constants.EVENT_TYPE.ALLOW_UNKNOWN,
        file_name='Product.app',
        file_path='/Applications/Product.app/Contents/MacOs',
        host_id=host_id,
        last_blocked_dt=datetime.datetime(2015, 4, 1, 1, 0, 0),
        first_blocked_dt=datetime.datetime(2015, 4, 1, 1, 0, 0),
        parent=datastore_utils.ConcatenateKeys(
            user_2.key, ndb.Key('Host', host_id), self.santa_blockable.key))
    # Create one event for another user. This should not be included in
    # the results when fetching blockables for user_2.
    test_utils.CreateBit9Event(
        self.bit9_blockable2,
        executing_user=user_1.nickname,
        file_name='notepad++.exe',
        file_path=r'c:\program files (x86)\notepad++',
        host_id='a_host_id',
        last_blocked_dt=datetime.datetime(2015, 5, 1, 1, 0, 0),
        first_blocked_dt=datetime.datetime(2015, 5, 1, 1, 0, 0),
        parent=datastore_utils.ConcatenateKeys(
            user_1.key, ndb.Key('Host', 'a_host_id'), self.santa_blockable.key))

    params = {'filter': 'own'}
    with self.LoggedInUser(user=user_2):
      response = self.testapp.get('/blockables/all/all', params)

    output = response.json

    # Verify that only two blockables (from the two events) are returned to
    # this user.
    self.assertIn('application/json', response.headers['Content-type'])
    self.assertIsInstance(output['content'], list)
    self.assertLen(output['content'], 2)

  def testUserGetOwnBlockables_UserHasNoBlockables(self):
    params = {'filter': 'own'}
    with self.LoggedInUser():
      response = self.testapp.get('/blockables/all/all', params)
    output = response.json

    self.assertIn('application/json', response.headers['Content-type'])
    self.assertIsInstance(output['content'], list)
    self.assertLen(output['content'], 0)

  def testAdminGetListOfFlaggedBlockables(self):
    """Admin getting a list of flagged blockables."""
    params = {'filter': 'flagged'}

    with self.LoggedInUser(admin=True):
      response = self.testapp.get('/blockables/all/all', params)

    output = response.json

    self.assertIn('application/json', response.headers['Content-type'])
    self.assertIsInstance(output['content'], list)
    self.assertLen(output['content'], 1)

  def testAdminGetListOfSuspectBlockables(self):
    """Admin getting a list of flagged blockables."""
    params = {'filter': 'suspect'}

    with self.LoggedInUser(admin=True):
      response = self.testapp.get('/blockables/all/all', params)

    output = response.json

    self.assertIn('application/json', response.headers['Content-type'])
    self.assertIsInstance(output['content'], list)
    self.assertLen(output['content'], 1)

  def testAdminGetQueryByFileName(self):
    """Admin searching for a blockable by filename."""
    params = {'search': 'Not4Mac.exe', 'searchBase': 'fileName'}

    with self.LoggedInUser(admin=True):
      response = self.testapp.get('/blockables/all/all', params)

    output = response.json
    self.assertIn('application/json', response.headers['Content-type'])
    self.assertTrue(isinstance(output, dict))
    self.assertTrue(isinstance(output['content'], list))
    self.assertLen(output['content'], 1)

  def testAdminGetQueryByPublisher(self):
    """Admin searching for a blockable by filename."""
    params = {'search': 'Arple', 'searchBase': 'publisher'}

    with self.LoggedInUser(admin=True):
      response = self.testapp.get('/blockables/all/all', params)

    output = response.json
    self.assertIn('application/json', response.headers['Content-type'])
    self.assertTrue(isinstance(output, dict))
    self.assertTrue(isinstance(output['content'], list))
    self.assertLen(output['content'], 1)

  def testAdminGetQueryByProductName(self):
    """Admin searching for a blockable by filename."""
    params = {'search': 'New Shiny', 'searchBase': 'productName'}

    with self.LoggedInUser(admin=True):
      response = self.testapp.get('/blockables/all/all', params)

    output = response.json
    self.assertIn('application/json', response.headers['Content-type'])
    self.assertTrue(isinstance(output, dict))
    self.assertTrue(isinstance(output['content'], list))
    self.assertLen(output['content'], 1)

  def testAdminGetQueryPlatform(self):
    """Admin searching for a blockable by platform."""
    params = {'search': 'New Shiny', 'searchBase': 'productName'}

    with self.LoggedInUser(admin=True):
      response = self.testapp.get('/blockables/santa/binaries', params)

    output = response.json
    self.assertIn('application/json', response.headers['Content-type'])
    self.assertTrue(isinstance(output, dict))
    self.assertTrue(isinstance(output['content'], list))
    self.assertLen(output['content'], 1)

  def testAdminGetQueryByUnknown(self):
    """Admin searching for a blockable by an unknown property."""
    params = {'search': 'ProbablyNotReal', 'searchBase': 'notReal'}

    with self.LoggedInUser(admin=True):
      self.testapp.get(
          '/blockables/all/all', params, status=httplib.BAD_REQUEST)

  def testAdminGetQueryBadPlatform(self):
    """Admin searching by a property not valid for the specified platform."""
    params = {'search': 'DoesntMatter', 'searchBase': 'bundle_id'}

    with self.LoggedInUser(admin=True):
      self.testapp.get(
          '/blockables/bit9/binaries', params, status=httplib.BAD_REQUEST)


class BlockableHandlerTest(BlockablesTest):

  ROUTE = '/blockables/%s'

  def testGet_CaseInsensitiveID(self):

    sha256 = test_utils.RandomSHA256()
    test_utils.CreateBit9Binary(
        id=sha256, id_type=constants.ID_TYPE.SHA256, file_name='some_binary')

    with self.LoggedInUser():
      self.testapp.get(self.ROUTE % sha256.lower(), status=httplib.OK)
      self.testapp.get(self.ROUTE % sha256.upper(), status=httplib.OK)

  def testGet_User_Generic(self):
    """Normal user querying for a blockable by hash."""
    with self.LoggedInUser():
      response = self.testapp.get(self.ROUTE % self.generic_blockable.key.id())

    output = response.json

    self.assertIn('application/json', response.headers['Content-type'])
    self.assertIsInstance(output, dict)
    self.assertEqual(output['fileName'], self.generic_blockable.file_name)
    self.assertIsNone(output.get('operating_system_family'))
    self.assertIn('Blockable', output['class_'])

  def testGet_User_SantaBlockable(self):
    """Normal user querying for a blockable by hash."""
    with self.LoggedInUser():
      response = self.testapp.get(self.ROUTE % self.santa_blockable.key.id())

    output = response.json

    self.assertIn('application/json', response.headers['Content-type'])
    self.assertIsInstance(output, dict)
    self.assertEqual(output['fileName'], self.santa_blockable.file_name)
    self.assertEqual(output['operatingSystemFamily'], constants.PLATFORM.MACOS)
    self.assertIn('Blockable', output['class_'])
    self.assertIn('SantaBlockable', output['class_'])

  def testGet_User_Bit9Binary(self):
    """Normal user querying for a blockable by hash."""
    with self.LoggedInUser():
      response = self.testapp.get(self.ROUTE % self.bit9_blockable.key.id())

    output = response.json

    self.assertIn('application/json', response.headers['Content-type'])
    self.assertIsInstance(output, dict)
    self.assertEqual(output['id'], self.bit9_blockable.key.id())
    self.assertEqual(output['fileName'], self.bit9_blockable.file_name)
    self.assertEqual(output['operatingSystemFamily'],
                     constants.PLATFORM.WINDOWS)
    self.assertIn('Blockable', output['class_'])
    self.assertIn('Bit9Binary', output['class_'])

  def testGet_User_SantaCertificate(self):
    """Normal user querying for a cert by hash."""
    with self.LoggedInUser():
      response = self.testapp.get(self.ROUTE % self.santa_certificate.key.id())

    output = response.json

    self.assertIn('application/json', response.headers['Content-type'])
    self.assertIsInstance(output, dict)
    self.assertEqual(output['commonName'], self.santa_certificate.common_name)
    self.assertIn('Blockable', output['class_'])
    self.assertIn('SantaCertificate', output['class_'])

  def testGet_User_UnknownId_Santa(self):
    with self.LoggedInUser():
      self.testapp.get(self.ROUTE % 'Nonexistent', status=httplib.NOT_FOUND)

  def testPost_Admin_InsertUnknownType(self):
    """Admin tries to inject a blockable of unknown type."""
    sha256 = test_utils.RandomSHA256()
    params = {'type': 'Unknown', 'hash': sha256}

    with self.LoggedInUser(admin=True):
      self.testapp.post(self.ROUTE % sha256, params, status=httplib.BAD_REQUEST)

    self.assertNoBigQueryInsertions()

  def testPost_Admin_InsertExistingBlockable(self):
    """Admin tries to inject an existing blockable."""
    santa_blockable = test_utils.CreateSantaBlockable()
    sha256 = santa_blockable.key.id()
    params = {'type': constants.BLOCKABLE_TYPE.SANTA_BINARY, 'hash': sha256}

    with self.LoggedInUser(admin=True):
      self.testapp.post(self.ROUTE % sha256, params, status=httplib.CONFLICT)

    self.assertNoBigQueryInsertions()

  def testPost_Admin_InsertNewBlockable(self):
    """Admin posting a valid blockable."""
    sha256 = test_utils.RandomSHA256()
    params = {
        'type': constants.BLOCKABLE_TYPE.SANTA_BINARY,
        'fileName': 'MacIIci.app',
        'publisher': 'Arple'}

    expected_key = ndb.Key(santa.SantaBlockable, sha256)
    self.assertIsNone(expected_key.get())

    with self.LoggedInUser(admin=True):
      response = self.testapp.post(self.ROUTE % sha256, params)

    output = response.json

    self.assertIn('application/json', response.headers['Content-type'])
    self.assertEqual(output['id'], sha256)
    self.assertIsNotNone(expected_key.get())

    self.assertBigQueryInsertions(
        [constants.BIGQUERY_TABLE.BINARY], reset_mock=False)

    # Verify the FIRST_SEEN row in BigQuery.
    predicate = lambda c: c[1].get('action') == 'FIRST_SEEN'
    calls = self.GetBigQueryCalls(predicate=predicate)
    self.assertLen(calls, 1)

  def testPost_Admin_InsertNote(self):
    """Admin posting a valid blockable."""
    sha256 = test_utils.RandomSHA256()
    params = {
        'notes': 'foo',
        'fileName': 'bar',
        'type': constants.BLOCKABLE_TYPE.SANTA_BINARY}

    with self.LoggedInUser(admin=True):
      self.testapp.post(self.ROUTE % sha256, params)

    blockable = base.Blockable.get_by_id(sha256)
    self.assertEqual('bar', blockable.file_name)

    self.assertEntityCount(note_models.Note, 1)
    note = note_models.Note.query().fetch()[0]

    self.assertEqual(note.message, 'foo')
    self.assertEqual(note.key.parent(), blockable.key)

    self.assertBigQueryInsertions(
        [constants.BIGQUERY_TABLE.BINARY], reset_mock=False)

    # Verify the FIRST_SEEN row in BigQuery.
    predicate = lambda c: c[1].get('action') == 'FIRST_SEEN'
    calls = self.GetBigQueryCalls(predicate=predicate)
    self.assertLen(calls, 1)

  def testPost_Admin_Recount_Success(self):
    """Admin requesting a recount for a blockable."""
    # Create an anomalous global blacklist rule that should be deactivated by
    # the recount.
    rule = test_utils.CreateSantaRule(self.santa_blockable.key)
    self.assertTrue(rule.in_effect)

    id_ = self.santa_blockable.key.id()
    params = {'recount': 'recount'}
    with self.LoggedInUser(admin=True):
      response = self.testapp.post(self.ROUTE % id_, params)

    self.assertFalse(rule.key.get().in_effect)

    output = response.json
    self.assertIn('application/json', response.headers['Content-type'])
    self.assertIsInstance(output, dict)
    self.assertEqual(output['fileName'], self.santa_blockable.file_name)
    self.assertIn('Blockable', output['class_'])

  def testPost_Admin_RecountThenReset(self):
    """Test private reset method."""

    # Create a vote and trigger a recount on the blockable to update the score.
    test_utils.CreateVote(self.santa_blockable)
    self.santa_blockable.put()

    # Ensure Vote properly updated the blockable score.
    with self.LoggedInUser(admin=True):
      response = self.testapp.get(self.ROUTE % self.santa_blockable.key.id())
      output = response.json

      self.assertEqual(output['id'], self.santa_blockable.key.id())
      self.assertEqual(output['score'], 1)

      # Issue a reset and ensure the resulting score is 0.
      params = {'reset': 'reset'}
      response = self.testapp.post(
          self.ROUTE % self.santa_blockable.key.id(), params)
      output = response.json

      self.assertEqual(output['id'], self.santa_blockable.key.id())
      self.assertEqual(output['score'], 0)

    self.assertBigQueryInsertions(
        [constants.BIGQUERY_TABLE.BINARY, constants.BIGQUERY_TABLE.RULE])

  @mock.patch.object(
      blockables.voting_api, 'Recount',
      side_effect=voting_api.BlockableNotFoundError)
  def testPost_Admin_Recount_BlockableNotFoundError(self, mock_recount):
    with self.LoggedInUser(admin=True):
      self.testapp.post(
          self.ROUTE % test_utils.RandomSHA256(),
          params={'recount': 'recount'},
          status=httplib.NOT_FOUND)

  @mock.patch.object(
      blockables.voting_api, 'Recount',
      side_effect=voting_api.UnsupportedClientError)
  def testPost_Admin_Recount_UnsupportedClientError(self, mock_recount):
    with self.LoggedInUser(admin=True):
      self.testapp.post(
          self.ROUTE % test_utils.RandomSHA256(),
          params={'recount': 'recount'},
          status=httplib.BAD_REQUEST)

  @mock.patch.object(blockables.voting_api, 'Recount', side_effect=Exception)
  def testPost_Admin_Recount_Exception(self, mock_recount):
    with self.LoggedInUser(admin=True):
      self.testapp.post(
          self.ROUTE % test_utils.RandomSHA256(),
          params={'recount': 'recount'},
          status=httplib.INTERNAL_SERVER_ERROR)

  def testPost_Admin_Reset_Success(self):
    """Admin requesting a blockable be reset."""
    id_ = self.generic_blockable.key.id()
    params = {'reset': 'reset'}

    with self.LoggedInUser(admin=True):
      with mock.patch.object(
          blockables.BlockableHandler, '_reset_blockable') as mock_method:
        _ = self.testapp.post(self.ROUTE % id_, params)
        mock_method.assert_called_once_with(id_)

  @mock.patch.object(blockables.BlockableHandler, '_reset_blockable')
  def testPost_Admin_Reset_CaseInsensitiveID(self, mock_reset):

    sha256 = test_utils.RandomSHA256()
    test_utils.CreateBit9Binary(
        id=sha256, id_type=constants.ID_TYPE.SHA256, file_name='some_binary')

    params = {'reset': 'reset'}

    with self.LoggedInUser(admin=True):
      self.testapp.post(self.ROUTE % sha256.lower(), params, status=httplib.OK)
      self.testapp.post(self.ROUTE % sha256.upper(), params, status=httplib.OK)
      self.assertEqual(2, mock_reset.call_count)

  @mock.patch.object(
      blockables.voting_api, 'Reset',
      side_effect=voting_api.BlockableNotFoundError)
  def testPost_Admin_Reset_BlockableNotFoundError(self, mock_reset):
    with self.LoggedInUser(admin=True):
      self.testapp.post(
          self.ROUTE % test_utils.RandomSHA256(),
          params={'reset': 'reset'},
          status=httplib.NOT_FOUND)

  @mock.patch.object(
      blockables.voting_api, 'Reset',
      side_effect=voting_api.UnsupportedClientError)
  def testPost_Admin_Reset_UnsupportedClientError(self, mock_reset):
    with self.LoggedInUser(admin=True):
      self.testapp.post(
          self.ROUTE % test_utils.RandomSHA256(),
          params={'reset': 'reset'},
          status=httplib.BAD_REQUEST)

  @mock.patch.object(
      blockables.voting_api, 'Reset',
      side_effect=voting_api.OperationNotAllowedError)
  def testPost_Admin_Reset_OperationNotAllowedError(self, mock_reset):
    with self.LoggedInUser(admin=True):
      self.testapp.post(
          self.ROUTE % test_utils.RandomSHA256(),
          params={'reset': 'reset'},
          status=httplib.FORBIDDEN)

  @mock.patch.object(blockables.voting_api, 'Reset', side_effect=Exception)
  def testPost_Admin_Reset_Exception(self, mock_reset):
    with self.LoggedInUser(admin=True):
      self.testapp.post(
          self.ROUTE % test_utils.RandomSHA256(),
          params={'reset': 'reset'},
          status=httplib.INTERNAL_SERVER_ERROR)


class AuthorizedHostCountHandlerTest(BlockablesTest):

  ROUTE = '/blockables/%s/authorized-host-count'

  def testGet_GloballyWhitelisted(self):
    self.santa_blockable.state = constants.STATE.GLOBALLY_WHITELISTED
    self.santa_blockable.put()

    with self.LoggedInUser(admin=True):
      response = self.testapp.get(self.ROUTE % self.santa_blockable.key.id())
      output = response.json

      self.assertEqual(-1, output)

  def testGet_None(self):
    with self.LoggedInUser(admin=True):
      response = self.testapp.get(self.ROUTE % self.santa_blockable.key.id())
      output = response.json

      self.assertEqual(0, output)

  def testGet_Normal(self):
    expected = 3
    for i in xrange(expected):
      test_utils.CreateSantaRule(
          self.santa_blockable.key,
          policy=constants.RULE_POLICY.WHITELIST,
          host_id='host%s' % i)
    test_utils.CreateSantaRule(
        self.santa_blockable.key, policy=constants.RULE_POLICY.BLACKLIST)
    test_utils.CreateSantaRule(
        self.santa_blockable.key,
        policy=constants.RULE_POLICY.WHITELIST,
        in_effect=False)

    with self.LoggedInUser(admin=True):
      response = self.testapp.get(self.ROUTE % self.santa_blockable.key.id())
      output = response.json

      self.assertEqual(expected, output)

  def testGet_BlockableNotFoundError(self):
    with self.LoggedInUser(admin=True):
      self.testapp.get(
          self.ROUTE % 'NoteARealBlockable', status=httplib.NOT_FOUND)

  def testGet_BadBlockableType(self):
    with self.LoggedInUser(admin=True):
      self.testapp.get(
          self.ROUTE % self.bit9_blockable.key.id(), status=httplib.BAD_REQUEST)

  def testGet_NoPermission(self):
    with self.LoggedInUser():
      self.testapp.get(
          self.ROUTE % self.santa_blockable.key.id(), status=httplib.FORBIDDEN)

  def testGet_CaseInsensitiveID(self):

    sha256 = test_utils.RandomSHA256()
    test_utils.CreateSantaBlockable(
        id=sha256, id_type=constants.ID_TYPE.SHA256, file_name='some_binary')

    with self.LoggedInUser(admin=True):
      self.testapp.get(self.ROUTE % sha256.lower(), status=httplib.OK)
      self.testapp.get(self.ROUTE % sha256.upper(), status=httplib.OK)


class UniqueEventCountHandlerTest(BlockablesTest):

  ROUTE = '/blockables/%s/unique-event-count'

  def testGet_Binary_Normal(self):
    test_utils.CreateSantaEvent(self.santa_blockable)

    with self.LoggedInUser():
      response = self.testapp.get(self.ROUTE % self.santa_blockable.key.id())
    output = response.json

    self.assertEqual(1, output)

  def testGet_Cert_Normal(self):
    test_utils.CreateSantaEvent(
        self.santa_blockable, cert_sha256=self.santa_certificate.key.id())

    with self.LoggedInUser():
      response = self.testapp.get(self.ROUTE % self.santa_certificate.key.id())
    output = response.json

    self.assertEqual(1, output)

  def testGet_BlockableNotFoundError(self):
    self.santa_blockable.key.delete()
    with self.LoggedInUser():
      self.testapp.get(
          self.ROUTE % self.santa_blockable.key.id(), status=httplib.NOT_FOUND)

  def testGet_BadBlockableType(self):
    with self.LoggedInUser():
      self.testapp.get(
          self.ROUTE % self.generic_blockable.key.id(),
          status=httplib.BAD_REQUEST)

  def testGet_CaseInsensitiveID(self):

    sha256 = test_utils.RandomSHA256()
    test_utils.CreateSantaBlockable(
        id=sha256, id_type=constants.ID_TYPE.SHA256, file_name='some_binary')

    with self.LoggedInUser():
      self.testapp.get(self.ROUTE % sha256.lower(), status=httplib.OK)
      self.testapp.get(self.ROUTE % sha256.upper(), status=httplib.OK)


class PackageContentsHandlerTest(BlockablesTest):

  ROUTE = '/blockables/%s/contents'

  def testGet_Success_Bundle(self):
    test_blockables = test_utils.CreateSantaBlockables(4)
    bundle = test_utils.CreateSantaBundle(bundle_binaries=test_blockables)

    with self.LoggedInUser():
      response = self.testapp.get(self.ROUTE % bundle.key.id())
    output = response.json

    self.assertSameElements(
        (blockable.key.id() for blockable in test_blockables),
        (blockable_dict['id'] for blockable_dict in output))

  def testGet_Success_NoContents(self):
    bundle = test_utils.CreateSantaBundle()

    with self.LoggedInUser():
      response = self.testapp.get(self.ROUTE % bundle.key.id())
    output = response.json

    self.assertFalse(output)

  def testGet_Success_SantaBinaryOrder(self):
    bundle = test_utils.CreateSantaBundle(binary_count=4)
    path_pairs = [('a', 'z'), ('a', 'y'), ('a/b/c', 'x'), ('a/b', 'z')]
    expected_path_order = ['a/y', 'a/z', 'a/b/z', 'a/b/c/x']
    for rel_path, file_name in path_pairs:
      binary = test_utils.CreateSantaBlockable()
      package_models.SantaBundleBinary.Generate(
          bundle.key,
          binary.key,
          cert_key=binary.cert_key,
          rel_path=rel_path,
          file_name=file_name).put()

    with self.LoggedInUser():
      response = self.testapp.get(self.ROUTE % bundle.key.id())
    output = response.json

    self.assertListEqual(
        expected_path_order,
        [blockable_dict['fullPath'] for blockable_dict in output])

  def testGet_NotFound(self):
    with self.LoggedInUser():
      self.testapp.get(self.ROUTE % 'DoesntExist', status=httplib.NOT_FOUND)

  def testGet_NotAPackage(self):
    blockable = test_utils.CreateSantaBlockable()
    with self.LoggedInUser():
      self.testapp.get(
          self.ROUTE % blockable.key.id(), status=httplib.BAD_REQUEST)

  def testGet_NotASantaBundle(self):
    package_key = package_models.Package(id='foo', id_type='SHA256').put()
    with self.LoggedInUser():
      self.testapp.get(
          self.ROUTE % package_key.id(), status=httplib.BAD_REQUEST)


class PendingStateChangeHandlerTest(BlockablesTest):

  ROUTE = '/blockables/%s/pending-state-change'

  def testGet_PendingGlobalRule(self):
    test_utils.CreateBit9Rule(
        self.bit9_blockable.key, host_id='', is_committed=False)

    with self.LoggedInUser():
      response = self.testapp.get(self.ROUTE % self.bit9_blockable.key.id())
    output = response.json

    self.assertTrue(output)

  def testGet_PendingDisabledRule(self):
    test_utils.CreateBit9Rule(
        self.bit9_blockable.key,
        host_id='',
        is_committed=False,
        in_effect=False)

    with self.LoggedInUser():
      response = self.testapp.get(self.ROUTE % self.bit9_blockable.key.id())
    output = response.json

    self.assertFalse(output)

  def testGet_PendingGlobalRule_InstallerRule(self):
    test_utils.CreateBit9Rule(
        self.bit9_blockable.key,
        host_id='',
        policy=constants.RULE_POLICY.FORCE_INSTALLER,
        is_committed=False)

    with self.LoggedInUser():
      response = self.testapp.get(self.ROUTE % self.bit9_blockable.key.id())
    output = response.json

    self.assertFalse(output)

  def testGet_PendingLocalRule_ForUser(self):
    with self.LoggedInUser() as user:
      bit9_host = test_utils.CreateBit9Host(users=[user.nickname])
      test_utils.CreateBit9Rule(
          self.bit9_blockable.key,
          host_id=bit9_host.key.id(),
          user_key=user.key,
          is_committed=False)
      response = self.testapp.get(self.ROUTE % self.bit9_blockable.key.id())
    output = response.json

    self.assertTrue(output)

  def testGet_PendingLocalRule_ForSomeoneElse(self):
    other_user = test_utils.CreateUser()

    with self.LoggedInUser():
      bit9_host = test_utils.CreateBit9Host(users=[other_user.nickname])
      test_utils.CreateBit9Rule(
          self.bit9_blockable.key,
          host_id=bit9_host.key.id(),
          user_key=other_user.key,
          is_committed=False)
      response = self.testapp.get(self.ROUTE % self.bit9_blockable.key.id())
    output = response.json

    self.assertFalse(output)

  def testGet_NoRules(self):
    with self.LoggedInUser():
      response = self.testapp.get(self.ROUTE % self.bit9_blockable.key.id())
    output = response.json

    self.assertFalse(output)

  def testGet_OtherPlatform(self):
    with self.LoggedInUser():
      response = self.testapp.get(self.ROUTE % self.santa_blockable.key.id())
    output = response.json

    self.assertFalse(output)

  def testGet_UnknownBlockable(self):
    with self.LoggedInUser():
      self.testapp.get(
          self.ROUTE % 'not-a-real-blockable', status=httplib.NOT_FOUND)

  def testGet_CaseInsensitiveID(self):

    test_utils.CreateBit9Rule(
        self.bit9_blockable.key, host_id='', is_committed=False)
    sha256 = self.bit9_blockable.key.id()

    with self.LoggedInUser():
      self.testapp.get(self.ROUTE % sha256.lower(), status=httplib.OK)
      self.testapp.get(self.ROUTE % sha256.upper(), status=httplib.OK)


class PendingInstallerStateChangeHandlerTest(BlockablesTest):

  ROUTE = '/blockables/%s/pending-installer-state-change'

  def testGet_PendingInstallerRule(self):
    test_utils.CreateBit9Rule(
        self.bit9_blockable.key,
        is_committed=False,
        policy=constants.RULE_POLICY.FORCE_INSTALLER)

    with self.LoggedInUser():
      response = self.testapp.get(self.ROUTE % self.bit9_blockable.key.id())
    output = response.json

    self.assertTrue(output)

  def testGet_PendingNonInstallerRule(self):
    test_utils.CreateBit9Rule(
        self.bit9_blockable.key,
        is_committed=False,
        policy=constants.RULE_POLICY.WHITELIST)

    with self.LoggedInUser():
      response = self.testapp.get(self.ROUTE % self.bit9_blockable.key.id())
    output = response.json

    self.assertFalse(output)

  def testGet_PendingDisabledRule(self):
    test_utils.CreateBit9Rule(
        self.bit9_blockable.key,
        host_id='',
        is_committed=False,
        in_effect=False,
        policy=constants.RULE_POLICY.FORCE_INSTALLER)

    with self.LoggedInUser():
      response = self.testapp.get(self.ROUTE % self.bit9_blockable.key.id())
    output = response.json

    self.assertFalse(output)

  def testGet_NoRules(self):
    with self.LoggedInUser():
      response = self.testapp.get(self.ROUTE % self.bit9_blockable.key.id())
    output = response.json

    self.assertFalse(output)

  def testGet_OtherPlatform(self):
    with self.LoggedInUser():
      response = self.testapp.get(self.ROUTE % self.santa_blockable.key.id())
    output = response.json

    self.assertFalse(output)

  def testGet_UnknownBlockable(self):
    with self.LoggedInUser():
      self.testapp.get(
          '/blockables/not-a-real-blockable/pending-installer-state-change',
          status=httplib.NOT_FOUND)

  def testGet_CaseInsensitiveID(self):

    test_utils.CreateBit9Rule(
        self.bit9_blockable.key,
        is_committed=False,
        policy=constants.RULE_POLICY.FORCE_INSTALLER)
    sha256 = self.bit9_blockable.key.id()

    with self.LoggedInUser():
      self.testapp.get(self.ROUTE % sha256.lower(), status=httplib.OK)
      self.testapp.get(self.ROUTE % sha256.upper(), status=httplib.OK)


class SetInstallerStateHandlerTest(BlockablesTest):

  ROUTE = '/blockables/%s/installer-state'

  def testPost_NoPreexistingRule(self):
    self.assertFalse(self.bit9_blockable.is_installer)

    with self.LoggedInUser():
      response = self.testapp.post(
          self.ROUTE % self.bit9_blockable.key.id(), {'value': True})
    output = response.json

    self.assertTrue(output)

    self.assertEntityCount(rule_models.Bit9Rule, 1)
    self.assertEntityCount(rule_models.RuleChangeSet, 1)
    self.assertBigQueryInsertion(constants.BIGQUERY_TABLE.BINARY)
    self.assertTrue(self.bit9_blockable.key.get().is_installer)
    self.assertTaskCount(constants.TASK_QUEUE.BIT9_COMMIT_CHANGE, 1)

  def testPost_PreexistingRule(self):
    test_utils.CreateBit9Rule(
        self.bit9_blockable.key, policy=constants.RULE_POLICY.FORCE_INSTALLER)
    self.bit9_blockable.is_installer = True
    self.bit9_blockable.put()

    with self.LoggedInUser():
      response = self.testapp.post(
          self.ROUTE % self.bit9_blockable.key.id(), {'value': False})
    output = response.json

    self.assertFalse(output)

    self.assertEntityCount(rule_models.Bit9Rule, 2)
    self.assertEntityCount(rule_models.RuleChangeSet, 1)
    self.assertBigQueryInsertion(constants.BIGQUERY_TABLE.BINARY)
    self.assertFalse(self.bit9_blockable.key.get().is_installer)
    self.assertTaskCount(constants.TASK_QUEUE.BIT9_COMMIT_CHANGE, 1)

  def testPost_SameStateAsPreexistingRule(self):
    test_utils.CreateBit9Rule(
        self.bit9_blockable.key, policy=constants.RULE_POLICY.FORCE_INSTALLER)
    self.bit9_blockable.is_installer = True
    self.bit9_blockable.put()

    with self.LoggedInUser():
      response = self.testapp.post(
          self.ROUTE % self.bit9_blockable.key.id(), {'value': True})
    output = response.json

    self.assertTrue(output)

    self.assertEntityCount(rule_models.Bit9Rule, 1)
    self.assertEntityCount(rule_models.RuleChangeSet, 0)
    self.assertTrue(self.bit9_blockable.key.get().is_installer)
    self.assertTaskCount(constants.TASK_QUEUE.BIT9_COMMIT_CHANGE, 0)

  def testPost_OtherPlatform(self):
    with self.LoggedInUser():
      self.testapp.post(
          self.ROUTE % self.santa_blockable.key.id(), {'value': 'false'},
          status=httplib.BAD_REQUEST)

  def testPost_UnknownBlockable(self):
    with self.LoggedInUser():
      self.testapp.post(
          self.ROUTE % 'not-a-real-blockable', {'value': 'false'},
          status=httplib.NOT_FOUND)

  def testPost_CaseInsensitiveID(self):

    sha256 = test_utils.RandomSHA256()
    test_utils.CreateBit9Binary(
        id=sha256, id_type=constants.ID_TYPE.SHA256, file_name='some_binary')

    with self.LoggedInUser():
      self.testapp.post(self.ROUTE % sha256.lower(), {'value': True})
      self.testapp.post(self.ROUTE % sha256.upper(), {'value': True})

    self.assertBigQueryInsertion(constants.BIGQUERY_TABLE.BINARY)


if __name__ == '__main__':
  basetest.main()
