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
from upvote.gae.datastore import utils
from upvote.gae.datastore.models import base
from upvote.gae.datastore.models import bit9
from upvote.gae.datastore.models import santa
from upvote.gae.modules.upvote_app.api.handlers import blockables
from upvote.gae.shared.common import basetest
from upvote.shared import constants


class BlockablesTest(basetest.UpvoteTestCase):
  """Base class for Audit Logs handler tests."""

  def setUp(self, app):
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
        file_name='Not4Mac.exe',
        state=constants.STATE.SUSPECT)
    self.santa_blockable = test_utils.CreateSantaBlockable(
        publisher='Arple',
        product_name='New Shiny',
        flagged=True)
    self.santa_certificate = test_utils.CreateSantaCertificate(
        id_type=constants.ID_TYPE.SHA256,
        common_name='Best Cert Ever',
        organization='Totally Legit CA')

    self.PatchValidateXSRFToken()


class BlockableQueryHandlerTest(BlockablesTest):

  def setUp(self):
    app = webapp2.WSGIApplication([
        webapp2.Route('/<platform>/<blockable_type>',
                      handler=blockables.BlockableQueryHandler)])
    super(BlockableQueryHandlerTest, self).setUp(app)

  def testAdminGetList(self):
    """Admin getting list of all blockables."""
    with self.LoggedInUser(admin=True):
      response = self.testapp.get('/all/all')

    output = response.json

    self.assertIn('application/json', response.headers['Content-type'])
    self.assertIsInstance(output['content'], list)
    self.assertEqual(len(output['content']), 5)

  def testAdminGetListWithPlatform(self):
    """Admin getting list of all blockables on a specific platform."""
    with self.LoggedInUser(admin=True):
      response = self.testapp.get('/santa/certificates')

    output = response.json

    self.assertIn('application/json', response.headers['Content-type'])
    self.assertIsInstance(output['content'], list)
    self.assertEqual(len(output['content']), 1)

  def testUserGetBlockableList(self):
    """Normal user getting a list of all blockables."""

    with self.LoggedInUser():
      self.testapp.get('/all/all', status=httplib.FORBIDDEN)

  def testUserGetFlaggedBlockables(self):
    """Normal user getting a list of flagged blockables."""
    params = {'filter': 'flagged'}
    with self.LoggedInUser():
      self.testapp.get('/all/all', params, status=httplib.FORBIDDEN)

  def testUserGetSuspectBlockables(self):
    """Normal user getting a list of suspect blockables."""
    params = {'filter': 'suspect'}
    with self.LoggedInUser():
      self.testapp.get('/all/all', params, status=httplib.FORBIDDEN)

  def testUserGetOwnBlockables(self):

    user_1 = test_utils.CreateUser()
    user_2 = test_utils.CreateUser()

    # Create two events for this user.
    test_utils.CreateBit9Event(
        self.bit9_blockable,
        executing_user=user_2.nickname,
        host_id='a_host_id',
        parent=utils.ConcatenateKeys(
            user_2.key, ndb.Key('Host', 'a_host_id'),
            self.santa_blockable.key)
    )
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
        parent=utils.ConcatenateKeys(
            user_2.key, ndb.Key('Host', host_id),
            self.santa_blockable.key)
    )
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
        parent=utils.ConcatenateKeys(
            user_1.key, ndb.Key('Host', 'a_host_id'),
            self.santa_blockable.key)
    )

    params = {'filter': 'own'}
    with self.LoggedInUser(user=user_2):
      response = self.testapp.get('/all/all', params)

    output = response.json

    # Verify that only two blockables (from the two events) are returned to
    # this user.
    self.assertIn('application/json', response.headers['Content-type'])
    self.assertIsInstance(output['content'], list)
    self.assertEqual(len(output['content']), 2)

  def testUserGetOwnBlockables_UserHasNoBlockables(self):
    params = {'filter': 'own'}
    with self.LoggedInUser():
      response = self.testapp.get('/all/all', params)
    output = response.json

    self.assertIn('application/json', response.headers['Content-type'])
    self.assertIsInstance(output['content'], list)
    self.assertEqual(len(output['content']), 0)

  def testAdminGetListOfFlaggedBlockables(self):
    """Admin getting a list of flagged blockables."""
    params = {'filter': 'flagged'}

    with self.LoggedInUser(admin=True):
      response = self.testapp.get('/all/all', params)

    output = response.json

    self.assertIn('application/json', response.headers['Content-type'])
    self.assertIsInstance(output['content'], list)
    self.assertEqual(len(output['content']), 1)

  def testAdminGetListOfSuspectBlockables(self):
    """Admin getting a list of flagged blockables."""
    params = {'filter': 'suspect'}

    with self.LoggedInUser(admin=True):
      response = self.testapp.get('/all/all', params)

    output = response.json

    self.assertIn('application/json', response.headers['Content-type'])
    self.assertIsInstance(output['content'], list)
    self.assertEqual(len(output['content']), 1)

  def testAdminGetQueryByFileName(self):
    """Admin searching for a blockable by filename."""
    params = {'search': 'Not4Mac.exe', 'searchBase': 'fileName'}

    with self.LoggedInUser(admin=True):
      response = self.testapp.get('/all/all', params)

    output = response.json
    self.assertIn('application/json', response.headers['Content-type'])
    self.assertTrue(isinstance(output, dict))
    self.assertTrue(isinstance(output['content'], list))
    self.assertEqual(len(output['content']), 1)

  def testAdminGetQueryByPublisher(self):
    """Admin searching for a blockable by filename."""
    params = {'search': 'Arple', 'searchBase': 'publisher'}

    with self.LoggedInUser(admin=True):
      response = self.testapp.get('/all/all', params)

    output = response.json
    self.assertIn('application/json', response.headers['Content-type'])
    self.assertTrue(isinstance(output, dict))
    self.assertTrue(isinstance(output['content'], list))
    self.assertEqual(len(output['content']), 1)

  def testAdminGetQueryByProductName(self):
    """Admin searching for a blockable by filename."""
    params = {'search': 'New Shiny', 'searchBase': 'productName'}

    with self.LoggedInUser(admin=True):
      response = self.testapp.get('/all/all', params)

    output = response.json
    self.assertIn('application/json', response.headers['Content-type'])
    self.assertTrue(isinstance(output, dict))
    self.assertTrue(isinstance(output['content'], list))
    self.assertEqual(len(output['content']), 1)

  def testAdminGetQueryPlatform(self):
    """Admin searching for a blockable by platform."""
    params = {'search': 'New Shiny', 'searchBase': 'productName'}

    with self.LoggedInUser(admin=True):
      response = self.testapp.get('/santa/binaries', params)

    output = response.json
    self.assertIn('application/json', response.headers['Content-type'])
    self.assertTrue(isinstance(output, dict))
    self.assertTrue(isinstance(output['content'], list))
    self.assertEqual(len(output['content']), 1)

  def testAdminGetQueryByUnknown(self):
    """Admin searching for a blockable by an unknown property."""
    params = {'search': 'ProbablyNotReal', 'searchBase': 'notReal'}

    with self.LoggedInUser(admin=True):
      self.testapp.get('/all/all', params, status=httplib.BAD_REQUEST)

  def testAdminGetQueryBadPlatform(self):
    """Admin searching by a property not valid for the specified platform."""
    params = {'search': 'DoesntMatter', 'searchBase': 'bundle_id'}

    with self.LoggedInUser(admin=True):
      self.testapp.get('/bit9/binaries', params, status=httplib.BAD_REQUEST)


class BlockableHandlerTest(BlockablesTest):

  def setUp(self):
    app = webapp2.WSGIApplication(
        [webapp2.Route('/<blockable_id>',
                       handler=blockables.BlockableHandler)])
    super(BlockableHandlerTest, self).setUp(app)

  def testUserGetGenericByID(self):
    """Normal user querying for a blockable by hash."""
    with self.LoggedInUser():
      response = self.testapp.get('/' + self.generic_blockable.key.id())

    output = response.json

    self.assertIn('application/json', response.headers['Content-type'])
    self.assertIsInstance(output, dict)
    self.assertEqual(output['fileName'], self.generic_blockable.file_name)
    self.assertIsNone(output.get('operating_system_family'))
    self.assertIn('Blockable', output['class_'])

  def testUserGetSantaBlockableByID(self):
    """Normal user querying for a blockable by hash."""
    with self.LoggedInUser():
      response = self.testapp.get('/' + self.santa_blockable.key.id())

    output = response.json

    self.assertIn('application/json', response.headers['Content-type'])
    self.assertIsInstance(output, dict)
    self.assertEqual(output['fileName'], self.santa_blockable.file_name)
    self.assertEqual(
        output['operatingSystemFamily'], constants.PLATFORM.MACOS)
    self.assertIn('Blockable', output['class_'])
    self.assertIn('SantaBlockable', output['class_'])

  def testUserGetBit9BinaryByID(self):
    """Normal user querying for a blockable by hash."""
    with self.LoggedInUser():
      response = self.testapp.get('/' + self.bit9_blockable.key.id())

    output = response.json

    self.assertIn('application/json', response.headers['Content-type'])
    self.assertIsInstance(output, dict)
    self.assertEqual(output['id'], self.bit9_blockable.key.id())
    self.assertEqual(output['fileName'], self.bit9_blockable.file_name)
    self.assertEqual(
        output['operatingSystemFamily'], constants.PLATFORM.WINDOWS)
    self.assertIn('Blockable', output['class_'])
    self.assertIn('Bit9Binary', output['class_'])

  def testUserGetSantaCertificateByID(self):
    """Normal user querying for a cert by hash."""
    with self.LoggedInUser():
      response = self.testapp.get('/' + self.santa_certificate.key.id())

    output = response.json

    self.assertIn('application/json', response.headers['Content-type'])
    self.assertIsInstance(output, dict)
    self.assertEqual(
        output['commonName'], self.santa_certificate.common_name)
    self.assertIn('Blockable', output['class_'])
    self.assertIn('SantaCertificate', output['class_'])

  def AddBlockableToDatastore(self, *args):
    test_utils.CreateSantaBlockable(id='NotYetSynced')
    return mock.Mock(status_code=httplib.OK)

  def testUserGetUnknownId_Santa(self):
    with self.LoggedInUser():
      self.testapp.get('/Nonexistent', status=httplib.NOT_FOUND)

  def testAdminPostCallRecount(self):
    """Admin requesting a recount for a blockable."""
    # Create an anomalous global blacklist rule that should be deactivated by
    # the recount.
    rule = test_utils.CreateSantaRule(self.santa_blockable.key)
    self.assertTrue(rule.in_effect)

    id_ = self.santa_blockable.key.id()
    params = {'recount': 'recount'}
    with self.LoggedInUser(admin=True):
      response = self.testapp.post('/' + id_, params)

    self.assertFalse(rule.key.get().in_effect)

    output = response.json
    self.assertIn('application/json', response.headers['Content-type'])
    self.assertIsInstance(output, dict)
    self.assertEqual(output['fileName'], self.santa_blockable.file_name)
    self.assertIn('Blockable', output['class_'])

  def testAdminPostReset(self):
    """Admin requesting a blockable be reset."""
    id_ = self.generic_blockable.key.id()
    params = {'reset': 'reset'}

    with self.LoggedInUser(admin=True):
      with mock.patch.object(
          blockables.BlockableHandler, '_reset_blockable') as mock_method:
        _ = self.testapp.post('/' + id_, params)
        mock_method.assert_called_once_with(id_)

  def testAdminPostInsertUnknownType(self):
    """Admin tries to inject a blockable of unknown type."""
    id_ = 'qqqqrrrrsssstttt'
    params = {'type': 'mock_blockable', 'hash': id_}

    with mock.patch.object(blockables, 'model_mapping') as mock_mapping:
      mock_mapping.BlockableTypeModelMap.mock_blockable = None
      with self.LoggedInUser(admin=True):
        self.testapp.post('/' + id_, params, status=httplib.BAD_REQUEST)

  def testAdminPostInsertExistingID(self):
    """Admin tries to inject an existing blockable."""
    id_ = self.generic_blockable.key.id()
    params = {'type': 'Blockable', 'hash': id_}

    with mock.patch.object(blockables, 'model_mapping'):
      with self.LoggedInUser(admin=True):
        self.testapp.post('/' + id_, params, status=httplib.CONFLICT)

  def testAdminPostInsert(self):
    """Admin posting a valid blockable."""
    id_ = 'qqqqrrrrsssstttt'
    params = {
        'type': constants.BLOCKABLE_TYPE.SANTA_BINARY,
        'fileName': 'MacIIci.app',
        'publisher': 'Arple'}
    mock_model = mock.MagicMock()
    mock_model.get_by_id.return_value = False
    test_blockable = test_utils.CreateBlockable(id=id_)
    mock_model.get_or_insert.return_value = test_blockable

    with mock.patch.object(blockables, 'model_mapping') as mock_mapping:
      mock_mapping.BlockableTypeModelMap.SANTA_BINARY = mock_model
      with self.LoggedInUser(admin=True):
        response = self.testapp.post('/%s' % id_, params)

    output = response.json

    self.assertIn('application/json', response.headers['Content-type'])
    self.assertEqual(output['id'], 'qqqqrrrrsssstttt')
    mock_model.get_or_insert.assert_called_with(
        'qqqqrrrrsssstttt',
        file_name='MacIIci.app',
        publisher='Arple',
        flagged=False,
        id_type=constants.ID_TYPE.SHA256
    )

  def testAdminPostInsert_Note(self):
    """Admin posting a valid blockable."""
    id_ = 'qqqqrrrrsssstttt'
    params = {
        'notes': 'foo',
        'fileName': 'bar',
        'type': constants.BLOCKABLE_TYPE.SANTA_BINARY}

    with self.LoggedInUser(admin=True):
      self.testapp.post('/%s' % id_, params)

    blockable = base.Blockable.get_by_id(id_)
    self.assertEqual('bar', blockable.file_name)

    self.assertEntityCount(base.Note, 1)
    note = base.Note.query().fetch()[0]

    self.assertEqual(note.message, 'foo')
    self.assertEqual(note.key.parent(), blockable.key)

  def testResetBlockable(self):
    """Test private reset method."""

    # Create a vote and trigger a recount on the blockable to update the score.
    test_utils.CreateVote(self.santa_blockable)
    self.santa_blockable.put()

    # Ensure Vote properly updated the blockable score.
    with self.LoggedInUser(admin=True):
      response = self.testapp.get('/%s' % self.santa_blockable.key.id())
      output = response.json

      self.assertEqual(output['id'], self.santa_blockable.key.id())
      self.assertEqual(output['score'], 1)

      # Issue a reset and ensure the resulting score is 0.
      params = {'reset': 'reset'}
      response = self.testapp.post(
          '/%s' % self.santa_blockable.key.id(), params)
      output = response.json

      self.assertEqual(output['id'], self.santa_blockable.key.id())
      self.assertEqual(output['score'], 0)


class AuthorizedHostCountHandlerTest(BlockablesTest):

  def setUp(self):
    app = webapp2.WSGIApplication(
        [webapp2.Route(r'/<blockable_id>',
                       handler=blockables.AuthorizedHostCountHandler)])
    super(AuthorizedHostCountHandlerTest, self).setUp(app)

  def testGloballyWhitelisted(self):
    self.santa_blockable.state = constants.STATE.GLOBALLY_WHITELISTED
    self.santa_blockable.put()

    with self.LoggedInUser(admin=True):
      response = self.testapp.get('/%s' % self.santa_blockable.key.id())
      output = response.json

      self.assertEqual(-1, output)

  def testNone(self):
    with self.LoggedInUser(admin=True):
      response = self.testapp.get('/%s' % self.santa_blockable.key.id())
      output = response.json

      self.assertEqual(0, output)

  def testNormal(self):
    expected = 3
    for i in xrange(expected):
      test_utils.CreateSantaRule(
          self.santa_blockable.key,
          policy=constants.RULE_POLICY.WHITELIST,
          host_id='host%s' % i)
    test_utils.CreateSantaRule(
        self.santa_blockable.key,
        policy=constants.RULE_POLICY.BLACKLIST)
    test_utils.CreateSantaRule(
        self.santa_blockable.key,
        policy=constants.RULE_POLICY.WHITELIST,
        in_effect=False)

    with self.LoggedInUser(admin=True):
      response = self.testapp.get('/%s' % self.santa_blockable.key.id())
      output = response.json

      self.assertEqual(expected, output)

  def testBlockableNotFound(self):
    with self.LoggedInUser(admin=True):
      self.testapp.get('/NotARealBlockable', status=httplib.NOT_FOUND)

  def testBadBlockableType(self):
    with self.LoggedInUser(admin=True):
      self.testapp.get(
          '/%s' % self.bit9_blockable.key.id(), status=httplib.BAD_REQUEST)

  def testNoPermission(self):
    with self.LoggedInUser():
      self.testapp.get(
          '/%s' % self.santa_blockable.key.id(), status=httplib.FORBIDDEN)


class UniqueEventCountHandlerTest(BlockablesTest):

  def setUp(self):
    app = webapp2.WSGIApplication(
        [webapp2.Route(r'/<blockable_id>',
                       handler=blockables.UniqueEventCountHandler)])
    super(UniqueEventCountHandlerTest, self).setUp(app)

  def testBinary_Normal(self):
    test_utils.CreateSantaEvent(self.santa_blockable)

    with self.LoggedInUser():
      response = self.testapp.get('/%s' % self.santa_blockable.key.id())
    output = response.json

    self.assertEqual(1, output)

  def testCert_Normal(self):
    test_utils.CreateSantaEvent(
        self.santa_blockable,
        cert_sha256=self.santa_certificate.key.id())

    with self.LoggedInUser():
      response = self.testapp.get('/%s' % self.santa_certificate.key.id())
    output = response.json

    self.assertEqual(1, output)

  def testBlockableNotFound(self):
    self.santa_blockable.key.delete()
    with self.LoggedInUser():
      self.testapp.get(
          '/%s' % self.santa_blockable.key.id(), status=httplib.NOT_FOUND)

  def testBadBlockableType(self):
    with self.LoggedInUser():
      self.testapp.get(
          '/%s' % self.generic_blockable.key.id(),
          status=httplib.BAD_REQUEST)


class PackageContentsHandlerTest(BlockablesTest):

  def setUp(self):
    app = webapp2.WSGIApplication(
        [webapp2.Route(r'/<package_id>',
                       handler=blockables.PackageContentsHandler)])
    super(PackageContentsHandlerTest, self).setUp(app)

  def testSuccess_Bundle(self):
    test_blockables = test_utils.CreateSantaBlockables(4)
    bundle = test_utils.CreateSantaBundle(bundle_binaries=test_blockables)

    with self.LoggedInUser():
      response = self.testapp.get('/%s' % bundle.key.id())
    output = response.json

    self.assertSameElements(
        (blockable.key.id() for blockable in test_blockables),
        (blockable_dict['id'] for blockable_dict in output))

  def testSuccess_NoContents(self):
    bundle = test_utils.CreateSantaBundle()

    with self.LoggedInUser():
      response = self.testapp.get('/%s' % bundle.key.id())
    output = response.json

    self.assertFalse(output)

  def testSuccess_SantaBinaryOrder(self):
    bundle = test_utils.CreateSantaBundle(binary_count=4)
    path_pairs = [('a', 'z'), ('a', 'y'), ('a/b/c', 'x'), ('a/b', 'z')]
    expected_path_order = ['a/y', 'a/z', 'a/b/z', 'a/b/c/x']
    for rel_path, file_name in path_pairs:
      binary = test_utils.CreateSantaBlockable()
      santa.SantaBundleBinary.Generate(
          bundle.key, binary.key, cert_key=binary.cert_key,
          rel_path=rel_path, file_name=file_name).put()

    with self.LoggedInUser():
      response = self.testapp.get('/%s' % bundle.key.id())
    output = response.json

    self.assertListEqual(
        expected_path_order,
        [blockable_dict['fullPath'] for blockable_dict in output])

  def testNotFound(self):
    with self.LoggedInUser():
      self.testapp.get('/DoesntExist', status=httplib.NOT_FOUND)

  def testNotAPackage(self):
    blockable = test_utils.CreateSantaBlockable()
    with self.LoggedInUser():
      self.testapp.get('/%s' % blockable.key.id(), status=httplib.BAD_REQUEST)

  def testNotASantaBundle(self):
    package_key = base.Package(id='foo', id_type='SHA256').put()
    with self.LoggedInUser():
      self.testapp.get('/%s' % package_key.id(), status=httplib.BAD_REQUEST)


class PendingStateChangeHandlerTest(BlockablesTest):

  def setUp(self):
    app = webapp2.WSGIApplication(
        [webapp2.Route(
            r'/<blockable_id>', handler=blockables.PendingStateChangeHandler)])
    super(PendingStateChangeHandlerTest, self).setUp(app)

  def testPendingGlobalRule(self):
    test_utils.CreateBit9Rule(
        self.bit9_blockable.key, host_id='', is_committed=False)

    with self.LoggedInUser():
      response = self.testapp.get('/%s' % self.bit9_blockable.key.id())
    output = response.json

    self.assertTrue(output)

  def testPendingDisabledRule(self):
    test_utils.CreateBit9Rule(
        self.bit9_blockable.key, host_id='', is_committed=False,
        in_effect=False)

    with self.LoggedInUser():
      response = self.testapp.get('/%s' % self.bit9_blockable.key.id())
    output = response.json

    self.assertFalse(output)

  def testPendingGlobalRule_InstallerRule(self):
    test_utils.CreateBit9Rule(
        self.bit9_blockable.key, host_id='',
        policy=constants.RULE_POLICY.FORCE_INSTALLER, is_committed=False)

    with self.LoggedInUser():
      response = self.testapp.get('/%s' % self.bit9_blockable.key.id())
    output = response.json

    self.assertFalse(output)

  def testPendingLocalRule_ForUser(self):
    with self.LoggedInUser() as user:
      bit9_host = test_utils.CreateBit9Host(users=[user.nickname])
      test_utils.CreateBit9Rule(
          self.bit9_blockable.key, host_id=bit9_host.key.id(),
          user_key=user.key, is_committed=False)
      response = self.testapp.get('/%s' % self.bit9_blockable.key.id())
    output = response.json

    self.assertTrue(output)

  def testPendingLocalRule_ForSomeoneElse(self):
    other_user = test_utils.CreateUser()

    with self.LoggedInUser():
      bit9_host = test_utils.CreateBit9Host(users=[other_user.nickname])
      test_utils.CreateBit9Rule(
          self.bit9_blockable.key, host_id=bit9_host.key.id(),
          user_key=other_user.key, is_committed=False)
      response = self.testapp.get('/%s' % self.bit9_blockable.key.id())
    output = response.json

    self.assertFalse(output)

  def testNoRules(self):
    with self.LoggedInUser():
      response = self.testapp.get('/%s' % self.bit9_blockable.key.id())
    output = response.json

    self.assertFalse(output)

  def testOtherPlatform(self):
    with self.LoggedInUser():
      response = self.testapp.get('/%s' % self.santa_blockable.key.id())
    output = response.json

    self.assertFalse(output)

  def testUnknownBlockable(self):
    with self.LoggedInUser():
      self.testapp.get('/not-a-real-blockable', status=httplib.NOT_FOUND)


class PendingInstallerStateChangeHandlerTest(BlockablesTest):

  def setUp(self):
    app = webapp2.WSGIApplication(
        [webapp2.Route(
            r'/<blockable_id>',
            handler=blockables.PendingInstallerStateChangeHandler)])
    super(PendingInstallerStateChangeHandlerTest, self).setUp(app)

  def testPendingInstallerRule(self):
    test_utils.CreateBit9Rule(
        self.bit9_blockable.key, is_committed=False,
        policy=constants.RULE_POLICY.FORCE_INSTALLER)

    with self.LoggedInUser():
      response = self.testapp.get('/%s' % self.bit9_blockable.key.id())
    output = response.json

    self.assertTrue(output)

  def testPendingNonInstallerRule(self):
    test_utils.CreateBit9Rule(
        self.bit9_blockable.key, is_committed=False,
        policy=constants.RULE_POLICY.WHITELIST)

    with self.LoggedInUser():
      response = self.testapp.get('/%s' % self.bit9_blockable.key.id())
    output = response.json

    self.assertFalse(output)

  def testPendingDisabledRule(self):
    test_utils.CreateBit9Rule(
        self.bit9_blockable.key, host_id='', is_committed=False,
        in_effect=False, policy=constants.RULE_POLICY.FORCE_INSTALLER)

    with self.LoggedInUser():
      response = self.testapp.get('/%s' % self.bit9_blockable.key.id())
    output = response.json

    self.assertFalse(output)

  def testNoRules(self):
    with self.LoggedInUser():
      response = self.testapp.get('/%s' % self.bit9_blockable.key.id())
    output = response.json

    self.assertFalse(output)

  def testOtherPlatform(self):
    with self.LoggedInUser():
      response = self.testapp.get('/%s' % self.santa_blockable.key.id())
    output = response.json

    self.assertFalse(output)

  def testUnknownBlockable(self):
    with self.LoggedInUser():
      self.testapp.get('/not-a-real-blockable', status=httplib.NOT_FOUND)


class SetInstallerStateHandlerTest(BlockablesTest):

  def setUp(self):
    app = webapp2.WSGIApplication(
        [webapp2.Route(
            r'/<blockable_id>', handler=blockables.SetInstallerStateHandler)])
    super(SetInstallerStateHandlerTest, self).setUp(app)

  def testNoPreexistingRule(self):
    self.assertFalse(self.bit9_blockable.is_installer)

    with self.LoggedInUser():
      response = self.testapp.post(
          '/%s' % self.bit9_blockable.key.id(), {'value': True})
    output = response.json

    self.assertTrue(output)

    self.assertEntityCount(bit9.Bit9Rule, 1)
    self.assertEntityCount(bit9.RuleChangeSet, 1)
    self.assertEntityCount(base.AuditLog, 1, ancestor=self.bit9_blockable.key)
    self.assertTrue(self.bit9_blockable.key.get().is_installer)
    self.assertTaskCount(constants.TASK_QUEUE.BIT9_COMMIT_CHANGE, 1)

  def testPreexistingRule(self):
    test_utils.CreateBit9Rule(
        self.bit9_blockable.key,
        policy=constants.RULE_POLICY.FORCE_INSTALLER)
    self.bit9_blockable.is_installer = True
    self.bit9_blockable.put()

    with self.LoggedInUser():
      response = self.testapp.post(
          '/%s' % self.bit9_blockable.key.id(), {'value': False})
    output = response.json

    self.assertFalse(output)

    self.assertEntityCount(bit9.Bit9Rule, 2)
    self.assertEntityCount(bit9.RuleChangeSet, 1)
    self.assertEntityCount(base.AuditLog, 1, ancestor=self.bit9_blockable.key)
    self.assertFalse(self.bit9_blockable.key.get().is_installer)
    self.assertTaskCount(constants.TASK_QUEUE.BIT9_COMMIT_CHANGE, 1)

  def testSameStateAsPreexistingRule(self):
    test_utils.CreateBit9Rule(
        self.bit9_blockable.key,
        policy=constants.RULE_POLICY.FORCE_INSTALLER)
    self.bit9_blockable.is_installer = True
    self.bit9_blockable.put()

    with self.LoggedInUser():
      response = self.testapp.post(
          '/%s' % self.bit9_blockable.key.id(), {'value': True})
    output = response.json

    self.assertTrue(output)

    self.assertEntityCount(bit9.Bit9Rule, 1)
    self.assertEntityCount(bit9.RuleChangeSet, 0)
    self.assertEntityCount(base.AuditLog, 0)
    self.assertTrue(self.bit9_blockable.key.get().is_installer)
    self.assertTaskCount(constants.TASK_QUEUE.BIT9_COMMIT_CHANGE, 0)

  def testOtherPlatform(self):
    with self.LoggedInUser():
      self.testapp.post(
          '/%s' % self.santa_blockable.key.id(), {'value': 'false'},
          status=httplib.BAD_REQUEST)

  def testUnknownBlockable(self):
    with self.LoggedInUser():
      self.testapp.post(
          '/not-a-real-blockable', {'value': 'false'}, status=httplib.NOT_FOUND)


if __name__ == '__main__':
  basetest.main()
