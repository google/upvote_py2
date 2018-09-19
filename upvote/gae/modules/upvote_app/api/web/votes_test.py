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

"""Unit tests for Votes handlers."""

import httplib
import mock

import webapp2

from google.appengine.ext import ndb

from upvote.gae.datastore import test_utils
from upvote.gae.datastore import utils
from upvote.gae.datastore.models import base as base_models
from upvote.gae.lib.testing import basetest
from upvote.gae.lib.voting import api as voting_api
from upvote.gae.modules.upvote_app.api.web import votes
from upvote.shared import constants


class VotesTest(basetest.UpvoteTestCase):
  """Test Votes Handler Class."""

  def setUp(self):
    app = webapp2.WSGIApplication(routes=[votes.ROUTES])
    super(VotesTest, self).setUp(wsgi_app=app)

    self.santa_blockable = test_utils.CreateSantaBlockable()
    self.other_blockable = test_utils.CreateSantaBlockable()
    self.santa_certificate = test_utils.CreateSantaCertificate()

    self.user_1 = test_utils.CreateUser()
    self.user_2 = test_utils.CreateUser()

    self.vote_1 = test_utils.CreateVote(
        self.santa_blockable, user_email=self.user_1.email, weight=2)
    self.vote_2 = test_utils.CreateVote(
        self.other_blockable, user_email=self.user_1.email, weight=10)
    self.vote_3 = test_utils.CreateVote(
        self.santa_certificate, user_email=self.user_1.email, weight=0,
        candidate_type='CERTIFICATE')

    self.PatchValidateXSRFToken()

  def tearDown(self):
    self.testbed.deactivate()


class VoteQueryHandlerTest(VotesTest):

  ROUTE = '/votes/query'

  def testAdminGetList(self):
    """Admin retrieves list of all users."""
    with self.LoggedInUser(admin=True):
      response = self.testapp.get(self.ROUTE)

    output = response.json

    self.assertIn('application/json', response.headers['Content-type'])
    self.assertIsInstance(output, dict)
    self.assertEqual(len(output['content']), 3)

  def testAdminGetList_PlatformNoEffect(self):
    """Admin specifies a platform which has no effect on the results."""
    params = {'platform': 'santa'}

    with self.LoggedInUser(admin=True):
      response = self.testapp.get(self.ROUTE, params)

    output = response.json

    self.assertIn('application/json', response.headers['Content-type'])
    self.assertIsInstance(output, dict)
    self.assertEqual(len(output['content']), 3)

  def testAdminGetList_OnlyInEffect(self):
    inactive_key = ndb.Key(flat=self.vote_1.key.flat()[:-1] + (None,))
    inactive_vote = utils.CopyEntity(self.vote_1, new_key=inactive_key)
    inactive_vote.put()

    self.assertEqual(4, base_models.Vote.query().count())

    with self.LoggedInUser(admin=True):
      response = self.testapp.get(self.ROUTE)

      self.assertEqual(len(response.json['content']), 3)

  def testUserGetList_NoPermissions(self):
    """Normal user attempts to retrieve all users."""
    with self.LoggedInUser(email_addr=self.user_1.email):
      self.testapp.get(self.ROUTE, status=httplib.FORBIDDEN)

  def testAdminGetQuery(self):
    """Admin queries a user."""
    params = {
        'search': self.user_1.email,
        'searchBase': 'userEmail'}

    with self.LoggedInUser(admin=True):
      response = self.testapp.get(self.ROUTE, params)

    output = response.json

    self.assertIn('application/json', response.headers['Content-type'])
    self.assertIsInstance(output, dict)
    self.assertEqual(len(output['content']), 3)

    key = utils.GetKeyFromUrlsafe(output['content'][0]['key'])
    self.assertEqual(key.flat()[1], output['content'][0]['candidateId'])

  def testUserGetQueryNoPermissions(self):
    """Normal user queries a rule."""
    params = {
        'search': self.user_1.email,
        'searchBase': 'userEmail'}

    with self.LoggedInUser(email_addr=self.user_1.email):
      self.testapp.get(self.ROUTE, params, status=httplib.FORBIDDEN)


class VoteHandlerTest(VotesTest):

  ROUTE = '/votes/%s'

  def testAdminGetID(self):
    """Admin gets a vote by ID."""
    with self.LoggedInUser(admin=True):
      response = self.testapp.get(self.ROUTE % self.vote_1.key.urlsafe())

    output = response.json

    self.assertIn('application/json', response.headers['Content-type'])
    self.assertIsInstance(output, dict)
    self.assertEqual(
        output['candidateId'], self.vote_1.key.parent().parent().id())

  def testAdminGetBadKey(self):
    """Admin gets a vote by an invalid key."""
    with self.LoggedInUser(admin=True):
      self.testapp.get(self.ROUTE % 'BadKey', status=httplib.BAD_REQUEST)

  def testAdminGetUnknownID(self):
    """Admin gets a vote by an unknown ID."""
    key = self.vote_3.key.urlsafe()
    self.vote_3.key.delete()
    with self.LoggedInUser(admin=True):
      self.testapp.get(self.ROUTE % key, status=httplib.NOT_FOUND)

  def testUserGetID(self):
    """Normal user attempts to get a vote by ID."""
    with self.LoggedInUser(email_addr=self.user_1.email):
      self.testapp.get(
          self.ROUTE % self.vote_1.key.urlsafe(), status=httplib.FORBIDDEN)


class VoteCastHandlerTest(VotesTest):

  ROUTE = '/votes/cast/%s'

  def testPost_Admin_Success(self):
    """Admin posts a vote."""
    params = {'wasYesVote': 'true'}

    with self.LoggedInUser(admin=True):
      response = self.testapp.post(
          self.ROUTE % self.santa_blockable.key.id(), params)

    output = response.json

    self.assertIn('application/json', response.headers['Content-type'])
    self.assertIsInstance(output, dict)

    self.assertEqual(self.santa_blockable.key.id(), output['blockable']['id'])
    self.assertEqual(True, output['vote']['wasYesVote'])

  def testPost_Admin_Cert(self):
    params = {'wasYesVote': 'true'}

    with self.LoggedInUser(admin=True):
      response = self.testapp.post(
          self.ROUTE % self.santa_certificate.key.id(), params)

    output = response.json

    self.assertIn('application/json', response.headers['Content-type'])
    self.assertIsInstance(output, dict)

    self.assertEqual(self.santa_certificate.key.id(), output['blockable']['id'])
    self.assertEqual(True, output['vote']['wasYesVote'])

  def testPost_Admin_AsRole_User(self):
    params = {'wasYesVote': 'true', 'asRole': constants.USER_ROLE.USER}

    with self.LoggedInUser(admin=True):
      response = self.testapp.post(
          self.ROUTE % self.santa_blockable.key.id(), params)
    output = response.json

    self.assertEqual(1, output['vote']['weight'])

  def testPost_Admin_AsRole_NoRole(self):
    params = {'wasYesVote': 'true', 'asRole': ''}

    with self.LoggedInUser(admin=True) as admin:
      response = self.testapp.post(
          self.ROUTE % self.santa_blockable.key.id(), params)
      output = response.json

      self.assertEqual(admin.vote_weight, output['vote']['weight'])

  def testPost_Admin_AsRole_BadRole(self):
    params = {'wasYesVote': 'true', 'asRole': 'NotARole'}

    with self.LoggedInUser(admin=True):
      self.testapp.post(
          self.ROUTE % self.santa_blockable.key.id(), params,
          status=httplib.BAD_REQUEST)

  def testPost_User_AsRole_NotAuthorized(self):
    params = {'wasYesVote': 'true', 'asRole': constants.USER_ROLE.TRUSTED_USER}

    with self.LoggedInUser(email_addr=self.user_2.email):
      self.testapp.post(
          self.ROUTE % self.santa_blockable.key.id(), params,
          status=httplib.FORBIDDEN)

  def testPost_User_Success(self):
    """Normal user posts a vote."""
    params = {'wasYesVote': 'true'}

    with self.LoggedInUser(email_addr=self.user_2.email):
      response = self.testapp.post(
          self.ROUTE % self.santa_blockable.key.id(), params)

    output = response.json

    self.assertIn('application/json', response.headers['Content-type'])
    self.assertIsInstance(output, dict)

    self.assertEqual(self.santa_blockable.key.id(), output['blockable']['id'])
    self.assertEqual(True, output['vote']['wasYesVote'])

  def testPost_User_Duplicate(self):
    params = {'wasYesVote': 'true'}

    with self.LoggedInUser(email_addr=self.user_2.email):
      self.testapp.post(
          self.ROUTE % self.santa_blockable.key.id(), params)

      self.testapp.post(
          self.ROUTE % self.santa_blockable.key.id(), params,
          status=httplib.CONFLICT)

  def testPost_User_UnknownBlockable(self):
    params = {'wasYesVote': 'true'}

    with self.LoggedInUser(email_addr=self.user_2.email):
      self.testapp.post(
          self.ROUTE % 'notablockable', params, status=httplib.NOT_FOUND)

  def testPost_User_Cert(self):
    """Normal user posts a vote."""
    params = {'wasYesVote': 'true'}

    with self.LoggedInUser(email_addr=self.user_2.email):
      self.testapp.post(
          self.ROUTE % self.santa_certificate.key.id(), params,
          status=httplib.FORBIDDEN)

  @mock.patch.object(
      votes.voting_api, 'Vote', side_effect=voting_api.BlockableNotFound)
  def testPost_BlockableNotFound(self, mock_vote):
    with self.LoggedInUser():
      self.testapp.post(
          self.ROUTE % test_utils.RandomSHA256(),
          params={'wasYesVote': 'true'},
          status=httplib.NOT_FOUND)

  @mock.patch.object(
      votes.voting_api, 'Vote', side_effect=voting_api.UnsupportedPlatform)
  def testPost_UnsupportedPlatform(self, mock_vote):
    with self.LoggedInUser():
      self.testapp.post(
          self.ROUTE % test_utils.RandomSHA256(),
          params={'wasYesVote': 'true'},
          status=httplib.BAD_REQUEST)

  @mock.patch.object(
      votes.voting_api, 'Vote', side_effect=voting_api.InvalidVoteWeight)
  def testPost_InvalidVoteWeight(self, mock_vote):
    with self.LoggedInUser():
      self.testapp.post(
          self.ROUTE % test_utils.RandomSHA256(),
          params={'wasYesVote': 'true'},
          status=httplib.BAD_REQUEST)

  @mock.patch.object(
      votes.voting_api, 'Vote', side_effect=voting_api.DuplicateVoteError)
  def testPost_DuplicateVoteError(self, mock_vote):
    with self.LoggedInUser():
      self.testapp.post(
          self.ROUTE % test_utils.RandomSHA256(),
          params={'wasYesVote': 'true'},
          status=httplib.CONFLICT)

  @mock.patch.object(
      votes.voting_api, 'Vote', side_effect=voting_api.OperationNotAllowed)
  def testPost_OperationNotAllowed(self, mock_vote):
    with self.LoggedInUser():
      self.testapp.post(
          self.ROUTE % test_utils.RandomSHA256(),
          params={'wasYesVote': 'true'},
          status=httplib.FORBIDDEN)

  @mock.patch.object(votes.voting_api, 'Vote', side_effect=Exception)
  def testPost_Exception(self, mock_vote):
    with self.LoggedInUser():
      self.testapp.post(
          self.ROUTE % test_utils.RandomSHA256(),
          params={'wasYesVote': 'true'},
          status=httplib.INTERNAL_SERVER_ERROR)

  def testGet_User(self):
    """Normal user reads a vote."""
    inactive_key = ndb.Key(flat=self.vote_2.key.flat()[:-1] + (None,))
    inactive_vote = utils.CopyEntity(self.vote_2, new_key=inactive_key)
    inactive_vote.put()

    self.assertFalse(inactive_vote.in_effect)

    with self.LoggedInUser(email_addr=self.user_1.email):
      response = self.testapp.get(self.ROUTE % self.other_blockable.key.id())

    self.assertEqual(self.vote_2.key.urlsafe(), response.json['key'])


if __name__ == '__main__':
  basetest.main()
