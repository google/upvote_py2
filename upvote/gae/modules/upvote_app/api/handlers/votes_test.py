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

import webapp2

from google.appengine.ext import ndb

from upvote.gae.datastore import test_utils
from upvote.gae.datastore import utils
from upvote.gae.datastore.models import base as base_db
from upvote.gae.modules.upvote_app.api.handlers import votes
from upvote.gae.shared.common import basetest
from upvote.shared import constants


class VotesTest(basetest.UpvoteTestCase):
  """Test Votes Handler Class."""

  def setUp(self, app):
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

  def setUp(self):
    app = webapp2.WSGIApplication(
        [webapp2.Route(r'', handler=votes.VoteQueryHandler)])
    super(VoteQueryHandlerTest, self).setUp(app)

  def testAdminGetList(self):
    """Admin retrieves list of all users."""
    with self.LoggedInUser(admin=True):
      response = self.testapp.get('')

    output = response.json

    self.assertIn('application/json', response.headers['Content-type'])
    self.assertIsInstance(output, dict)
    self.assertEqual(len(output['content']), 3)

  def testAdminGetList_PlatformNoEffect(self):
    """Admin specifies a platform which has no effect on the results."""
    params = {'platform': 'santa'}

    with self.LoggedInUser(admin=True):
      response = self.testapp.get('', params)

    output = response.json

    self.assertIn('application/json', response.headers['Content-type'])
    self.assertIsInstance(output, dict)
    self.assertEqual(len(output['content']), 3)

  def testAdminGetList_OnlyInEffect(self):
    inactive_key = ndb.Key(flat=self.vote_1.key.flat()[:-1] + (None,))
    inactive_vote = utils.CopyEntity(self.vote_1, new_key=inactive_key)
    inactive_vote.put()

    self.assertEqual(4, base_db.Vote.query().count())

    with self.LoggedInUser(admin=True):
      response = self.testapp.get('')

      self.assertEqual(len(response.json['content']), 3)

  def testUserGetList_NoPermissions(self):
    """Normal user attempts to retrieve all users."""
    with self.LoggedInUser(email_addr=self.user_1.email):
      self.testapp.get('', status=httplib.FORBIDDEN)

  def testAdminGetQuery(self):
    """Admin queries a user."""
    params = {
        'search': self.user_1.email,
        'searchBase': 'userEmail'}

    with self.LoggedInUser(admin=True):
      response = self.testapp.get('', params)

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
      self.testapp.get('', params, status=httplib.FORBIDDEN)


class VoteHandlerTest(VotesTest):

  def setUp(self):
    app = webapp2.WSGIApplication(
        [webapp2.Route(r'/<vote_key>', handler=votes.VoteHandler)])
    super(VoteHandlerTest, self).setUp(app)

  def testAdminGetID(self):
    """Admin gets a vote by ID."""
    with self.LoggedInUser(admin=True):
      response = self.testapp.get('/%s' % self.vote_1.key.urlsafe())

    output = response.json

    self.assertIn('application/json', response.headers['Content-type'])
    self.assertIsInstance(output, dict)
    self.assertEqual(
        output['candidateId'], self.vote_1.key.parent().parent().id())

  def testAdminGetBadKey(self):
    """Admin gets a vote by an invalid key."""
    with self.LoggedInUser(admin=True):
      self.testapp.get('/BadKey', status=httplib.BAD_REQUEST)

  def testAdminGetUnknownID(self):
    """Admin gets a vote by an unknown ID."""
    key = self.vote_3.key.urlsafe()
    self.vote_3.key.delete()
    with self.LoggedInUser(admin=True):
      self.testapp.get('/%s' % key, status=httplib.NOT_FOUND)

  def testUserGetID(self):
    """Normal user attempts to get a vote by ID."""
    with self.LoggedInUser(email_addr=self.user_1.email):
      self.testapp.get(
          '/%s' % self.vote_1.key.urlsafe(), status=httplib.FORBIDDEN)


class VoteCastHandlerTest(VotesTest):

  def setUp(self):
    app = webapp2.WSGIApplication(
        [webapp2.Route(r'/<blockable_id>', handler=votes.VoteCastHandler)])
    super(VoteCastHandlerTest, self).setUp(app)

  def testAdminPost(self):
    """Admin posts a vote."""
    params = {'wasYesVote': 'true'}

    with self.LoggedInUser(admin=True):
      response = self.testapp.post(
          '/%s' % self.santa_blockable.key.id(), params)

    output = response.json

    self.assertIn('application/json', response.headers['Content-type'])
    self.assertIsInstance(output, dict)

    self.assertEqual(self.santa_blockable.key.id(), output['blockable']['id'])
    self.assertEqual(True, output['vote']['wasYesVote'])

  def testAdminPost_Cert(self):
    params = {'wasYesVote': 'true'}

    with self.LoggedInUser(admin=True):
      response = self.testapp.post(
          '/%s' % self.santa_certificate.key.id(), params)

    output = response.json

    self.assertIn('application/json', response.headers['Content-type'])
    self.assertIsInstance(output, dict)

    self.assertEqual(self.santa_certificate.key.id(), output['blockable']['id'])
    self.assertEqual(True, output['vote']['wasYesVote'])

  def testAdminPost_AsRole_User(self):
    params = {'wasYesVote': 'true', 'asRole': constants.USER_ROLE.USER}

    with self.LoggedInUser(admin=True):
      response = self.testapp.post(
          '/%s' % self.santa_blockable.key.id(), params)
    output = response.json

    self.assertEqual(1, output['vote']['weight'])

  def testAdminPost_AsRole_NoRole(self):
    params = {'wasYesVote': 'true', 'asRole': ''}

    with self.LoggedInUser(admin=True) as admin:
      response = self.testapp.post(
          '/%s' % self.santa_blockable.key.id(), params)
      output = response.json

      self.assertEqual(admin.vote_weight, output['vote']['weight'])

  def testAdminPost_AsRole_BadRole(self):
    params = {'wasYesVote': 'true', 'asRole': 'NotARole'}

    with self.LoggedInUser(admin=True):
      self.testapp.post(
          '/%s' % self.santa_blockable.key.id(), params,
          status=httplib.BAD_REQUEST)

  def testUserPost_AsRole_NotAuthorized(self):
    params = {'wasYesVote': 'true', 'asRole': constants.USER_ROLE.TRUSTED_USER}

    with self.LoggedInUser(email_addr=self.user_2.email):
      self.testapp.post(
          '/%s' % self.santa_blockable.key.id(), params,
          status=httplib.FORBIDDEN)

  def testUserPost(self):
    """Normal user posts a vote."""
    params = {'wasYesVote': 'true'}

    with self.LoggedInUser(email_addr=self.user_2.email):
      response = self.testapp.post(
          '/%s' % self.santa_blockable.key.id(), params)

    output = response.json

    self.assertIn('application/json', response.headers['Content-type'])
    self.assertIsInstance(output, dict)

    self.assertEqual(self.santa_blockable.key.id(), output['blockable']['id'])
    self.assertEqual(True, output['vote']['wasYesVote'])

  def testUserPost_Duplicate(self):
    params = {'wasYesVote': 'true'}

    with self.LoggedInUser(email_addr=self.user_2.email):
      self.testapp.post(
          '/%s' % self.santa_blockable.key.id(), params)

      self.testapp.post(
          '/%s' % self.santa_blockable.key.id(), params,
          status=httplib.CONFLICT)

  def testUserPost_UnknownBlockable(self):
    params = {'wasYesVote': 'true'}

    with self.LoggedInUser(email_addr=self.user_2.email):
      self.testapp.post('/notablockable', params, status=httplib.NOT_FOUND)

  def testUserPost_Cert(self):
    """Normal user posts a vote."""
    params = {'wasYesVote': 'true'}

    with self.LoggedInUser(email_addr=self.user_2.email):
      self.testapp.post(
          '/%s' % self.santa_certificate.key.id(), params,
          status=httplib.FORBIDDEN)

  def testUserGet(self):
    """Normal user reads a vote."""
    inactive_key = ndb.Key(flat=self.vote_2.key.flat()[:-1] + (None,))
    inactive_vote = utils.CopyEntity(self.vote_2, new_key=inactive_key)
    inactive_vote.put()

    self.assertFalse(inactive_vote.in_effect)

    with self.LoggedInUser(email_addr=self.user_1.email):
      response = self.testapp.get('/%s' % self.other_blockable.key.id())

    self.assertEqual(self.vote_2.key.urlsafe(), response.json['key'])


if __name__ == '__main__':
  basetest.main()
